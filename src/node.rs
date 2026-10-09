// SPDX-License-Identifier: MIT

//! Event-driven BIP 324 server for Bitcoin and BIP 183 proof requests.
//!
//! # Architecture
//!
//! [`Node::run`] binds one nonblocking listener and starts an [`Acceptor`] plus
//! a fixed number of [`Worker`] threads. The acceptor owns connection
//! admission, distributes accepted sockets round-robin, and forwards new-block
//! notifications. Each worker owns a `mio` poller and advances many [`Peer`]
//! state machines from socket readiness; no connection gets a dedicated thread
//! and no async runtime is involved.
//!
//! A peer moves through three incremental BIP 324 handshake states:
//! remote key, garbage terminator, and encrypted version packets. Once the
//! handshake completes, the peer retains split inbound and outbound ciphers and
//! processes encrypted packets through the same readiness loop. [`V2Codec`]
//! decodes only requests this server handles. Unsupported message IDs are
//! ignored without invoking their potentially allocation-heavy Bitcoin
//! decoders.
//!
//! # Admission and failure isolation
//!
//! [`PeerRegistry`] caps the total admitted population, temporarily bans peers
//! that repeatedly exceed the packet rate, and prefers network-prefix
//! diversity when replacing a peer at capacity. Worker queues and work done per
//! poll iteration are bounded so connection churn cannot indefinitely postpone
//! established peers. Every peer callback is unwind-protected; malformed input
//! disconnects that peer rather than terminating its worker.
//!
//! # Resource bounds
//!
//! Handshake duration, bytes, and packet count are bounded independently.
//! Established peers have limits on bytes read per readiness event, encrypted
//! packet size, request collection lengths, packet rate, and pending encrypted
//! output. These limits must be checked before allocation or backend work:
//! authenticated encryption prevents forgery, but does not prevent an
//! authenticated peer from sending adversarial lengths or expensive requests.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Display;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::TryRecvError;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::time::Duration;
use std::time::Instant;

use bip324::GarbageResult;
use bip324::Handshake;
use bip324::InboundCipher;
use bip324::Initialized;
use bip324::OutboundCipher;
use bip324::PacketType;
use bip324::ReceivedGarbage;
use bip324::ReceivedKey;
use bip324::Role;
use bip324::SentKey;
use bip324::SentVersion;
use bip324::VersionResult;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message::CommandString;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_filter::CFilter;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::Magic;
use bitcoin::p2p::ServiceFlags;
use bitcoin::BlockHash;
use bitcoin::VarInt;
use log::debug;
use log::error;
use log::info;
use log::warn;
use mio::net::TcpListener;
use mio::net::TcpStream;
use mio::Events;
use mio::Interest;
use mio::Token;
use self_cell::self_cell;

use crate::block_index::BlocksIndex;
use crate::blockfile::BlockFile;
use crate::chainview::ChainView;
use crate::udata::CompactLeafData;

/// Deprecated Utreexo compact-filter type retained for compatibility.
pub const FILTER_TYPE_UTREEXO: u8 = 1;
const WORKERS_PER_CLUSTER: usize = 4;
/// Maximum number of sockets represented in the shared admission registry.
const MAX_PEERS: usize = 64;
/// Maximum number of addresses retained in the temporary ban table.
const MAX_BANNED_PEERS: usize = 4_096;
/// Number of authenticated packets a peer may send in one rate-limit window.
const MAX_MESSAGES_PER_SECOND: u32 = 100;
const RATE_LIMIT_VIOLATIONS: u8 = 3;
const EVENT_CAPACITY: usize = 1_024;
/// Maximum accepts handled before returning to block broadcasts and polling.
const MAX_ACCEPTS_PER_EVENT: usize = 64;
/// Maximum control messages a worker handles before returning to socket I/O.
const MAX_WORKER_MESSAGES_PER_TICK: usize = 64;
/// Bounded acceptor-to-worker backlog; `send` provides admission backpressure.
const WORKER_QUEUE_CAPACITY: usize = (MAX_PEERS / WORKERS_PER_CLUSTER) * 2;
const READ_BUFFER_SIZE: usize = 64 * 1_024;
/// Per-readiness byte budget, preventing a continuously readable peer from
/// monopolizing a worker.
const MAX_READ_BYTES_PER_EVENT: usize = 256 * 1_024;
const MAX_PACKET_SIZE: usize = 4_000_014;
/// Largest inbound encrypted packet accepted by the request server.
const MAX_INBOUND_PACKET_SIZE: usize = 256 * 1_024;
/// Per-peer encrypted output cap, sized for exactly one maximum Bitcoin packet.
const MAX_WRITE_BUFFER_SIZE: usize = OutboundCipher::encryption_buffer_len(MAX_PACKET_SIZE);
/// Cumulative handshake input budget, including garbage and decoy packets.
const MAX_HANDSHAKE_BYTES: usize = 1 * 1_024 * 1_024;
/// CPU-work bound for encrypted version/decoy packets during one handshake.
const MAX_HANDSHAKE_PACKETS: usize = 64;
const MAX_GETDATA_ITEMS: u64 = 1_024;
const MAX_LOCATOR_HASHES: u64 = 101;
const MAX_PROOF_BITMAP_BYTES: usize = 64 * 1_024;
const MAX_USER_AGENT_BYTES: usize = 256;
const MIN_COMPACT_LEAF_BYTES: usize = 13;
const MAX_UTREEXO_LEAVES: usize = MAX_PACKET_SIZE / MIN_COMPACT_LEAF_BYTES;
const MAX_HEADERS: u64 = 2_000;
const BIP324_KEY_SIZE: usize = 64;
const NODE_UTREEXO: u64 = 1 << 12;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const BAN_DURATION: Duration = Duration::from_secs(60 * 60);
const POLL_TIMEOUT: Duration = Duration::from_millis(100);
const PEER_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Admission state shared by the acceptor and all workers.
type SharedPeerRegistry = Arc<Mutex<PeerRegistry>>;

/// Network group used to avoid filling all peer slots from one address range.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum NetworkPrefix {
    V4([u8; 2]),
    V6([u8; 4]),
}

impl NetworkPrefix {
    fn from_address(address: IpAddr) -> Self {
        match Self::normalize(address) {
            IpAddr::V4(address) => {
                let octets = address.octets();
                Self::V4([octets[0], octets[1]])
            }
            IpAddr::V6(address) => {
                let octets = address.octets();
                Self::V6([octets[0], octets[1], octets[2], octets[3]])
            }
        }
    }

    fn normalize(address: IpAddr) -> IpAddr {
        match address {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(address)),
            address => address,
        }
    }
}

/// Registry metadata for one admitted socket.
///
/// The worker owns the actual socket; this record lets the acceptor enforce
/// global capacity and route eviction requests without touching worker state.
struct PeerRecord {
    address: IpAddr,
    connected_at: Instant,
    prefix: NetworkPrefix,
    /// Sanitized, self-reported first software component from `version`.
    software: Option<String>,
    worker: usize,
}

/// Result of attempting to reserve a slot for an incoming connection.
enum Admission {
    Accepted {
        peer_id: usize,
    },
    Replaced {
        evicted_peer: usize,
        evicted_worker: usize,
        peer_id: usize,
    },
    RejectedBanned,
    RejectedCapacity,
}

/// Global admission, diversity, and temporary-ban bookkeeping.
///
/// Entries are inserted before a socket is sent to its worker and removed by
/// that worker on disconnect. Poison recovery is intentional: losing admission
/// accounting would otherwise leave the public listener unprotected.
struct PeerRegistry {
    banned: HashMap<IpAddr, Instant>,
    max_peers: usize,
    next_peer: usize,
    peers: HashMap<usize, PeerRecord>,
}

impl PeerRegistry {
    fn new(max_peers: usize) -> Self {
        Self {
            banned: HashMap::new(),
            max_peers,
            next_peer: 0,
            peers: HashMap::new(),
        }
    }

    fn lock(registry: &SharedPeerRegistry) -> std::sync::MutexGuard<'_, Self> {
        match registry.lock() {
            Ok(registry) => registry,
            Err(poisoned) => {
                warn!("Recovering poisoned P2P peer registry");
                poisoned.into_inner()
            }
        }
    }

    fn is_banned(&mut self, address: IpAddr, now: Instant) -> bool {
        let address = NetworkPrefix::normalize(address);
        match self.banned.get(&address).copied() {
            Some(expires) if expires > now => true,
            Some(_) => {
                self.banned.remove(&address);
                false
            }
            None => false,
        }
    }

    /// Reserves capacity before dispatching a socket to a worker.
    ///
    /// At capacity, a connection from a new prefix may replace the oldest peer
    /// from an overrepresented prefix. The caller must deliver the corresponding
    /// disconnect before delivering the replacement socket.
    fn admit(&mut self, address: IpAddr, worker: usize, now: Instant) -> Admission {
        let address = NetworkPrefix::normalize(address);
        if self.is_banned(address, now) {
            return Admission::RejectedBanned;
        }

        if self.peers.len() < self.max_peers {
            let peer_id = self.insert(address, worker, now);
            return Admission::Accepted { peer_id };
        }

        let incoming_prefix = NetworkPrefix::from_address(address);
        if self
            .peers
            .values()
            .any(|peer| peer.prefix == incoming_prefix)
        {
            return Admission::RejectedCapacity;
        }

        let mut prefix_counts = HashMap::new();
        for peer in self.peers.values() {
            let count = prefix_counts.entry(peer.prefix).or_insert(0usize);
            *count = count.saturating_add(1);
        }
        let Some((evicted_prefix, count)) =
            prefix_counts.into_iter().max_by_key(|(_, count)| *count)
        else {
            return Admission::RejectedCapacity;
        };
        if count <= 1 {
            return Admission::RejectedCapacity;
        }

        let Some((&evicted_peer, evicted_record)) = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.prefix == evicted_prefix)
            .min_by_key(|(_, peer)| peer.connected_at)
        else {
            return Admission::RejectedCapacity;
        };
        let evicted_worker = evicted_record.worker;
        self.peers.remove(&evicted_peer);
        let peer_id = self.insert(address, worker, now);
        Admission::Replaced {
            evicted_peer,
            evicted_worker,
            peer_id,
        }
    }

    fn insert(&mut self, address: IpAddr, worker: usize, now: Instant) -> usize {
        let peer_id = self.allocate_peer_id();
        self.peers.insert(
            peer_id,
            PeerRecord {
                address,
                connected_at: now,
                prefix: NetworkPrefix::from_address(address),
                software: None,
                worker,
            },
        );
        peer_id
    }

    fn allocate_peer_id(&mut self) -> usize {
        loop {
            let peer_id = self.next_peer;
            self.next_peer = self.next_peer.wrapping_add(1);
            if !self.peers.contains_key(&peer_id) {
                return peer_id;
            }
        }
    }

    fn identify(&mut self, peer_id: usize, software: String) {
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.software.get_or_insert(software);
        }
    }

    fn software_summary(&self) -> PeerSoftwareSummary<'_> {
        let mut software = BTreeMap::<&str, usize>::new();
        let mut unidentified = 0usize;
        for peer in self.peers.values() {
            if let Some(name) = peer.software.as_deref() {
                *software.entry(name).or_default() += 1;
            } else {
                unidentified += 1;
            }
        }
        PeerSoftwareSummary {
            total: self.peers.len(),
            software,
            unidentified,
        }
    }
    fn remove(&mut self, peer_id: usize) {
        self.peers.remove(&peer_id);
    }

    fn remove_worker(&mut self, worker: usize) {
        self.peers.retain(|_, peer| peer.worker != worker);
    }

    fn ban(&mut self, peer_id: usize, now: Instant) -> Option<IpAddr> {
        let peer = self.peers.remove(&peer_id)?;
        self.banned.retain(|_, expires| *expires > now);
        if self.banned.len() >= MAX_BANNED_PEERS {
            if let Some(address) = self
                .banned
                .iter()
                .min_by_key(|(_, expires)| *expires)
                .map(|(address, _)| *address)
            {
                self.banned.remove(&address);
            }
        }
        let expires = now.checked_add(BAN_DURATION).unwrap_or(now);
        self.banned.insert(peer.address, expires);
        Some(peer.address)
    }
}

/// Deterministically formatted snapshot used by the periodic peer log.
struct PeerSoftwareSummary<'a> {
    total: usize,
    software: BTreeMap<&'a str, usize>,
    unidentified: usize,
}

impl Display for PeerSoftwareSummary<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "P2P peers total={} software=[", self.total)?;
        let mut first = true;
        for (name, count) in &self.software {
            if !first {
                formatter.write_str(" ")?;
            }
            write!(formatter, "{name}={count}")?;
            first = false;
        }
        write!(formatter, "] unidentified={}", self.unidentified)
    }
}

/// Action selected for the next authenticated packet in the current window.
enum RateLimitDecision {
    Allow,
    Drop,
    Ban,
}

/// Small fixed-window limiter applied to genuine and decoy BIP 324 packets.
///
/// Counting decoys is important because they still require authenticated
/// decryption and could otherwise monopolize a worker without sending a Bitcoin
/// message.
struct MessageRateLimiter {
    messages: u32,
    violations: u8,
    window_started: Instant,
}

impl MessageRateLimiter {
    fn new(now: Instant) -> Self {
        Self {
            messages: 0,
            violations: 0,
            window_started: now,
        }
    }

    fn check(&mut self, now: Instant) -> RateLimitDecision {
        if now.duration_since(self.window_started) >= Duration::from_secs(1) {
            self.messages = 0;
            self.violations = 0;
            self.window_started = now;
        }
        self.messages = self.messages.saturating_add(1);
        if self.messages <= MAX_MESSAGES_PER_SECOND {
            return RateLimitDecision::Allow;
        }

        self.violations = self.violations.saturating_add(1);
        if self.violations >= RATE_LIMIT_VIOLATIONS {
            RateLimitDecision::Ban
        } else {
            RateLimitDecision::Drop
        }
    }
}

/// Data required by peers to answer requests.
#[derive(Clone)]
pub struct WorkerContext {
    /// The blocks and proofs served to peers.
    pub proof_backend: Arc<RwLock<BlockFile>>,

    /// The index used to locate blocks in the proof backend.
    pub proof_index: Arc<BlocksIndex>,

    /// Cached active-chain metadata and headers.
    pub chainview: Arc<ChainView>,

    /// Network magic used by the encrypted transport.
    pub magic: Magic,
}

/// Errors that prevent the P2P server from starting.
#[derive(Debug)]
pub enum NodeError {
    /// The listening socket could not be bound.
    Bind(std::io::Error),

    /// A worker poller could not be created.
    WorkerPoll(std::io::Error),

    /// A server thread could not be spawned.
    Spawn(std::io::Error),
}

impl Display for NodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(error) => write!(formatter, "failed to bind P2P listener: {error}"),
            Self::WorkerPoll(error) => {
                write!(formatter, "failed to create P2P worker poller: {error}")
            }
            Self::Spawn(error) => write!(formatter, "failed to spawn P2P thread: {error}"),
        }
    }
}

impl std::error::Error for NodeError {}

/// Starts the inbound P2PV2 proof server.
pub struct Node;

impl Node {
    /// Starts the acceptor and evented workers.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener, a poller, or a server thread cannot
    /// be created.
    pub fn run(
        address: SocketAddr,
        worker_context: WorkerContext,
        block_notifier: Receiver<BlockHash>,
    ) -> Result<(), NodeError> {
        let listener = TcpListener::bind(address).map_err(NodeError::Bind)?;
        let registry = Arc::new(Mutex::new(PeerRegistry::new(MAX_PEERS)));
        let workers = Self::create_workers(&worker_context, &registry)?;
        let acceptor = Acceptor {
            block_notifier,
            listener,
            next_worker: 0,
            last_peer_log: Instant::now(),
            registry,
            workers,
        };

        std::thread::Builder::new()
            .name("bridge-p2p-acceptor".to_string())
            .spawn(move || {
                if let Err(error) = acceptor.run() {
                    error!("P2P acceptor stopped: {error}");
                }
            })
            .map_err(NodeError::Spawn)?;

        Ok(())
    }

    fn create_workers(
        context: &WorkerContext,
        registry: &SharedPeerRegistry,
    ) -> Result<Vec<SyncSender<WorkerMessage>>, NodeError> {
        let mut workers = Vec::with_capacity(WORKERS_PER_CLUSTER);
        for id in 0..WORKERS_PER_CLUSTER {
            let (sender, receiver) = std::sync::mpsc::sync_channel(WORKER_QUEUE_CAPACITY);
            let worker = Worker::new(id, context.clone(), receiver, registry.clone())
                .map_err(NodeError::WorkerPoll)?;
            std::thread::Builder::new()
                .name(format!("bridge-p2p-worker-{id}"))
                .spawn(move || {
                    if let Err(error) = worker.run() {
                        error!("P2P worker {id} stopped: {error}");
                    }
                })
                .map_err(NodeError::Spawn)?;
            workers.push(sender);
        }
        Ok(workers)
    }
}

/// Bounded control-plane messages sent from the acceptor to a worker.
enum WorkerMessage {
    NewConnection {
        address: SocketAddr,
        id: usize,
        stream: TcpStream,
    },
    NewBlock(BlockHash),
    Disconnect(usize),
}

/// Socket and protocol state owned exclusively by one worker thread.
struct PeerConnection {
    address: SocketAddr,
    id: usize,
    peer: Peer,
    stream: TcpStream,
}

/// Event loop that advances all peers assigned to one OS thread.
///
/// A worker first handles a bounded control-message batch, then polls socket
/// readiness, expires stalled handshakes, and repeats. Peer errors remove only
/// the offending connection.
struct Worker {
    context: WorkerContext,
    events: Events,
    id: usize,
    messages: Receiver<WorkerMessage>,
    next_token: usize,
    peers: HashMap<Token, PeerConnection>,
    poller: mio::Poll,
    registry: SharedPeerRegistry,
}

impl Worker {
    fn new(
        id: usize,
        context: WorkerContext,
        messages: Receiver<WorkerMessage>,
        registry: SharedPeerRegistry,
    ) -> std::io::Result<Self> {
        Ok(Self {
            context,
            events: Events::with_capacity(EVENT_CAPACITY),
            id,
            messages,
            next_token: 0,
            peers: HashMap::new(),
            poller: mio::Poll::new()?,
            registry,
        })
    }

    /// Runs the worker until its control channel closes or polling fails.
    fn run(mut self) -> Result<(), PeerError> {
        loop {
            if !self.handle_messages()? {
                return Ok(());
            }

            match self.poller.poll(&mut self.events, Some(POLL_TIMEOUT)) {
                Ok(()) => self.handle_events(),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
            self.expire_handshakes();
        }
    }

    /// Applies a bounded control-plane batch and reports whether the sender is
    /// still connected.
    fn handle_messages(&mut self) -> Result<bool, PeerError> {
        let mut handled = 0;
        while handled < MAX_WORKER_MESSAGES_PER_TICK {
            let message = match self.messages.try_recv() {
                Ok(message) => message,
                Err(TryRecvError::Empty) => return Ok(true),
                Err(TryRecvError::Disconnected) => return Ok(false),
            };
            handled += 1;
            match message {
                WorkerMessage::NewConnection {
                    address,
                    id,
                    stream,
                } => {
                    if let Err(error) = self.add_peer(id, address, stream) {
                        PeerRegistry::lock(&self.registry).remove(id);
                        debug!("Worker {} rejected peer {id}: {error}", self.id);
                    }
                }
                WorkerMessage::NewBlock(block_hash) => self.broadcast_block(block_hash),
                WorkerMessage::Disconnect(id) => self.disconnect_peer(id),
            }
        }
        Ok(true)
    }

    fn add_peer(
        &mut self,
        id: usize,
        address: SocketAddr,
        mut stream: TcpStream,
    ) -> Result<(), PeerError> {
        let token = self.allocate_token().ok_or(PeerError::NoPeerToken)?;
        stream.set_nodelay(true)?;
        self.poller.registry().register(
            &mut stream,
            token,
            Interest::READABLE | Interest::WRITABLE,
        )?;
        let connection = PeerConnection {
            address,
            id,
            peer: Peer::new(self.context.clone())?,
            stream,
        };

        debug!(
            "Worker {} accepted P2PV2 connection {} at {}",
            self.id, id, address
        );
        self.peers.insert(token, connection);
        Ok(())
    }

    fn allocate_token(&mut self) -> Option<Token> {
        let attempts = self.peers.len().saturating_add(1);
        for _ in 0..attempts {
            let token = Token(self.next_token);
            self.next_token = self.next_token.wrapping_add(1);
            if !self.peers.contains_key(&token) {
                return Some(token);
            }
        }
        None
    }

    fn disconnect_peer(&mut self, id: usize) {
        let token = self
            .peers
            .iter()
            .find_map(|(token, peer)| (peer.id == id).then_some(*token));
        if let Some(token) = token {
            self.remove_peer(token, &PeerError::Evicted);
        }
    }

    fn broadcast_block(&mut self, block_hash: BlockHash) {
        let tokens: Vec<_> = self.peers.keys().copied().collect();
        for token in tokens {
            let result = match self.peers.get_mut(&token) {
                Some(connection) if connection.peer.is_established() => Self::protect_peer(|| {
                    connection.peer.send_message(NetworkMessage::Inv(vec![
                        Inventory::WitnessBlock(block_hash),
                    ]))
                }),
                Some(_) | None => continue,
            };
            if let Err(error) = result {
                self.remove_peer(token, &error);
            } else if let Err(error) = self.refresh_interest(token) {
                self.remove_peer(token, &error);
            }
        }
    }

    /// Advances each ready peer once, removing only peers whose operation fails.
    fn handle_events(&mut self) {
        let ready: Vec<_> = self
            .events
            .iter()
            .map(|event| {
                (
                    event.token(),
                    event.is_readable(),
                    event.is_writable(),
                    event.is_error() || event.is_read_closed() || event.is_write_closed(),
                )
            })
            .collect();

        for (token, readable, writable, closed) in ready {
            if closed {
                self.remove_peer(token, &PeerError::Disconnected);
                continue;
            }

            if readable {
                let result = match self.peers.get_mut(&token) {
                    Some(connection) => {
                        Self::protect_peer(|| connection.peer.on_readable(&mut connection.stream))
                    }
                    None => continue,
                };
                if let Err(error) = result {
                    self.remove_peer(token, &error);
                    continue;
                }
                let identification = self.peers.get_mut(&token).and_then(|connection| {
                    connection
                        .peer
                        .take_announced_software()
                        .map(|software| (connection.id, software))
                });
                if let Some((peer_id, software)) = identification {
                    PeerRegistry::lock(&self.registry).identify(peer_id, software);
                }
            }

            if writable {
                let result = match self.peers.get_mut(&token) {
                    Some(connection) => {
                        Self::protect_peer(|| connection.peer.on_writable(&mut connection.stream))
                    }
                    None => continue,
                };
                if let Err(error) = result {
                    self.remove_peer(token, &error);
                    continue;
                }
            }

            if let Err(error) = self.refresh_interest(token) {
                self.remove_peer(token, &error);
            }
        }
    }

    fn expire_handshakes(&mut self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(token, connection)| {
                connection.peer.handshake_expired(now).then_some(*token)
            })
            .collect();
        for token in expired {
            self.remove_peer(token, &PeerError::HandshakeTimeout);
        }
    }

    fn refresh_interest(&mut self, token: Token) -> Result<(), PeerError> {
        let Some(connection) = self.peers.get_mut(&token) else {
            return Ok(());
        };
        let interest = if connection.peer.wants_write() {
            Interest::READABLE | Interest::WRITABLE
        } else {
            Interest::READABLE
        };
        self.poller
            .registry()
            .reregister(&mut connection.stream, token, interest)?;
        Ok(())
    }

    fn remove_peer(&mut self, token: Token, reason: &PeerError) {
        let Some(mut connection) = self.peers.remove(&token) else {
            return;
        };
        if let Err(error) = self.poller.registry().deregister(&mut connection.stream) {
            debug!(
                "Failed to deregister peer {} at {}: {}",
                connection.id, connection.address, error
            );
        }
        let banned_address =
            Self::record_disconnect(&self.registry, connection.id, reason, Instant::now());
        if let Some(address) = banned_address {
            warn!(
                "Banning P2PV2 peer {} at {} for excessive messages",
                connection.id, address
            );
        }
        debug!(
            "P2PV2 peer {} at {} disconnected: {}",
            connection.id, connection.address, reason
        );
    }

    fn record_disconnect(
        registry: &SharedPeerRegistry,
        peer_id: usize,
        reason: &PeerError,
        now: Instant,
    ) -> Option<IpAddr> {
        let mut registry = PeerRegistry::lock(registry);
        if matches!(reason, PeerError::RateLimitExceeded) {
            registry.ban(peer_id, now)
        } else {
            registry.remove(peer_id);
            None
        }
    }

    /// Converts a peer-local panic into a disconnect so the worker survives.
    fn protect_peer<T>(operation: impl FnOnce() -> Result<T, PeerError>) -> Result<T, PeerError> {
        match std::panic::catch_unwind(AssertUnwindSafe(operation)) {
            Ok(result) => result,
            Err(_) => Err(PeerError::Panicked),
        }
    }
}

/// Listener event loop responsible for admission and worker dispatch.
///
/// Accepted sockets remain nonblocking. A bounded synchronous worker channel
/// provides backpressure if connection churn outruns a worker.
struct Acceptor {
    block_notifier: Receiver<BlockHash>,
    listener: TcpListener,
    /// Last periodic software-summary emission.
    last_peer_log: Instant,
    next_worker: usize,
    registry: SharedPeerRegistry,
    workers: Vec<SyncSender<WorkerMessage>>,
}

impl Acceptor {
    /// Polls the listening socket and block-notification channel forever.
    fn run(mut self) -> Result<(), PeerError> {
        let mut poller = mio::Poll::new()?;
        poller
            .registry()
            .register(&mut self.listener, Token(0), Interest::READABLE)?;
        let mut events = Events::with_capacity(EVENT_CAPACITY);

        loop {
            match poller.poll(&mut events, Some(POLL_TIMEOUT)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(error) => return Err(error.into()),
            }

            if events.iter().any(|event| event.token() == Token(0)) {
                self.accept_ready_connections();
            }
            self.broadcast_blocks();
            self.log_peer_summary();
        }
    }

    fn accept_ready_connections(&mut self) {
        let mut accepted = 0;
        loop {
            if accepted >= MAX_ACCEPTS_PER_EVENT {
                return;
            }
            let (stream, address) = match self.listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return;
                }
                Err(error) => {
                    warn!("Failed to accept P2P connection: {error}");
                    return;
                }
            };
            accepted += 1;
            if self.workers.is_empty() {
                error!("No P2P worker is available");
                return;
            }

            let worker_id = self.next_worker % self.workers.len();
            self.next_worker = (self.next_worker + 1) % self.workers.len();
            let admission =
                PeerRegistry::lock(&self.registry).admit(address.ip(), worker_id, Instant::now());
            let peer_id = match admission {
                Admission::Accepted { peer_id } => peer_id,
                Admission::Replaced {
                    evicted_peer,
                    evicted_worker,
                    peer_id,
                } => {
                    if let Some(worker) = self.workers.get(evicted_worker) {
                        if worker
                            .send(WorkerMessage::Disconnect(evicted_peer))
                            .is_err()
                        {
                            warn!("P2P worker {evicted_worker} stopped");
                            PeerRegistry::lock(&self.registry).remove_worker(evicted_worker);
                        }
                    }
                    peer_id
                }
                Admission::RejectedBanned => {
                    debug!("Rejecting banned P2P peer at {address}");
                    continue;
                }
                Admission::RejectedCapacity => {
                    debug!("Rejecting P2P peer at {address}: peer capacity reached");
                    continue;
                }
            };

            let Some(worker) = self.workers.get(worker_id) else {
                PeerRegistry::lock(&self.registry).remove(peer_id);
                continue;
            };
            if worker
                .send(WorkerMessage::NewConnection {
                    address,
                    id: peer_id,
                    stream,
                })
                .is_err()
            {
                warn!("P2P worker stopped before accepting peer {peer_id}");
                PeerRegistry::lock(&self.registry).remove_worker(worker_id);
            }
        }
    }

    fn log_peer_summary(&mut self) {
        let now = Instant::now();
        if now.saturating_duration_since(self.last_peer_log) < PEER_LOG_INTERVAL {
            return;
        }
        self.last_peer_log = now;
        info!("{}", PeerRegistry::lock(&self.registry).software_summary());
    }

    fn broadcast_blocks(&mut self) {
        loop {
            let block_hash = match self.block_notifier.try_recv() {
                Ok(block_hash) => block_hash,
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => return,
            };
            for (worker_id, worker) in self.workers.iter().enumerate() {
                if worker.send(WorkerMessage::NewBlock(block_hash)).is_err() {
                    warn!("P2P worker {worker_id} stopped");
                    PeerRegistry::lock(&self.registry).remove_worker(worker_id);
                }
            }
        }
    }
}

/// Borrowed BIP 324 handshake state tied to the buffer containing remote
/// garbage and version packets.
///
/// [`ReceivedHandshakeCell`] keeps that backing buffer alive while the
/// `bip324` state machine borrows from it.
struct ReceivedHandshake<'a> {
    consumed_bytes: usize,
    handshake: Option<Handshake<ReceivedGarbage<'a>>>,
}

self_cell!(
    struct ReceivedHandshakeCell {
        owner: Vec<u8>,

        #[covariant]
        dependent: ReceivedHandshake,
    }
);

/// Result of trying to locate the remote garbage terminator.
enum GarbageTransition {
    NeedMore(Handshake<SentVersion>),
    Protocol(bip324::Error),
}

/// Incremental responder-side BIP 324 handshake state.
///
/// Each transition consumes only bytes already present in [`Peer::read_buffer`]
/// and returns to the `mio` loop when more input is required.
enum HandshakeState {
    AwaitingKey(Handshake<SentKey<'static>>),
    AwaitingGarbage(Handshake<SentVersion>),
    AwaitingVersion {
        handshake: ReceivedHandshakeCell,
        packet_size: Option<usize>,
    },
}

/// Per-connection transport, parser, rate-limit, and output state.
///
/// `Peer` never blocks on socket I/O. It owns partial input and output buffers
/// so fragmented handshakes and encrypted packets can resume on the next
/// readiness event.
struct Peer {
    connected_at: Instant,
    context: WorkerContext,
    handshake: Option<HandshakeState>,
    handshake_bytes: usize,
    /// Software classification waiting to be copied into the shared registry.
    announced_software: Option<String>,
    handshake_packets: usize,
    inbound: Option<InboundCipher>,
    outbound: Option<OutboundCipher>,
    packet_size: Option<usize>,
    rate_limiter: MessageRateLimiter,
    read_buffer: Vec<u8>,
    read_position: usize,
    write_buffer: Vec<u8>,
    write_position: usize,
}

impl Peer {
    fn new(context: WorkerContext) -> Result<Self, PeerError> {
        let handshake = Handshake::<Initialized>::new(context.magic.to_bytes(), Role::Responder)?;
        let key_size = Handshake::<Initialized>::send_key_len(None);
        let mut write_buffer = vec![0; key_size];
        let handshake: Handshake<SentKey<'static>> = handshake.send_key(None, &mut write_buffer)?;
        let now = Instant::now();
        Ok(Self {
            connected_at: now,
            context,
            handshake: Some(HandshakeState::AwaitingKey(handshake)),
            handshake_bytes: 0,
            handshake_packets: 0,
            announced_software: None,
            inbound: None,
            outbound: None,
            packet_size: None,
            rate_limiter: MessageRateLimiter::new(now),
            read_buffer: Vec::new(),
            read_position: 0,
            write_buffer,
            write_position: 0,
        })
    }

    fn is_established(&self) -> bool {
        self.handshake.is_none() && self.inbound.is_some() && self.outbound.is_some()
    }

    /// Returns the first software announcement observed by the worker.
    fn take_announced_software(&mut self) -> Option<String> {
        self.announced_software.take()
    }

    /// Extracts a log-safe software family from a Bitcoin user-agent string.
    ///
    /// `/Satoshi:28.0.0/` becomes `Satoshi`. Invalid, empty, overlong, or
    /// control-character-bearing names are grouped as `Unknown`.
    fn classify_user_agent(user_agent: &str) -> String {
        let component = user_agent
            .split('/')
            .find(|component| !component.is_empty())
            .unwrap_or(user_agent);
        let software = component
            .split_once(':')
            .map_or(component, |(software, _)| software);
        let valid = !software.is_empty()
            && software.len() <= 32
            && software
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
        if valid {
            software.to_string()
        } else {
            "Unknown".to_string()
        }
    }

    fn handshake_expired(&self, now: Instant) -> bool {
        !self.is_established()
            && now.saturating_duration_since(self.connected_at) >= HANDSHAKE_TIMEOUT
    }

    fn check_handshake_budget(&self, additional: usize) -> Result<usize, PeerError> {
        let total = self
            .handshake_bytes
            .checked_add(additional)
            .ok_or(PeerError::HandshakeTooLarge(usize::MAX))?;
        if total > MAX_HANDSHAKE_BYTES {
            return Err(PeerError::HandshakeTooLarge(total));
        }
        Ok(total)
    }

    fn record_handshake_bytes(&mut self, additional: usize) -> Result<(), PeerError> {
        self.handshake_bytes = self.check_handshake_budget(additional)?;
        Ok(())
    }

    fn on_readable(&mut self, stream: &mut TcpStream) -> Result<(), PeerError> {
        let mut buffer = [0; READ_BUFFER_SIZE];
        let mut bytes_read = 0;
        while bytes_read < MAX_READ_BYTES_PER_EVENT {
            let remaining = MAX_READ_BYTES_PER_EVENT - bytes_read;
            let read_limit = remaining.min(buffer.len());
            match stream.read(&mut buffer[..read_limit]) {
                Ok(0) => return Err(PeerError::Disconnected),
                Ok(read) => {
                    bytes_read += read;
                    self.read_buffer.extend_from_slice(&buffer[..read]);
                    self.process_input()?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn process_input(&mut self) -> Result<(), PeerError> {
        while self.handshake.is_some() {
            if !self.advance_handshake()? {
                return Ok(());
            }
        }
        self.process_messages()
    }

    /// Advances one or more immediately available handshake transitions.
    ///
    /// Returns `false` when the current state needs more bytes. Handshake byte
    /// and packet budgets are checked before retaining or decrypting attacker-
    /// controlled payloads.
    fn advance_handshake(&mut self) -> Result<bool, PeerError> {
        let state = self
            .handshake
            .take()
            .ok_or(PeerError::InvalidHandshakeState)?;
        match state {
            HandshakeState::AwaitingKey(handshake) => {
                let key_end = self.read_position + BIP324_KEY_SIZE;
                let Some(remote_key) = self.read_buffer.get(self.read_position..key_end) else {
                    self.handshake = Some(HandshakeState::AwaitingKey(handshake));
                    return Ok(false);
                };
                let mut remote_key_bytes = [0; BIP324_KEY_SIZE];
                remote_key_bytes.copy_from_slice(remote_key);
                self.read_position = key_end;
                self.record_handshake_bytes(BIP324_KEY_SIZE)?;

                let handshake = handshake.receive_key(remote_key_bytes)?;
                let version_size = Handshake::<ReceivedKey>::send_version_len(None);
                let start = self.write_buffer.len();
                self.write_buffer.resize(start + version_size, 0);
                let handshake = handshake.send_version(&mut self.write_buffer[start..], None)?;
                self.handshake = Some(HandshakeState::AwaitingGarbage(handshake));
                self.compact_read_buffer_fully();
                Ok(true)
            }
            HandshakeState::AwaitingGarbage(handshake) => {
                self.compact_read_buffer_fully();
                if self.read_buffer.is_empty() {
                    self.handshake = Some(HandshakeState::AwaitingGarbage(handshake));
                    return Ok(false);
                }

                let input = std::mem::take(&mut self.read_buffer);
                match ReceivedHandshakeCell::try_new_or_recover(input, move |input| match handshake
                    .receive_garbage(input)
                {
                    Ok(GarbageResult::FoundGarbage {
                        handshake,
                        consumed_bytes,
                    }) => Ok(ReceivedHandshake {
                        consumed_bytes,
                        handshake: Some(handshake),
                    }),
                    Ok(GarbageResult::NeedMoreData(handshake)) => {
                        Err(GarbageTransition::NeedMore(handshake))
                    }
                    Err(error) => Err(GarbageTransition::Protocol(error)),
                }) {
                    Ok(handshake) => {
                        let consumed_bytes = handshake.borrow_dependent().consumed_bytes;
                        self.record_handshake_bytes(consumed_bytes)?;
                        self.read_buffer = handshake.borrow_owner()[consumed_bytes..].to_vec();
                        self.handshake = Some(HandshakeState::AwaitingVersion {
                            handshake,
                            packet_size: None,
                        });
                        Ok(true)
                    }
                    Err((input, GarbageTransition::NeedMore(handshake))) => {
                        self.check_handshake_budget(input.len())?;
                        self.read_buffer = input;
                        self.handshake = Some(HandshakeState::AwaitingGarbage(handshake));
                        Ok(false)
                    }
                    Err((_input, GarbageTransition::Protocol(error))) => Err(error.into()),
                }
            }
            HandshakeState::AwaitingVersion {
                mut handshake,
                mut packet_size,
            } => {
                if packet_size.is_none() {
                    let length_end = self.read_position + bip324::NUM_LENGTH_BYTES;
                    let Some(length) = self.read_buffer.get(self.read_position..length_end) else {
                        self.handshake = Some(HandshakeState::AwaitingVersion {
                            handshake,
                            packet_size,
                        });
                        return Ok(false);
                    };
                    let mut encrypted_length = [0; bip324::NUM_LENGTH_BYTES];
                    encrypted_length.copy_from_slice(length);
                    let decrypted_size = handshake.with_dependent_mut(|_, received| {
                        received
                            .handshake
                            .as_mut()
                            .ok_or(PeerError::InvalidHandshakeState)?
                            .decrypt_packet_len(encrypted_length)
                            .map_err(PeerError::from)
                    })?;
                    if decrypted_size > MAX_INBOUND_PACKET_SIZE {
                        return Err(PeerError::MessageTooLarge(decrypted_size));
                    }
                    self.check_handshake_budget(
                        bip324::NUM_LENGTH_BYTES
                            .checked_add(decrypted_size)
                            .ok_or(PeerError::HandshakeTooLarge(usize::MAX))?,
                    )?;
                    packet_size = Some(decrypted_size);
                    self.read_position = length_end;
                }

                let packet_size = packet_size.ok_or(PeerError::InvalidHandshakeState)?;
                let packet_end = self.read_position + packet_size;
                if self.read_buffer.len() < packet_end {
                    self.handshake = Some(HandshakeState::AwaitingVersion {
                        handshake,
                        packet_size: Some(packet_size),
                    });
                    return Ok(false);
                }
                self.handshake_packets = self.handshake_packets.saturating_add(1);
                if self.handshake_packets > MAX_HANDSHAKE_PACKETS {
                    return Err(PeerError::TooManyHandshakePackets(self.handshake_packets));
                }
                self.record_handshake_bytes(
                    bip324::NUM_LENGTH_BYTES
                        .checked_add(packet_size)
                        .ok_or(PeerError::HandshakeTooLarge(usize::MAX))?,
                )?;

                let packet = &mut self.read_buffer[self.read_position..packet_end];
                let completed = handshake.with_dependent_mut(
                    |_, received| -> Result<Option<bip324::CipherSession>, PeerError> {
                        let current = received
                            .handshake
                            .take()
                            .ok_or(PeerError::InvalidHandshakeState)?;
                        match current.receive_version(packet)? {
                            VersionResult::Complete { cipher } => Ok(Some(cipher)),
                            VersionResult::Decoy(next) => {
                                received.handshake = Some(next);
                                Ok(None)
                            }
                        }
                    },
                )?;
                self.read_position = packet_end;
                self.compact_read_buffer_fully();

                if let Some(session) = completed {
                    let (inbound, outbound) = session.into_split();
                    self.inbound = Some(inbound);
                    self.outbound = Some(outbound);
                    self.handshake = None;
                } else {
                    self.handshake = Some(HandshakeState::AwaitingVersion {
                        handshake,
                        packet_size: None,
                    });
                }
                Ok(true)
            }
        }
    }

    /// Decrypts complete buffered packets and dispatches allowed requests.
    ///
    /// The inbound cipher is temporarily moved out because each packet mutates
    /// its sequence state. It is restored on both success and error so dropping
    /// the peer remains the only recovery path after a failed packet.
    fn process_messages(&mut self) -> Result<(), PeerError> {
        let now = Instant::now();
        let mut inbound = self
            .inbound
            .take()
            .ok_or(PeerError::InvalidHandshakeState)?;
        let result = (|| {
            loop {
                if self.packet_size.is_none() {
                    let length_end = self.read_position + bip324::NUM_LENGTH_BYTES;
                    let Some(length) = self.read_buffer.get(self.read_position..length_end) else {
                        break;
                    };
                    let mut encrypted_length = [0; bip324::NUM_LENGTH_BYTES];
                    encrypted_length.copy_from_slice(length);
                    let packet_size = inbound.decrypt_packet_len(encrypted_length);
                    if packet_size > MAX_INBOUND_PACKET_SIZE {
                        return Err(PeerError::MessageTooLarge(packet_size));
                    }
                    self.packet_size = Some(packet_size);
                    self.read_position = length_end;
                }

                let packet_size = self.packet_size.ok_or(PeerError::InvalidHandshakeState)?;
                let packet_end = self.read_position + packet_size;
                if self.read_buffer.len() < packet_end {
                    break;
                }

                let (packet_type, message) = inbound.decrypt_in_place(
                    &mut self.read_buffer[self.read_position..packet_end],
                    None,
                )?;
                let decision = self.rate_limiter.check(now);
                if matches!(decision, RateLimitDecision::Ban) {
                    return Err(PeerError::RateLimitExceeded);
                }
                let request = if packet_type == PacketType::Genuine
                    && matches!(decision, RateLimitDecision::Allow)
                {
                    Some(V2Codec::decode(&message[1..])?)
                } else {
                    None
                };
                self.read_position = packet_end;
                self.packet_size = None;
                if let Some(request) = request {
                    self.handle_message(request)?;
                }
            }
            Ok(())
        })();
        self.inbound = Some(inbound);
        self.compact_read_buffer();
        result
    }

    fn compact_read_buffer(&mut self) {
        if self.read_position == self.read_buffer.len() {
            self.read_buffer.clear();
            self.read_position = 0;
        } else if self.read_position >= READ_BUFFER_SIZE {
            self.compact_read_buffer_fully();
        }
    }

    fn compact_read_buffer_fully(&mut self) {
        if self.read_position == 0 {
            return;
        }
        let remaining = self.read_buffer.len() - self.read_position;
        self.read_buffer.copy_within(self.read_position.., 0);
        self.read_buffer.truncate(remaining);
        self.read_position = 0;
    }

    fn on_writable(&mut self, stream: &mut TcpStream) -> Result<(), PeerError> {
        while self.wants_write() {
            match stream.write(&self.write_buffer[self.write_position..]) {
                Ok(0) => return Err(PeerError::Disconnected),
                Ok(written) => self.write_position += written,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.write_buffer.clear();
        self.write_position = 0;
        Ok(())
    }

    fn wants_write(&self) -> bool {
        self.write_position < self.write_buffer.len()
    }

    fn send_message(&mut self, message: NetworkMessage) -> Result<(), PeerError> {
        let payload = V2Codec::encode(&V2Message::Bitcoin(message))?;
        self.send_payload(&payload)
    }

    /// Encrypts and queues one outbound payload without exceeding the per-peer
    /// pending-output budget.
    fn send_payload(&mut self, payload: &[u8]) -> Result<(), PeerError> {
        if payload.len() > MAX_PACKET_SIZE {
            return Err(PeerError::MessageTooLarge(payload.len()));
        }
        let packet_size = OutboundCipher::encryption_buffer_len(payload.len());
        let pending = self.write_buffer.len() - self.write_position;
        if pending.saturating_add(packet_size) > MAX_WRITE_BUFFER_SIZE {
            return Err(PeerError::WriteBufferFull);
        }
        if self.write_position > 0 {
            let remaining = self.write_buffer.len() - self.write_position;
            self.write_buffer.copy_within(self.write_position.., 0);
            self.write_buffer.truncate(remaining);
            self.write_position = 0;
        }

        let outbound = self
            .outbound
            .as_mut()
            .ok_or(PeerError::HandshakeIncomplete)?;
        let start = self.write_buffer.len();
        self.write_buffer.resize(start + packet_size, 0);
        outbound.encrypt(
            payload,
            &mut self.write_buffer[start..],
            PacketType::Genuine,
            None,
        )?;
        Ok(())
    }

    fn handle_message(&mut self, request: V2Message) -> Result<(), PeerError> {
        match request {
            V2Message::Bitcoin(request) => self.handle_bitcoin_message(request),
            V2Message::GetUtreexoProof(request) => self.handle_get_utreexo_proof(request),
            V2Message::UtreexoProof(_) => Ok(()),
            V2Message::Ignored => Ok(()),
        }
    }

    fn handle_bitcoin_message(&mut self, request: NetworkMessage) -> Result<(), PeerError> {
        match request {
            NetworkMessage::Ping(nonce) => {
                self.send_message(NetworkMessage::Pong(nonce))?;
            }
            NetworkMessage::GetData(inventory) => {
                self.handle_get_data(inventory)?;
            }
            NetworkMessage::GetHeaders(request) => {
                let headers = self.headers_for_request(&request)?;
                self.send_message(NetworkMessage::Headers(headers))?;
            }
            NetworkMessage::Version(version) => {
                if self.announced_software.is_none() {
                    self.announced_software = Some(Self::classify_user_agent(&version.user_agent));
                }
                info!(
                    "P2PV2 handshake user_agent_bytes={} blocks={} services={} address={:?}",
                    version.user_agent.len(),
                    version.start_height,
                    version.services,
                    version.receiver.address
                );
                self.send_message(NetworkMessage::Version(VersionMessage {
                    version: 70016,
                    services: Self::advertised_services(),
                    timestamp: version.timestamp.saturating_add(1),
                    receiver: version.sender.clone(),
                    sender: version.receiver,
                    nonce: version.nonce.wrapping_add(100),
                    user_agent: "/bridge:0.1.3/".to_string(),
                    start_height: self.context.proof_index.load_height() as i32,
                    relay: false,
                }))?;
                self.send_message(NetworkMessage::Verack)?;
            }
            NetworkMessage::GetCFilters(request) if request.filter_type == FILTER_TYPE_UTREEXO => {
                if let Some(accumulator) = self.context.chainview.get_acc(request.stop_hash)? {
                    self.send_message(NetworkMessage::CFilter(CFilter {
                        filter_type: FILTER_TYPE_UTREEXO,
                        block_hash: request.stop_hash,
                        filter: accumulator,
                    }))?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_get_data(&mut self, inventory: Vec<Inventory>) -> Result<(), PeerError> {
        if inventory.len() > MAX_GETDATA_ITEMS as usize {
            return Err(PeerError::TooManyInventoryItems(inventory.len() as u64));
        }
        let mut not_found = Vec::new();
        for item in inventory {
            if let Inventory::WitnessBlock(block_hash) = item {
                let Some(index) = self.context.proof_index.get_index(block_hash) else {
                    not_found.push(Inventory::WitnessBlock(block_hash));
                    continue;
                };
                let block = self
                    .context
                    .proof_backend
                    .read()
                    .map_err(|_| PeerError::PoisonedProofBackend)?
                    .get_block(index);
                match block {
                    Some(block) => self.send_message(NetworkMessage::Block(block.into()))?,
                    None => not_found.push(Inventory::WitnessBlock(block_hash)),
                }
            }
        }
        if !not_found.is_empty() {
            self.send_message(NetworkMessage::NotFound(not_found))?;
        }
        Ok(())
    }

    fn handle_get_utreexo_proof(&mut self, request: GetUtreexoProof) -> Result<(), PeerError> {
        if request.proof_bitmap.len() > MAX_PROOF_BITMAP_BYTES
            || request.leaf_bitmap.len() > MAX_PROOF_BITMAP_BYTES
        {
            return Err(PeerError::ProofBitmapTooLarge);
        }
        let Some(index) = self.context.proof_index.get_index(request.block_hash) else {
            return Ok(());
        };
        let proof = {
            let backend = self
                .context
                .proof_backend
                .read()
                .map_err(|_| PeerError::PoisonedProofBackend)?;
            let Some(block) = backend.get_block(index) else {
                return Ok(());
            };
            let Some(udata) = block.udata else {
                return Ok(());
            };
            UtreexoProof {
                block_hash: request.block_hash,
                proof_hashes: if request.include_all {
                    udata.proof.hashes
                } else {
                    Self::select_bitmap(&udata.proof.hashes, &request.proof_bitmap)
                },
                target_locations: udata.proof.targets,
                leaf_data: if request.include_all {
                    udata.leaves
                } else {
                    Self::select_bitmap(&udata.leaves, &request.leaf_bitmap)
                },
            }
        };
        let payload = V2Codec::encode(&V2Message::UtreexoProof(proof))?;
        self.send_payload(&payload)
    }

    fn select_bitmap<T: Clone>(values: &[T], bitmap: &[u8]) -> Vec<T> {
        values
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                bitmap
                    .get(index / 8)
                    .is_some_and(|byte| byte & (1 << (7 - index % 8)) != 0)
            })
            .map(|(_, value)| value.clone())
            .collect()
    }

    fn headers_for_request(
        &self,
        request: &GetHeadersMessage,
    ) -> Result<Vec<bitcoin::block::Header>, PeerError> {
        if request.locator_hashes.len() > MAX_LOCATOR_HASHES as usize {
            return Err(PeerError::TooManyLocatorHashes(
                request.locator_hashes.len() as u64,
            ));
        }
        let mut common_height = 0;
        for block_hash in &request.locator_hashes {
            if let Some(height) = self.context.chainview.get_height(*block_hash)? {
                common_height = height;
                break;
            }
        }

        let start = common_height.saturating_add(1);
        let end = start.saturating_add(MAX_HEADERS as u32);
        let mut headers = Vec::with_capacity(MAX_HEADERS as usize);
        for height in start..end {
            let Some(block_hash) = self.context.chainview.get_block_hash(height)? else {
                break;
            };
            let Some(header) = self.context.chainview.get_block(block_hash)? else {
                break;
            };
            headers.push(deserialize(&header)?);
            if request.stop_hash != BlockHash::all_zeros() && request.stop_hash == block_hash {
                break;
            }
        }
        Ok(headers)
    }

    fn advertised_services() -> ServiceFlags {
        ServiceFlags::NETWORK_LIMITED
            | ServiceFlags::NETWORK
            | ServiceFlags::WITNESS
            | ServiceFlags::P2P_V2
            | ServiceFlags::from(NODE_UTREEXO)
    }
}

/// BIP 183 `getuproof` request carried under P2PV2 short message ID 30.
#[derive(Clone, Debug, Eq, PartialEq)]
struct GetUtreexoProof {
    block_hash: BlockHash,
    include_all: bool,
    proof_bitmap: Vec<u8>,
    leaf_bitmap: Vec<u8>,
}

impl Encodable for GetUtreexoProof {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut written = self.block_hash.consensus_encode(writer)?;
        written += u8::from(self.include_all).consensus_encode(writer)?;
        written += self.proof_bitmap.consensus_encode(writer)?;
        written += self.leaf_bitmap.consensus_encode(writer)?;
        Ok(written)
    }
}

impl GetUtreexoProof {
    /// Decodes one length-prefixed bitmap after validating its allocation size.
    fn decode_bitmap<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Vec<u8>, bitcoin::consensus::encode::Error> {
        let length = VarInt::consensus_decode(reader)?.0;
        if length > MAX_PROOF_BITMAP_BYTES as u64 {
            return Err(
                bitcoin::consensus::encode::Error::OversizedVectorAllocation {
                    requested: usize::try_from(length).unwrap_or(usize::MAX),
                    max: MAX_PROOF_BITMAP_BYTES,
                },
            );
        }
        let mut bitmap = vec![0; length as usize];
        reader.read_exact(&mut bitmap)?;
        Ok(bitmap)
    }
}

impl Decodable for GetUtreexoProof {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let block_hash = BlockHash::consensus_decode(reader)?;
        let include_all = match u8::consensus_decode(reader)? {
            0 => false,
            1 => true,
            _ => {
                return Err(bitcoin::consensus::encode::Error::ParseFailed(
                    "invalid getuproof include-all flag",
                ))
            }
        };
        Ok(Self {
            block_hash,
            include_all,
            proof_bitmap: Self::decode_bitmap(reader)?,
            leaf_bitmap: Self::decode_bitmap(reader)?,
        })
    }
}

/// BIP 183 `uproof` response carried under P2PV2 short message ID 29.
#[derive(Clone, Debug, Eq, PartialEq)]
struct UtreexoProof {
    block_hash: BlockHash,
    proof_hashes: Vec<BlockHash>,
    target_locations: Vec<VarInt>,
    leaf_data: Vec<CompactLeafData>,
}

impl Encodable for UtreexoProof {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut written = self.block_hash.consensus_encode(writer)?;
        written += self.proof_hashes.consensus_encode(writer)?;
        written += self.target_locations.consensus_encode(writer)?;
        written += VarInt(self.leaf_data.len() as u64).consensus_encode(writer)?;
        for leaf in &self.leaf_data {
            written += leaf.header_code.consensus_encode(writer)?;
            written += leaf.amount.consensus_encode(writer)?;
            written += leaf.spk_ty.consensus_encode(writer)?;
        }
        Ok(written)
    }
}

impl Decodable for UtreexoProof {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let block_hash = BlockHash::consensus_decode(reader)?;
        let proof_hashes = Vec::consensus_decode(reader)?;
        let target_locations = Vec::consensus_decode(reader)?;
        let leaf_count = VarInt::consensus_decode(reader)?.0;
        if leaf_count > MAX_UTREEXO_LEAVES as u64 {
            return Err(
                bitcoin::consensus::encode::Error::OversizedVectorAllocation {
                    requested: usize::try_from(leaf_count).unwrap_or(usize::MAX),
                    max: MAX_UTREEXO_LEAVES,
                },
            );
        }
        let mut leaf_data = Vec::with_capacity(leaf_count as usize);
        for _ in 0..leaf_count {
            leaf_data.push(CompactLeafData {
                header_code: u32::consensus_decode(reader)?,
                amount: u64::consensus_decode(reader)?,
                spk_ty: Decodable::consensus_decode(reader)?,
            });
        }
        Ok(Self {
            block_hash,
            proof_hashes,
            target_locations,
            leaf_data,
        })
    }
}

/// Internal message set crossing the encrypted transport boundary.
///
/// [`V2Message::Ignored`] represents an authenticated but unsupported inbound
/// message. Keeping it opaque avoids parsing data the server will not use.
#[derive(Clone, Debug, Eq, PartialEq)]
enum V2Message {
    Bitcoin(NetworkMessage),
    UtreexoProof(UtreexoProof),
    GetUtreexoProof(GetUtreexoProof),
    Ignored,
}

/// Encoder for outbound messages and allow-list decoder for inbound requests.
///
/// Inbound collection lengths and trailing bytes are validated here before a
/// request reaches storage-backed handlers.
struct V2Codec;

impl V2Codec {
    fn encode(message: &V2Message) -> Result<Vec<u8>, PeerError> {
        match message {
            V2Message::Bitcoin(message) => Self::encode_bitcoin(message),
            V2Message::UtreexoProof(proof) => {
                let mut buffer = vec![29];
                proof.consensus_encode(&mut buffer)?;
                Ok(buffer)
            }
            V2Message::GetUtreexoProof(request) => {
                let mut buffer = vec![30];
                request.consensus_encode(&mut buffer)?;
                Ok(buffer)
            }
            V2Message::Ignored => Err(PeerError::CannotEncodeIgnoredMessage),
        }
    }

    fn encode_bitcoin(message: &NetworkMessage) -> Result<Vec<u8>, PeerError> {
        let mut buffer = Vec::new();
        match message {
            NetworkMessage::Addr(_) => buffer.push(1),
            NetworkMessage::Block(_) => buffer.push(2),
            NetworkMessage::BlockTxn(_) => buffer.push(3),
            NetworkMessage::CmpctBlock(_) => buffer.push(4),
            NetworkMessage::FeeFilter(_) => buffer.push(5),
            NetworkMessage::FilterAdd(_) => buffer.push(6),
            NetworkMessage::FilterClear => buffer.push(7),
            NetworkMessage::FilterLoad(_) => buffer.push(8),
            NetworkMessage::GetBlocks(_) => buffer.push(9),
            NetworkMessage::GetBlockTxn(_) => buffer.push(10),
            NetworkMessage::GetData(_) => buffer.push(11),
            NetworkMessage::GetHeaders(_) => buffer.push(12),
            NetworkMessage::Headers(_) => buffer.push(13),
            NetworkMessage::Inv(_) => buffer.push(14),
            NetworkMessage::MemPool => buffer.push(15),
            NetworkMessage::MerkleBlock(_) => buffer.push(16),
            NetworkMessage::NotFound(_) => buffer.push(17),
            NetworkMessage::Ping(_) => buffer.push(18),
            NetworkMessage::Pong(_) => buffer.push(19),
            NetworkMessage::SendCmpct(_) => buffer.push(20),
            NetworkMessage::Tx(_) => buffer.push(21),
            NetworkMessage::GetCFilters(_) => buffer.push(22),
            NetworkMessage::CFilter(_) => buffer.push(23),
            NetworkMessage::GetCFHeaders(_) => buffer.push(24),
            NetworkMessage::CFHeaders(_) => buffer.push(25),
            NetworkMessage::GetCFCheckpt(_) => buffer.push(26),
            NetworkMessage::CFCheckpt(_) => buffer.push(27),
            NetworkMessage::AddrV2(_) => buffer.push(28),
            NetworkMessage::Version(_)
            | NetworkMessage::Verack
            | NetworkMessage::SendHeaders
            | NetworkMessage::GetAddr
            | NetworkMessage::WtxidRelay
            | NetworkMessage::SendAddrV2
            | NetworkMessage::Alert(_)
            | NetworkMessage::Reject(_) => {
                buffer.push(0);
                message.command().consensus_encode(&mut buffer)?;
            }
            NetworkMessage::Unknown { command, payload } => {
                buffer.push(0);
                command.consensus_encode(&mut buffer)?;
                buffer.extend_from_slice(payload);
                return Ok(buffer);
            }
        }
        message.consensus_encode(&mut buffer)?;
        Ok(buffer)
    }

    /// Decodes one authenticated P2PV2 payload.
    ///
    /// Only request messages handled by this server are parsed. All other short
    /// IDs and long commands become [`V2Message::Ignored`].
    fn decode(buffer: &[u8]) -> Result<V2Message, PeerError> {
        let Some((&short_id, payload)) = buffer.split_first() else {
            return Err(PeerError::MissingShortId);
        };
        match short_id {
            0 => Self::decode_long_command(payload),
            11 => Ok(V2Message::Bitcoin(NetworkMessage::GetData(
                Self::decode_get_data(payload)?,
            ))),
            12 => Ok(V2Message::Bitcoin(NetworkMessage::GetHeaders(
                Self::decode_get_headers(payload)?,
            ))),
            18 => Ok(V2Message::Bitcoin(NetworkMessage::Ping(
                Self::decode_exact(payload)?,
            ))),
            22 => Ok(V2Message::Bitcoin(NetworkMessage::GetCFilters(
                Self::decode_exact(payload)?,
            ))),
            30 => Ok(V2Message::GetUtreexoProof(Self::decode_exact(payload)?)),
            _ => Ok(V2Message::Ignored),
        }
    }

    fn decode_long_command(buffer: &[u8]) -> Result<V2Message, PeerError> {
        let Some(command_bytes) = buffer.get(..12) else {
            return Err(PeerError::MissingCommand);
        };
        let mut command_reader = command_bytes;
        let command = CommandString::consensus_decode(&mut command_reader)?;
        let payload = &buffer[12..];
        match command.as_ref() {
            "version" => {
                let version: VersionMessage = Self::decode_exact(payload)?;
                if version.user_agent.len() > MAX_USER_AGENT_BYTES {
                    return Err(PeerError::UserAgentTooLong(version.user_agent.len()));
                }
                Ok(V2Message::Bitcoin(NetworkMessage::Version(version)))
            }
            "verack" => {
                Self::ensure_empty(payload)?;
                Ok(V2Message::Bitcoin(NetworkMessage::Verack))
            }
            "sendheaders" => {
                Self::ensure_empty(payload)?;
                Ok(V2Message::Bitcoin(NetworkMessage::SendHeaders))
            }
            "getaddr" => {
                Self::ensure_empty(payload)?;
                Ok(V2Message::Bitcoin(NetworkMessage::GetAddr))
            }
            "wtxidrelay" => {
                Self::ensure_empty(payload)?;
                Ok(V2Message::Bitcoin(NetworkMessage::WtxidRelay))
            }
            "sendaddrv2" => {
                Self::ensure_empty(payload)?;
                Ok(V2Message::Bitcoin(NetworkMessage::SendAddrV2))
            }
            _ => Ok(V2Message::Ignored),
        }
    }

    fn decode_get_data(payload: &[u8]) -> Result<Vec<Inventory>, PeerError> {
        let mut reader = payload;
        let count = VarInt::consensus_decode(&mut reader)?.0;
        if count > MAX_GETDATA_ITEMS {
            return Err(PeerError::TooManyInventoryItems(count));
        }
        let mut inventory = Vec::with_capacity(count as usize);
        for _ in 0..count {
            inventory.push(Inventory::consensus_decode(&mut reader)?);
        }
        Self::ensure_empty(reader)?;
        Ok(inventory)
    }

    fn decode_get_headers(payload: &[u8]) -> Result<GetHeadersMessage, PeerError> {
        let mut reader = payload;
        let version = u32::consensus_decode(&mut reader)?;
        let count = VarInt::consensus_decode(&mut reader)?.0;
        if count > MAX_LOCATOR_HASHES {
            return Err(PeerError::TooManyLocatorHashes(count));
        }
        let mut locator_hashes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            locator_hashes.push(BlockHash::consensus_decode(&mut reader)?);
        }
        let stop_hash = BlockHash::consensus_decode(&mut reader)?;
        Self::ensure_empty(reader)?;
        Ok(GetHeadersMessage {
            version,
            locator_hashes,
            stop_hash,
        })
    }

    fn decode_exact<T: Decodable>(payload: &[u8]) -> Result<T, PeerError> {
        let mut reader = payload;
        let value = T::consensus_decode(&mut reader)?;
        Self::ensure_empty(reader)?;
        Ok(value)
    }

    fn ensure_empty(payload: &[u8]) -> Result<(), PeerError> {
        if payload.is_empty() {
            Ok(())
        } else {
            Err(PeerError::TrailingPayload(payload.len()))
        }
    }
}

/// Connection-local failures that cause the worker to disconnect one peer.
#[derive(Debug)]
enum PeerError {
    CannotEncodeIgnoredMessage,
    Decode(bitcoin::consensus::encode::Error),
    Disconnected,
    Evicted,
    HandshakeIncomplete,
    HandshakeTimeout,
    HandshakeTooLarge(usize),
    Io(std::io::Error),
    InvalidHandshakeState,
    MessageTooLarge(usize),
    MissingCommand,
    MissingShortId,
    NoPeerToken,
    Panicked,
    PoisonedProofBackend,
    ProofBitmapTooLarge,
    Protocol(bip324::Error),
    RateLimitExceeded,
    Storage(kv::Error),
    TooManyInventoryItems(u64),
    TooManyLocatorHashes(u64),
    TooManyHandshakePackets(usize),
    TrailingPayload(usize),
    UserAgentTooLong(usize),
    WriteBufferFull,
}

impl Display for PeerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CannotEncodeIgnoredMessage => {
                formatter.write_str("cannot encode an ignored inbound message")
            }
            Self::Decode(error) => write!(formatter, "message decode error: {error}"),
            Self::Disconnected => formatter.write_str("connection closed"),
            Self::Evicted => formatter.write_str("evicted to preserve peer prefix diversity"),
            Self::HandshakeIncomplete => formatter.write_str("P2PV2 handshake is not complete"),
            Self::HandshakeTimeout => formatter.write_str("P2PV2 handshake timed out"),
            Self::HandshakeTooLarge(size) => {
                write!(formatter, "P2PV2 handshake exceeded its byte limit: {size}")
            }
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::InvalidHandshakeState => formatter.write_str("invalid P2PV2 handshake state"),
            Self::MessageTooLarge(size) => {
                write!(formatter, "P2PV2 message is too large: {size} bytes")
            }
            Self::MissingCommand => formatter.write_str("P2PV2 long message has no command"),
            Self::MissingShortId => formatter.write_str("P2PV2 message has no short ID"),
            Self::NoPeerToken => formatter.write_str("no peer token is available"),
            Self::Panicked => formatter.write_str("peer operation panicked"),
            Self::PoisonedProofBackend => formatter.write_str("proof backend lock is poisoned"),
            Self::ProofBitmapTooLarge => formatter.write_str("BIP 183 proof bitmap is too large"),
            Self::Protocol(error) => write!(formatter, "BIP 324 error: {error}"),
            Self::RateLimitExceeded => formatter.write_str("peer exceeded the message rate limit"),
            Self::Storage(error) => write!(formatter, "peer storage error: {error}"),
            Self::TooManyInventoryItems(count) => {
                write!(
                    formatter,
                    "getdata message contains {count} inventory items"
                )
            }
            Self::TooManyHandshakePackets(count) => {
                write!(formatter, "P2PV2 handshake contains {count} packets")
            }
            Self::TooManyLocatorHashes(count) => {
                write!(
                    formatter,
                    "getheaders message contains {count} locator hashes"
                )
            }
            Self::TrailingPayload(bytes) => {
                write!(formatter, "message has {bytes} trailing payload bytes")
            }
            Self::UserAgentTooLong(bytes) => {
                write!(formatter, "version user agent is too long: {bytes} bytes")
            }
            Self::WriteBufferFull => formatter.write_str("peer write buffer is full"),
        }
    }
}

impl From<bip324::Error> for PeerError {
    fn from(error: bip324::Error) -> Self {
        Self::Protocol(error)
    }
}

impl From<bitcoin::consensus::encode::Error> for PeerError {
    fn from(error: bitcoin::consensus::encode::Error) -> Self {
        Self::Decode(error)
    }
}

impl From<bitcoin::io::Error> for PeerError {
    fn from(error: bitcoin::io::Error) -> Self {
        Self::Decode(bitcoin::consensus::encode::Error::Io(error))
    }
}

impl From<std::io::Error> for PeerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<kv::Error> for PeerError {
    fn from(error: kv::Error) -> Self {
        Self::Storage(error)
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;
    use std::path::Path;
    use std::time::SystemTime;

    use bip324::io::Payload;
    use bip324::io::Protocol;

    use crate::udata::BatchProof;
    use crate::udata::ScriptPubkeyType;
    use crate::udata::UData;
    use crate::udata::UtreexoBlock;

    use super::*;

    #[test]
    fn p2pv2_codec_handles_supported_inbound_and_outbound_bip183_messages() {
        let block_hash = BlockHash::all_zeros();
        let inbound_messages = [
            V2Message::Bitcoin(NetworkMessage::Ping(42)),
            V2Message::Bitcoin(NetworkMessage::Verack),
            V2Message::GetUtreexoProof(GetUtreexoProof {
                block_hash,
                include_all: false,
                proof_bitmap: vec![0b1010_0000],
                leaf_bitmap: vec![0b0100_0000],
            }),
        ];

        for message in inbound_messages {
            let encoded = V2Codec::encode(&message).expect("message encodes");
            let decoded = V2Codec::decode(&encoded).expect("message decodes");
            assert_eq!(decoded, message);
        }

        let proof = UtreexoProof {
            block_hash,
            proof_hashes: vec![block_hash],
            target_locations: vec![VarInt(7)],
            leaf_data: vec![CompactLeafData {
                header_code: 42,
                amount: 5_000,
                spk_ty: ScriptPubkeyType::PubKeyHash,
            }],
        };
        let encoded =
            V2Codec::encode(&V2Message::UtreexoProof(proof.clone())).expect("proof encodes");
        assert_eq!(encoded.first(), Some(&29));
        assert_eq!(
            deserialize::<UtreexoProof>(&encoded[1..]).expect("proof payload decodes"),
            proof
        );
        assert_eq!(
            V2Codec::decode(&encoded).expect("unsupported inbound proof is ignored"),
            V2Message::Ignored
        );
    }

    #[test]
    fn inbound_codec_rejects_oversized_and_noncanonical_requests_without_panicking() {
        assert_eq!(
            V2Codec::decode(&[2, 0xff, 0xff]).expect("unsupported block is ignored"),
            V2Message::Ignored
        );

        let mut ping_with_trailing_byte = vec![18];
        42u64
            .consensus_encode(&mut ping_with_trailing_byte)
            .expect("encode ping nonce");
        ping_with_trailing_byte.push(0);
        assert!(matches!(
            V2Codec::decode(&ping_with_trailing_byte),
            Err(PeerError::TrailingPayload(1))
        ));

        let mut oversized_getdata = vec![11];
        VarInt(MAX_GETDATA_ITEMS + 1)
            .consensus_encode(&mut oversized_getdata)
            .expect("encode inventory count");
        assert!(matches!(
            V2Codec::decode(&oversized_getdata),
            Err(PeerError::TooManyInventoryItems(count))
                if count == MAX_GETDATA_ITEMS + 1
        ));

        let mut oversized_getheaders = vec![12];
        70016u32
            .consensus_encode(&mut oversized_getheaders)
            .expect("encode protocol version");
        VarInt(MAX_LOCATOR_HASHES + 1)
            .consensus_encode(&mut oversized_getheaders)
            .expect("encode locator count");
        assert!(matches!(
            V2Codec::decode(&oversized_getheaders),
            Err(PeerError::TooManyLocatorHashes(count))
                if count == MAX_LOCATOR_HASHES + 1
        ));

        let mut oversized_bitmap = vec![30];
        BlockHash::all_zeros()
            .consensus_encode(&mut oversized_bitmap)
            .expect("encode block hash");
        0u8.consensus_encode(&mut oversized_bitmap)
            .expect("encode include-all flag");
        VarInt(MAX_PROOF_BITMAP_BYTES as u64 + 1)
            .consensus_encode(&mut oversized_bitmap)
            .expect("encode bitmap length");
        assert!(matches!(
            V2Codec::decode(&oversized_bitmap),
            Err(PeerError::Decode(
                bitcoin::consensus::encode::Error::OversizedVectorAllocation { .. }
            ))
        ));
    }

    #[test]
    fn utreexo_proof_decoder_bounds_leaf_allocation_before_reading_leaves() {
        let mut payload = Vec::new();
        BlockHash::all_zeros()
            .consensus_encode(&mut payload)
            .expect("encode block hash");
        Vec::<BlockHash>::new()
            .consensus_encode(&mut payload)
            .expect("encode proof hashes");
        Vec::<VarInt>::new()
            .consensus_encode(&mut payload)
            .expect("encode target locations");
        VarInt(MAX_UTREEXO_LEAVES as u64 + 1)
            .consensus_encode(&mut payload)
            .expect("encode leaf count");

        assert!(matches!(
            deserialize::<UtreexoProof>(&payload),
            Err(bitcoin::consensus::encode::Error::OversizedVectorAllocation { .. })
        ));
    }

    #[test]
    fn proof_bitmaps_select_big_endian_bits_in_wire_order() {
        let values = [0, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            Peer::select_bitmap(&values, &[0b1010_0001, 0b1000_0000]),
            vec![0, 2, 7, 8]
        );
    }

    struct FragmentedWriter(std::net::TcpStream);

    impl std::io::Write for FragmentedWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.write(&buffer[..buffer.len().min(1)])
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    fn test_worker_context(root: &Path) -> WorkerContext {
        std::fs::create_dir_all(root).expect("create test storage");
        let store = |name: &str| {
            kv::Store::new(kv::Config {
                path: root.join(name),
                temporary: false,
                use_compression: false,
                flush_every_ms: None,
                cache_capacity: None,
                segment_size: None,
            })
            .expect("open test database")
        };
        WorkerContext {
            proof_backend: Arc::new(RwLock::new(
                BlockFile::new(root.join("blocks.dat"), 1024 * 1024).expect("open test block file"),
            )),
            proof_index: Arc::new(BlocksIndex {
                database: store("index"),
            }),
            chainview: Arc::new(ChainView::new(store("chainview"))),
            magic: Magic::REGTEST,
        }
    }

    #[test]
    fn evented_peer_handshake_accepts_fragmented_garbage_and_decoys() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("read listener address");
        let storage = std::env::temp_dir().join(format!(
            "bridge-node-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos()
        ));
        let server_storage = storage.clone();
        let server = std::thread::spawn(move || -> Result<(), PeerError> {
            let context = test_worker_context(&server_storage);
            let (stream, _) = listener.accept()?;
            stream.set_nonblocking(true)?;
            let mut stream = TcpStream::from_std(stream);
            let mut peer = Peer::new(context)?;
            let deadline = Instant::now() + Duration::from_secs(5);
            while !peer.is_established() {
                peer.on_writable(&mut stream)?;
                peer.on_readable(&mut stream)?;
                if Instant::now() >= deadline {
                    return Err(PeerError::HandshakeTimeout);
                }
                std::thread::yield_now();
            }
            Ok(())
        });

        let stream = std::net::TcpStream::connect(address).expect("connect test peer");
        let reader = BufReader::new(stream.try_clone().expect("clone test peer stream"));
        let writer = FragmentedWriter(stream);
        let protocol = Protocol::new(
            Magic::REGTEST.to_bytes(),
            Role::Initiator,
            Some(vec![1, 2, 3, 4]),
            Some(vec![vec![5, 6, 7], vec![8, 9]]),
            reader,
            writer,
        )
        .expect("complete client handshake");

        server
            .join()
            .expect("server handshake thread did not panic")
            .expect("complete server handshake");
        drop(protocol);
        std::fs::remove_dir_all(storage).expect("remove test storage");
    }

    #[test]
    fn slow_and_malformed_peers_do_not_block_bip183_proof_service() {
        let storage = std::env::temp_dir().join(format!(
            "bridge-worker-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos()
        ));
        let context = test_worker_context(&storage);
        let block = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let block_hash = block.block_hash();
        let proof_hash = BlockHash::from_byte_array([1; 32]);
        let leaf = CompactLeafData {
            header_code: 42,
            amount: 5_000,
            spk_ty: ScriptPubkeyType::PubKeyHash,
        };
        let stored_block = UtreexoBlock {
            block,
            udata: Some(UData {
                remember_idx: Vec::new(),
                proof: BatchProof {
                    targets: vec![VarInt(7)],
                    hashes: vec![proof_hash],
                },
                leaves: vec![leaf.clone()],
            }),
        };
        let index = context
            .proof_backend
            .write()
            .expect("lock test block file")
            .append(&stored_block);
        context.proof_index.append(index, block_hash);
        let expected_proof = UtreexoProof {
            block_hash,
            proof_hashes: vec![proof_hash],
            target_locations: vec![VarInt(7)],
            leaf_data: vec![leaf],
        };

        let registry = Arc::new(Mutex::new(PeerRegistry::new(16)));
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker =
            Worker::new(0, context, receiver, registry.clone()).expect("create evented worker");
        let worker_thread = std::thread::spawn(move || worker.run());

        let mut slow_clients = Vec::new();
        for _ in 0..8 {
            let (client, server, address) = tcp_pair();
            let peer_id = match PeerRegistry::lock(&registry).admit(address.ip(), 0, Instant::now())
            {
                Admission::Accepted { peer_id } => peer_id,
                _ => panic!("slow peer should be admitted"),
            };
            sender
                .send(WorkerMessage::NewConnection {
                    address,
                    id: peer_id,
                    stream: server,
                })
                .expect("queue slow peer");
            slow_clients.push(client);
        }

        let (malicious_client, malicious_server, malicious_address) = tcp_pair();
        let malicious_peer_id =
            match PeerRegistry::lock(&registry).admit(malicious_address.ip(), 0, Instant::now()) {
                Admission::Accepted { peer_id } => peer_id,
                _ => panic!("malicious peer should be admitted"),
            };
        sender
            .send(WorkerMessage::NewConnection {
                address: malicious_address,
                id: malicious_peer_id,
                stream: malicious_server,
            })
            .expect("queue malicious peer");
        malicious_client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set malicious peer timeout");
        let malicious_reader = BufReader::new(
            malicious_client
                .try_clone()
                .expect("clone malicious peer stream"),
        );
        let mut malicious_protocol = Protocol::new(
            Magic::REGTEST.to_bytes(),
            Role::Initiator,
            None,
            None,
            malicious_reader,
            malicious_client,
        )
        .expect("complete malicious peer handshake");

        let (client, server, address) = tcp_pair();
        let peer_id = match PeerRegistry::lock(&registry).admit(address.ip(), 0, Instant::now()) {
            Admission::Accepted { peer_id } => peer_id,
            _ => panic!("active peer should be admitted"),
        };
        sender
            .send(WorkerMessage::NewConnection {
                address,
                id: peer_id,
                stream: server,
            })
            .expect("queue active peer");
        malicious_protocol
            .write(&Payload::genuine(vec![18]))
            .expect("send malformed ping");

        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set active peer timeout");
        let reader = BufReader::new(client.try_clone().expect("clone active peer stream"));
        let mut protocol = Protocol::new(
            Magic::REGTEST.to_bytes(),
            Role::Initiator,
            None,
            None,
            reader,
            client,
        )
        .expect("complete active peer handshake");
        let ping =
            V2Codec::encode(&V2Message::Bitcoin(NetworkMessage::Ping(42))).expect("encode ping");
        protocol
            .write(&Payload::genuine(ping))
            .expect("send ping through active peer");
        let response = protocol.read().expect("receive pong through active peer");
        let (short_id, payload) = response.contents().split_first().expect("pong short ID");
        assert_eq!(*short_id, 19);
        assert_eq!(deserialize::<u64>(payload).expect("decode pong"), 42);

        let request = V2Codec::encode(&V2Message::GetUtreexoProof(GetUtreexoProof {
            block_hash,
            include_all: true,
            proof_bitmap: Vec::new(),
            leaf_bitmap: Vec::new(),
        }))
        .expect("encode proof request");
        protocol
            .write(&Payload::genuine(request))
            .expect("send proof request");
        let response = protocol.read().expect("receive utreexo proof");
        let (short_id, payload) = response
            .contents()
            .split_first()
            .expect("utreexo proof short ID");
        assert_eq!(*short_id, 29);
        assert_eq!(
            deserialize::<UtreexoProof>(payload).expect("decode utreexo proof"),
            expected_proof
        );

        drop(protocol);
        drop(malicious_protocol);
        drop(slow_clients);
        drop(sender);
        worker_thread
            .join()
            .expect("worker thread did not panic")
            .expect("worker stopped cleanly");
        std::fs::remove_dir_all(storage).expect("remove worker test storage");
    }

    fn tcp_pair() -> (std::net::TcpStream, TcpStream, SocketAddr) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind socket pair");
        let client =
            std::net::TcpStream::connect(listener.local_addr().expect("read listener address"))
                .expect("connect socket pair");
        let (server, address) = listener.accept().expect("accept socket pair");
        server
            .set_nonblocking(true)
            .expect("set server socket nonblocking");
        (client, TcpStream::from_std(server), address)
    }

    #[test]
    fn user_agents_are_safely_clustered_by_software() {
        assert_eq!(Peer::classify_user_agent("/Floresta:0.8.0/"), "Floresta");
        assert_eq!(
            Peer::classify_user_agent("/Satoshi:28.0.0/Knots:27.1/"),
            "Satoshi"
        );
        assert_eq!(Peer::classify_user_agent("custom:1.0"), "custom");
        assert_eq!(Peer::classify_user_agent("/bad\nname:1.0/"), "Unknown");
        assert_eq!(Peer::classify_user_agent(""), "Unknown");

        let now = Instant::now();
        let mut registry = PeerRegistry::new(4);
        let mut admit = |address: &str| match registry.admit(
            address.parse().expect("valid peer address"),
            0,
            now,
        ) {
            Admission::Accepted { peer_id } => peer_id,
            _ => panic!("peer should be admitted"),
        };
        let floresta = admit("10.0.0.1");
        let satoshi_one = admit("11.0.0.1");
        let satoshi_two = admit("12.0.0.1");
        let _unidentified = admit("13.0.0.1");

        registry.identify(floresta, "Floresta".to_string());
        registry.identify(satoshi_one, "Satoshi".to_string());
        registry.identify(satoshi_two, "Satoshi".to_string());
        registry.identify(satoshi_two, "SpoofedReplacement".to_string());

        assert_eq!(
            registry.software_summary().to_string(),
            "P2P peers total=4 software=[Floresta=1 Satoshi=2] unidentified=1"
        );
    }

    #[test]
    fn advertised_services_use_assigned_bip183_bit() {
        let services = Peer::advertised_services();
        assert!(services.has(ServiceFlags::P2P_V2));
        assert!(services.has(ServiceFlags::WITNESS));
        assert!(services.has(ServiceFlags::from(1 << 12)));
        assert!(!services.has(ServiceFlags::from(1 << 24)));
    }

    #[test]
    fn message_rate_limiter_drops_then_bans_excess_messages() {
        let now = Instant::now();
        let mut limiter = MessageRateLimiter::new(now);
        for _ in 0..MAX_MESSAGES_PER_SECOND {
            assert!(matches!(limiter.check(now), RateLimitDecision::Allow));
        }
        for _ in 1..RATE_LIMIT_VIOLATIONS {
            assert!(matches!(limiter.check(now), RateLimitDecision::Drop));
        }
        assert!(matches!(limiter.check(now), RateLimitDecision::Ban));
        assert!(matches!(
            limiter.check(now + Duration::from_secs(1)),
            RateLimitDecision::Allow
        ));
    }

    #[test]
    fn network_prefix_uses_ipv4_16_and_ipv6_32() {
        let first_v4: IpAddr = "10.20.1.1".parse().expect("valid IPv4 address");
        let same_v4: IpAddr = "10.20.255.1".parse().expect("valid IPv4 address");
        let other_v4: IpAddr = "10.21.1.1".parse().expect("valid IPv4 address");
        assert_eq!(
            NetworkPrefix::from_address(first_v4),
            NetworkPrefix::from_address(same_v4)
        );
        assert_ne!(
            NetworkPrefix::from_address(first_v4),
            NetworkPrefix::from_address(other_v4)
        );

        let first_v6: IpAddr = "2001:db8:1::1".parse().expect("valid IPv6 address");
        let same_v6: IpAddr = "2001:db8:ffff::1".parse().expect("valid IPv6 address");
        let other_v6: IpAddr = "2001:db9::1".parse().expect("valid IPv6 address");
        assert_eq!(
            NetworkPrefix::from_address(first_v6),
            NetworkPrefix::from_address(same_v6)
        );
        assert_ne!(
            NetworkPrefix::from_address(first_v6),
            NetworkPrefix::from_address(other_v6)
        );
    }

    #[test]
    fn full_registry_evicts_oldest_peer_from_duplicate_prefix() {
        let now = Instant::now();
        let mut registry = PeerRegistry::new(3);
        let first = match registry.admit("10.20.1.1".parse().expect("valid peer address"), 0, now) {
            Admission::Accepted { peer_id } => peer_id,
            _ => panic!("first peer should be admitted"),
        };
        let second = match registry.admit(
            "10.20.2.1".parse().expect("valid peer address"),
            1,
            now + Duration::from_millis(1),
        ) {
            Admission::Accepted { peer_id } => peer_id,
            _ => panic!("second peer should be admitted"),
        };
        let third = match registry.admit(
            "11.20.1.1".parse().expect("valid peer address"),
            2,
            now + Duration::from_millis(2),
        ) {
            Admission::Accepted { peer_id } => peer_id,
            _ => panic!("third peer should be admitted"),
        };
        let replacement = registry.admit(
            "12.20.1.1".parse().expect("valid peer address"),
            3,
            now + Duration::from_millis(3),
        );

        let replacement = match replacement {
            Admission::Replaced {
                evicted_peer,
                evicted_worker,
                peer_id,
            } => {
                assert_eq!(evicted_peer, first);
                assert_eq!(evicted_worker, 0);
                peer_id
            }
            _ => panic!("new prefix should replace a duplicate-prefix peer"),
        };
        assert!(!registry.peers.contains_key(&first));
        assert!(registry.peers.contains_key(&second));
        assert!(registry.peers.contains_key(&third));
        assert!(registry.peers.contains_key(&replacement));
    }

    #[test]
    fn full_diverse_registry_rejects_peer_without_useful_eviction() {
        let now = Instant::now();
        let mut registry = PeerRegistry::new(2);
        for address in ["10.20.1.1", "11.20.1.1"] {
            assert!(matches!(
                registry.admit(address.parse().expect("valid peer address"), 0, now,),
                Admission::Accepted { .. }
            ));
        }
        assert!(matches!(
            registry.admit("12.20.1.1".parse().expect("valid peer address"), 0, now,),
            Admission::RejectedCapacity
        ));
    }

    #[test]
    fn rate_limit_disconnect_keeps_ban_until_expiry() {
        let now = Instant::now();
        let address = "10.20.1.1".parse().expect("valid peer address");
        let registry = Arc::new(Mutex::new(PeerRegistry::new(1)));
        let peer_id = match PeerRegistry::lock(&registry).admit(address, 0, now) {
            Admission::Accepted { peer_id } => peer_id,
            _ => panic!("peer should be admitted"),
        };
        assert_eq!(
            Worker::record_disconnect(&registry, peer_id, &PeerError::RateLimitExceeded, now,),
            Some(address)
        );

        let mut registry = PeerRegistry::lock(&registry);
        assert!(registry.is_banned(address, now));
        assert!(matches!(
            registry.admit(address, 0, now),
            Admission::RejectedBanned
        ));
        assert!(!registry.is_banned(address, now + BAN_DURATION + Duration::from_millis(1)));
    }

    #[test]
    fn peer_panic_is_contained_by_worker() {
        let result: Result<(), PeerError> = Worker::protect_peer(|| panic!("malicious peer panic"));
        assert!(matches!(result, Err(PeerError::Panicked)));
    }
}
