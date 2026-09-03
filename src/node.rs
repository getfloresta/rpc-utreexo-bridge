// SPDX-License-Identifier: MIT

//! A BIP 324 encrypted Bitcoin P2P server.
//!
//! The server keeps the original evented architecture: an acceptor dispatches
//! established connections to a fixed set of workers, and each worker advances
//! many peers from readiness events. A bounded handshake pool keeps slow
//! handshakes from blocking those workers.

use std::collections::HashMap;
use std::fmt::Display;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::TryRecvError;
use std::sync::mpsc::TrySendError;
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
use bip324::ReceivedKey;
use bip324::Role;
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

use crate::block_index::BlocksIndex;
use crate::blockfile::BlockFile;
use crate::chainview::ChainView;

/// Deprecated Utreexo compact-filter type retained for compatibility.
pub const FILTER_TYPE_UTREEXO: u8 = 1;

const WORKERS_PER_CLUSTER: usize = 4;
const HANDSHAKE_WORKERS: usize = 4;
const HANDSHAKE_QUEUE_SIZE: usize = 64;
const MAX_PEERS: usize = 64;
const MAX_BANNED_PEERS: usize = 4_096;
const MAX_MESSAGES_PER_SECOND: u32 = 100;
const RATE_LIMIT_VIOLATIONS: u8 = 3;
const EVENT_CAPACITY: usize = 1_024;
const READ_BUFFER_SIZE: usize = 64 * 1_024;
const MAX_PACKET_SIZE: usize = 4_000_014;
const MAX_WRITE_BUFFER_SIZE: usize = 16 * 1_024 * 1_024;
const MAX_HEADERS: u64 = 2_000;
const BIP324_KEY_SIZE: usize = 64;
const UTXO_PROOF_INVENTORY_TYPE: u32 = 0x41000002;
const NODE_UTREEXO: u64 = 1 << 24;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const BAN_DURATION: Duration = Duration::from_secs(60 * 60);
const POLL_TIMEOUT: Duration = Duration::from_millis(100);

type SharedPeerRegistry = Arc<Mutex<PeerRegistry>>;

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

struct PeerRecord {
    address: IpAddr,
    connected_at: Instant,
    prefix: NetworkPrefix,
    worker: usize,
}

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

enum RateLimitDecision {
    Allow,
    Drop,
    Ban,
}

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
    /// Starts the acceptor, handshake pool, and evented workers.
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
        let (completed_tx, completed_rx) = std::sync::mpsc::channel();
        let handshake_tx = Self::create_handshake_workers(worker_context.magic, completed_tx)?;
        let acceptor = Acceptor {
            block_notifier,
            completed_handshakes: completed_rx,
            handshake_workers: handshake_tx,
            listener,
            next_worker: 0,
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
    ) -> Result<Vec<Sender<WorkerMessage>>, NodeError> {
        let mut workers = Vec::with_capacity(WORKERS_PER_CLUSTER);
        for id in 0..WORKERS_PER_CLUSTER {
            let (sender, receiver) = std::sync::mpsc::channel();
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

    fn create_handshake_workers(
        magic: Magic,
        completed: Sender<HandshakenConnection>,
    ) -> Result<SyncSender<HandshakeJob>, NodeError> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(HANDSHAKE_QUEUE_SIZE);
        let receiver = Arc::new(Mutex::new(receiver));
        for id in 0..HANDSHAKE_WORKERS {
            let worker = HandshakeWorker {
                completed: completed.clone(),
                jobs: receiver.clone(),
                magic,
            };
            std::thread::Builder::new()
                .name(format!("bridge-p2p-handshake-{id}"))
                .spawn(move || worker.run())
                .map_err(NodeError::Spawn)?;
        }
        Ok(sender)
    }
}

struct HandshakeJob {
    address: SocketAddr,
    stream: std::net::TcpStream,
}

struct HandshakenConnection {
    address: SocketAddr,
    initial_bytes: Vec<u8>,
    session: bip324::CipherSession,
    stream: TcpStream,
}

struct HandshakeWorker {
    completed: Sender<HandshakenConnection>,
    jobs: Arc<Mutex<Receiver<HandshakeJob>>>,
    magic: Magic,
}

impl HandshakeWorker {
    fn run(self) {
        loop {
            let job = {
                let receiver = match self.jobs.lock() {
                    Ok(receiver) => receiver,
                    Err(poisoned) => {
                        warn!("Recovering poisoned P2P handshake queue");
                        poisoned.into_inner()
                    }
                };
                match receiver.recv() {
                    Ok(job) => job,
                    Err(_) => return,
                }
            };

            let address = job.address;
            let result =
                std::panic::catch_unwind(AssertUnwindSafe(|| Self::perform(job, self.magic)));
            match result {
                Ok(Ok(connection)) => {
                    if self.completed.send(connection).is_err() {
                        return;
                    }
                }
                Ok(Err(error)) => {
                    debug!("P2PV2 handshake failed for {address}: {error}");
                }
                Err(_) => {
                    warn!("Contained panic from P2PV2 handshake at {address}");
                }
            }
        }
    }

    fn perform(job: HandshakeJob, magic: Magic) -> Result<HandshakenConnection, PeerError> {
        let HandshakeJob {
            address,
            mut stream,
        } = job;
        stream.set_nonblocking(false)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

        let handshake = Handshake::<Initialized>::new(magic.to_bytes(), Role::Responder)?;
        let key_size = Handshake::<Initialized>::send_key_len(None);
        let mut local_key = vec![0; key_size];
        let handshake = handshake.send_key(None, &mut local_key)?;
        stream.write_all(&local_key)?;

        let mut remote_key = [0; BIP324_KEY_SIZE];
        stream.read_exact(&mut remote_key)?;
        let handshake = handshake.receive_key(remote_key)?;

        let version_size = Handshake::<ReceivedKey>::send_version_len(None);
        let mut local_version = vec![0; version_size];
        let mut handshake = handshake.send_version(&mut local_version, None)?;
        stream.write_all(&local_version)?;

        let mut garbage_buffer = Vec::with_capacity(256);
        let (mut handshake, consumed) = loop {
            Self::read_more(&mut stream, &mut garbage_buffer)?;
            match handshake.receive_garbage(&garbage_buffer)? {
                GarbageResult::FoundGarbage {
                    handshake,
                    consumed_bytes,
                } => break (handshake, consumed_bytes),
                GarbageResult::NeedMoreData(next) => handshake = next,
            }
        };
        let mut version_buffer = garbage_buffer[consumed..].to_vec();
        let mut position = 0;

        let session = loop {
            Self::read_until(
                &mut stream,
                &mut version_buffer,
                position + bip324::NUM_LENGTH_BYTES,
            )?;
            let length_end = position + bip324::NUM_LENGTH_BYTES;
            let mut encrypted_length = [0; bip324::NUM_LENGTH_BYTES];
            encrypted_length.copy_from_slice(&version_buffer[position..length_end]);
            let packet_size = handshake.decrypt_packet_len(encrypted_length)?;
            if packet_size > MAX_PACKET_SIZE {
                return Err(PeerError::MessageTooLarge(packet_size));
            }

            let packet_end = length_end + packet_size;
            Self::read_until(&mut stream, &mut version_buffer, packet_end)?;
            let mut packet = version_buffer[length_end..packet_end].to_vec();
            position = packet_end;
            match handshake.receive_version(&mut packet)? {
                VersionResult::Complete { cipher } => break cipher,
                VersionResult::Decoy(next) => handshake = next,
            }
        };

        let initial_bytes = version_buffer[position..].to_vec();
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;
        stream.set_nonblocking(true)?;

        Ok(HandshakenConnection {
            address,
            initial_bytes,
            session,
            stream: TcpStream::from_std(stream),
        })
    }

    fn read_more(stream: &mut std::net::TcpStream, buffer: &mut Vec<u8>) -> Result<(), PeerError> {
        let mut chunk = [0; 256];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(PeerError::Disconnected);
        }
        buffer.extend_from_slice(&chunk[..read]);
        Ok(())
    }

    fn read_until(
        stream: &mut std::net::TcpStream,
        buffer: &mut Vec<u8>,
        target: usize,
    ) -> Result<(), PeerError> {
        while buffer.len() < target {
            let remaining = target - buffer.len();
            let mut chunk = [0; 1_024];
            let chunk_size = remaining.min(chunk.len());
            let read = stream.read(&mut chunk[..chunk_size])?;
            if read == 0 {
                return Err(PeerError::Disconnected);
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        Ok(())
    }
}

enum WorkerMessage {
    NewConnection {
        id: usize,
        connection: Box<HandshakenConnection>,
    },
    NewBlock(BlockHash),
    Disconnect(usize),
}

struct PeerConnection {
    address: SocketAddr,
    id: usize,
    peer: Peer,
    stream: TcpStream,
}

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
        }
    }

    fn handle_messages(&mut self) -> Result<bool, PeerError> {
        loop {
            match self.messages.try_recv() {
                Ok(WorkerMessage::NewConnection { id, connection }) => {
                    if let Err(error) = self.add_peer(id, connection) {
                        PeerRegistry::lock(&self.registry).remove(id);
                        debug!("Worker {} rejected peer {id}: {error}", self.id);
                    }
                }
                Ok(WorkerMessage::NewBlock(block_hash)) => {
                    self.broadcast_block(block_hash);
                }
                Ok(WorkerMessage::Disconnect(id)) => {
                    self.disconnect_peer(id);
                }
                Err(TryRecvError::Empty) => return Ok(true),
                Err(TryRecvError::Disconnected) => return Ok(false),
            }
        }
    }

    fn add_peer(
        &mut self,
        id: usize,
        connection: Box<HandshakenConnection>,
    ) -> Result<(), PeerError> {
        let token = self.allocate_token().ok_or(PeerError::NoPeerToken)?;
        let HandshakenConnection {
            address,
            initial_bytes,
            session,
            mut stream,
        } = *connection;
        self.poller
            .registry()
            .register(&mut stream, token, Interest::READABLE)?;
        let mut connection = PeerConnection {
            address,
            id,
            peer: Peer::new(self.context.clone(), session, initial_bytes),
            stream,
        };

        let initial_result = Self::protect_peer(|| connection.peer.process_messages());
        if let Err(error) = initial_result {
            let _ = self.poller.registry().deregister(&mut connection.stream);
            return Err(error);
        }
        if connection.peer.wants_write() {
            self.poller.registry().reregister(
                &mut connection.stream,
                token,
                Interest::READABLE | Interest::WRITABLE,
            )?;
        }
        info!(
            "Worker {} accepted P2PV2 peer {} at {}",
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
                Some(connection) => Self::protect_peer(|| {
                    connection.peer.send_message(NetworkMessage::Inv(vec![
                        Inventory::WitnessBlock(block_hash),
                    ]))
                }),
                None => continue,
            };
            if let Err(error) = result {
                self.remove_peer(token, &error);
            } else if let Err(error) = self.refresh_interest(token) {
                self.remove_peer(token, &error);
            }
        }
    }

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
    fn protect_peer<T>(operation: impl FnOnce() -> Result<T, PeerError>) -> Result<T, PeerError> {
        match std::panic::catch_unwind(AssertUnwindSafe(operation)) {
            Ok(result) => result,
            Err(_) => Err(PeerError::Panicked),
        }
    }
}

struct Acceptor {
    block_notifier: Receiver<BlockHash>,
    completed_handshakes: Receiver<HandshakenConnection>,
    handshake_workers: SyncSender<HandshakeJob>,
    listener: TcpListener,
    next_worker: usize,
    registry: SharedPeerRegistry,
    workers: Vec<Sender<WorkerMessage>>,
}

impl Acceptor {
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
            self.dispatch_completed_handshakes();
            self.broadcast_blocks();
        }
    }

    fn accept_ready_connections(&mut self) {
        loop {
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
            if PeerRegistry::lock(&self.registry).is_banned(address.ip(), Instant::now()) {
                debug!("Rejecting banned P2P peer at {address}");
                continue;
            }
            let job = HandshakeJob {
                address,
                stream: stream.into(),
            };
            match self.handshake_workers.try_send(job) {
                Ok(()) => {}
                Err(TrySendError::Full(job)) => {
                    debug!(
                        "Rejecting P2P connection from {}: handshake queue full",
                        job.address
                    );
                }
                Err(TrySendError::Disconnected(_)) => {
                    error!("All P2P handshake workers stopped");
                    return;
                }
            }
        }
    }

    fn dispatch_completed_handshakes(&mut self) {
        loop {
            let connection = match self.completed_handshakes.try_recv() {
                Ok(connection) => connection,
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    error!("P2P handshake result channel closed");
                    return;
                }
            };
            if self.workers.is_empty() {
                error!("No P2P worker is available");
                return;
            }
            let worker_id = self.next_worker % self.workers.len();
            self.next_worker = (self.next_worker + 1) % self.workers.len();
            let admission = PeerRegistry::lock(&self.registry).admit(
                connection.address.ip(),
                worker_id,
                Instant::now(),
            );
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
                    debug!("Rejecting banned P2P peer at {}", connection.address);
                    continue;
                }
                Admission::RejectedCapacity => {
                    debug!(
                        "Rejecting P2P peer at {}: peer capacity reached",
                        connection.address
                    );
                    continue;
                }
            };
            let Some(worker) = self.workers.get(worker_id) else {
                PeerRegistry::lock(&self.registry).remove(peer_id);
                continue;
            };
            if worker
                .send(WorkerMessage::NewConnection {
                    id: peer_id,
                    connection: Box::new(connection),
                })
                .is_err()
            {
                warn!("P2P worker stopped before accepting peer {peer_id}");
                PeerRegistry::lock(&self.registry).remove_worker(worker_id);
            }
        }
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

struct Peer {
    context: WorkerContext,
    inbound: InboundCipher,
    outbound: OutboundCipher,
    packet_size: Option<usize>,
    rate_limiter: MessageRateLimiter,
    read_buffer: Vec<u8>,
    read_position: usize,
    write_buffer: Vec<u8>,
    write_position: usize,
}

impl Peer {
    fn new(context: WorkerContext, session: bip324::CipherSession, initial_bytes: Vec<u8>) -> Self {
        let (inbound, outbound) = session.into_split();
        Self {
            context,
            inbound,
            outbound,
            packet_size: None,
            rate_limiter: MessageRateLimiter::new(Instant::now()),
            read_buffer: initial_bytes,
            read_position: 0,
            write_buffer: Vec::new(),
            write_position: 0,
        }
    }

    fn on_readable(&mut self, stream: &mut TcpStream) -> Result<(), PeerError> {
        let mut buffer = [0; READ_BUFFER_SIZE];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => return Err(PeerError::Disconnected),
                Ok(read) => {
                    self.read_buffer.extend_from_slice(&buffer[..read]);
                    self.process_messages()?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn process_messages(&mut self) -> Result<(), PeerError> {
        let now = Instant::now();
        loop {
            if self.packet_size.is_none() {
                let length_end = self.read_position + bip324::NUM_LENGTH_BYTES;
                let Some(length) = self.read_buffer.get(self.read_position..length_end) else {
                    break;
                };
                let mut encrypted_length = [0; bip324::NUM_LENGTH_BYTES];
                encrypted_length.copy_from_slice(length);
                let packet_size = self.inbound.decrypt_packet_len(encrypted_length);
                if packet_size > MAX_PACKET_SIZE {
                    return Err(PeerError::MessageTooLarge(packet_size));
                }
                self.packet_size = Some(packet_size);
                self.read_position = length_end;
            }

            let packet_size = match self.packet_size {
                Some(packet_size) => packet_size,
                None => break,
            };
            let packet_end = self.read_position + packet_size;
            if self.read_buffer.len() < packet_end {
                break;
            }

            let (packet_type, message) = self
                .inbound
                .decrypt_in_place(&mut self.read_buffer[self.read_position..packet_end], None)?;
            let request = if packet_type == PacketType::Genuine {
                match self.rate_limiter.check(now) {
                    RateLimitDecision::Allow => Some(V2Codec::decode(&message[1..])?),
                    RateLimitDecision::Drop => None,
                    RateLimitDecision::Ban => {
                        return Err(PeerError::RateLimitExceeded);
                    }
                }
            } else {
                None
            };
            self.read_position = packet_end;
            self.packet_size = None;
            if let Some(request) = request {
                self.handle_message(request)?;
            }
        }

        self.compact_read_buffer();
        Ok(())
    }

    fn compact_read_buffer(&mut self) {
        if self.read_position == 0 {
            return;
        }
        if self.read_position == self.read_buffer.len() {
            self.read_buffer.clear();
            self.read_position = 0;
            return;
        }
        if self.read_position >= READ_BUFFER_SIZE {
            let remaining = self.read_buffer.len() - self.read_position;
            self.read_buffer.copy_within(self.read_position.., 0);
            self.read_buffer.truncate(remaining);
            self.read_position = 0;
        }
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
        let payload = V2Codec::encode(&message)?;
        self.send_payload(&payload)
    }

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

        let start = self.write_buffer.len();
        self.write_buffer.resize(start + packet_size, 0);
        self.outbound.encrypt(
            payload,
            &mut self.write_buffer[start..],
            PacketType::Genuine,
            None,
        )?;
        Ok(())
    }

    fn handle_message(&mut self, request: NetworkMessage) -> Result<(), PeerError> {
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
                info!(
                    "P2PV2 handshake version={} blocks={} services={} address={:?}",
                    version.user_agent,
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
        for item in inventory {
            match item {
                Inventory::Unknown { hash, inv_type } if inv_type == UTXO_PROOF_INVENTORY_TYPE => {
                    let block_hash = BlockHash::from_byte_array(hash);
                    let Some(index) = self.context.proof_index.get_index(block_hash) else {
                        self.send_message(NetworkMessage::NotFound(vec![Inventory::Unknown {
                            hash,
                            inv_type,
                        }]))?;
                        continue;
                    };
                    let payload = {
                        let backend = self
                            .context
                            .proof_backend
                            .read()
                            .map_err(|_| PeerError::PoisonedProofBackend)?;
                        V2Codec::encode_raw_block(backend.get_block_slice(index))
                    };
                    self.send_payload(&payload)?;
                }
                Inventory::WitnessBlock(block_hash) => {
                    let Some(index) = self.context.proof_index.get_index(block_hash) else {
                        self.send_message(NetworkMessage::NotFound(vec![
                            Inventory::WitnessBlock(block_hash),
                        ]))?;
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
                        None => self.send_message(NetworkMessage::NotFound(vec![
                            Inventory::WitnessBlock(block_hash),
                        ]))?,
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn headers_for_request(
        &self,
        request: &GetHeadersMessage,
    ) -> Result<Vec<bitcoin::block::Header>, PeerError> {
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

struct V2Codec;

impl V2Codec {
    fn encode_raw_block(block: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(block.len() + 1);
        payload.push(2);
        payload.extend_from_slice(block);
        payload
    }
    fn encode(message: &NetworkMessage) -> Result<Vec<u8>, PeerError> {
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

    fn decode(buffer: &[u8]) -> Result<NetworkMessage, PeerError> {
        let Some((&short_id, mut payload)) = buffer.split_first() else {
            return Err(PeerError::MissingShortId);
        };
        match short_id {
            0 => Self::decode_long_command(payload),
            1 => Ok(NetworkMessage::Addr(Decodable::consensus_decode(
                &mut payload,
            )?)),
            2 => Ok(NetworkMessage::Block(Decodable::consensus_decode(
                &mut payload,
            )?)),
            3 => Ok(NetworkMessage::BlockTxn(Decodable::consensus_decode(
                &mut payload,
            )?)),
            4 => Ok(NetworkMessage::CmpctBlock(Decodable::consensus_decode(
                &mut payload,
            )?)),
            5 => Ok(NetworkMessage::FeeFilter(Decodable::consensus_decode(
                &mut payload,
            )?)),
            6 => Ok(NetworkMessage::FilterAdd(Decodable::consensus_decode(
                &mut payload,
            )?)),
            7 => Ok(NetworkMessage::FilterClear),
            8 => Ok(NetworkMessage::FilterLoad(Decodable::consensus_decode(
                &mut payload,
            )?)),
            9 => Ok(NetworkMessage::GetBlocks(Decodable::consensus_decode(
                &mut payload,
            )?)),
            10 => Ok(NetworkMessage::GetBlockTxn(Decodable::consensus_decode(
                &mut payload,
            )?)),
            11 => Ok(NetworkMessage::GetData(Decodable::consensus_decode(
                &mut payload,
            )?)),
            12 => Ok(NetworkMessage::GetHeaders(Decodable::consensus_decode(
                &mut payload,
            )?)),
            13 => Self::decode_headers(payload),
            14 => Ok(NetworkMessage::Inv(Decodable::consensus_decode(
                &mut payload,
            )?)),
            15 => Ok(NetworkMessage::MemPool),
            16 => Ok(NetworkMessage::MerkleBlock(Decodable::consensus_decode(
                &mut payload,
            )?)),
            17 => Ok(NetworkMessage::NotFound(Decodable::consensus_decode(
                &mut payload,
            )?)),
            18 => Ok(NetworkMessage::Ping(Decodable::consensus_decode(
                &mut payload,
            )?)),
            19 => Ok(NetworkMessage::Pong(Decodable::consensus_decode(
                &mut payload,
            )?)),
            20 => Ok(NetworkMessage::SendCmpct(Decodable::consensus_decode(
                &mut payload,
            )?)),
            21 => Ok(NetworkMessage::Tx(Decodable::consensus_decode(
                &mut payload,
            )?)),
            22 => Ok(NetworkMessage::GetCFilters(Decodable::consensus_decode(
                &mut payload,
            )?)),
            23 => Ok(NetworkMessage::CFilter(Decodable::consensus_decode(
                &mut payload,
            )?)),
            24 => Ok(NetworkMessage::GetCFHeaders(Decodable::consensus_decode(
                &mut payload,
            )?)),
            25 => Ok(NetworkMessage::CFHeaders(Decodable::consensus_decode(
                &mut payload,
            )?)),
            26 => Ok(NetworkMessage::GetCFCheckpt(Decodable::consensus_decode(
                &mut payload,
            )?)),
            27 => Ok(NetworkMessage::CFCheckpt(Decodable::consensus_decode(
                &mut payload,
            )?)),
            28 => Ok(NetworkMessage::AddrV2(Decodable::consensus_decode(
                &mut payload,
            )?)),
            unknown => Err(PeerError::UnknownShortId(unknown)),
        }
    }

    fn decode_long_command(buffer: &[u8]) -> Result<NetworkMessage, PeerError> {
        let Some(command_bytes) = buffer.get(..12) else {
            return Err(PeerError::MissingCommand);
        };
        let mut command_reader = command_bytes;
        let command = CommandString::consensus_decode(&mut command_reader)?;
        let mut payload = &buffer[12..];
        match command.as_ref() {
            "version" => Ok(NetworkMessage::Version(Decodable::consensus_decode(
                &mut payload,
            )?)),
            "verack" => Ok(NetworkMessage::Verack),
            "sendheaders" => Ok(NetworkMessage::SendHeaders),
            "getaddr" => Ok(NetworkMessage::GetAddr),
            "wtxidrelay" => Ok(NetworkMessage::WtxidRelay),
            "sendaddrv2" => Ok(NetworkMessage::SendAddrV2),
            "alert" => Ok(NetworkMessage::Alert(Decodable::consensus_decode(
                &mut payload,
            )?)),
            "reject" => Ok(NetworkMessage::Reject(Decodable::consensus_decode(
                &mut payload,
            )?)),
            _ => Ok(NetworkMessage::Unknown {
                command,
                payload: payload.to_vec(),
            }),
        }
    }

    fn decode_headers(mut payload: &[u8]) -> Result<NetworkMessage, PeerError> {
        let count = VarInt::consensus_decode(&mut payload)?.0;
        if count > MAX_HEADERS {
            return Err(PeerError::TooManyHeaders(count));
        }
        let mut headers = Vec::with_capacity(count as usize);
        for _ in 0..count {
            headers.push(Decodable::consensus_decode(&mut payload)?);
            if u8::consensus_decode(&mut payload)? != 0 {
                return Err(PeerError::HeadersContainTransactions);
            }
        }
        Ok(NetworkMessage::Headers(headers))
    }
}

#[derive(Debug)]
enum PeerError {
    Decode(bitcoin::consensus::encode::Error),
    Disconnected,
    Evicted,
    HeadersContainTransactions,
    Io(std::io::Error),
    MessageTooLarge(usize),
    MissingCommand,
    MissingShortId,
    NoPeerToken,
    Panicked,
    PoisonedProofBackend,
    Protocol(bip324::Error),
    RateLimitExceeded,
    Storage(kv::Error),
    TooManyHeaders(u64),
    UnknownShortId(u8),
    WriteBufferFull,
}

impl Display for PeerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(error) => write!(formatter, "message decode error: {error}"),
            Self::Disconnected => formatter.write_str("connection closed"),
            Self::Evicted => formatter.write_str("evicted to preserve peer prefix diversity"),
            Self::HeadersContainTransactions => {
                formatter.write_str("headers message contains a nonzero transaction count")
            }
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::MessageTooLarge(size) => {
                write!(formatter, "P2PV2 message is too large: {size} bytes")
            }
            Self::MissingCommand => formatter.write_str("P2PV2 long message has no command"),
            Self::MissingShortId => formatter.write_str("P2PV2 message has no short ID"),
            Self::NoPeerToken => formatter.write_str("no peer token is available"),
            Self::Panicked => formatter.write_str("peer operation panicked"),
            Self::PoisonedProofBackend => formatter.write_str("proof backend lock is poisoned"),
            Self::Protocol(error) => write!(formatter, "BIP 324 error: {error}"),
            Self::RateLimitExceeded => formatter.write_str("peer exceeded the message rate limit"),
            Self::Storage(error) => write!(formatter, "peer storage error: {error}"),
            Self::TooManyHeaders(count) => {
                write!(formatter, "headers message contains {count} headers")
            }
            Self::UnknownShortId(id) => {
                write!(formatter, "unknown P2PV2 short ID {id}")
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

    use bip324::io::Protocol;

    use super::*;

    #[test]
    fn p2pv2_codec_round_trips_short_and_long_messages() {
        for message in [
            NetworkMessage::Ping(42),
            NetworkMessage::Verack,
            NetworkMessage::Unknown {
                command: CommandString::try_from_static("custom").expect("test command is valid"),
                payload: vec![1, 2, 3],
            },
        ] {
            let encoded = V2Codec::encode(&message).expect("message encodes");
            let decoded = V2Codec::decode(&encoded).expect("message decodes");
            assert_eq!(decoded, message);
        }
    }

    #[test]
    fn evented_server_handshake_interoperates_with_sync_client() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("read listener address");
        let server = std::thread::spawn(move || {
            let (stream, address) = listener.accept().expect("accept test peer");
            HandshakeWorker::perform(HandshakeJob { address, stream }, Magic::REGTEST)
        });

        let stream = std::net::TcpStream::connect(address).expect("connect test peer");
        let reader = BufReader::new(stream.try_clone().expect("clone test peer stream"));
        let protocol = Protocol::new(
            Magic::REGTEST.to_bytes(),
            Role::Initiator,
            None,
            None,
            reader,
            stream,
        )
        .expect("complete client handshake");
        drop(protocol);

        server
            .join()
            .expect("server handshake thread did not panic")
            .expect("complete server handshake");
    }

    #[test]
    fn advertised_services_require_p2pv2() {
        let services = Peer::advertised_services();
        assert!(services.has(ServiceFlags::P2P_V2));
        assert!(services.has(ServiceFlags::WITNESS));
        assert!(services.has(ServiceFlags::from(NODE_UTREEXO)));
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
