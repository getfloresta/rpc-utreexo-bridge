//SPDX-License-Identifier: MIT

//! A simple and efficient implementation of Bitcoin P2P network
//!
//! This bridge software gives you the option to serve proofs and blocks over the
//! p2p port, just like any other node. The way it works is simple and meant to use
//! as little deps as possible. We explicitly don't use async/await on this.
//!
//! ## Architecture
//!
//! This implementation uses async IO, but without the overhead of proper async/await.
//! It is broken down in three modules: [Acceptor], [Worker] and [Peer].
//! The [Acceptor] is responsible for accepting new connections and notifying the workers about
//! them.
//! The [Worker] is responsible for processing the requests and sending responses back to the
//! peers. It has an internal reactor that polls for events on the sockets it is watching, handles
//! them and sends the relevant messages to the [Peer].
//! A [Peer] holds the inner state of a connection, and is responsible for reading requests,
//! writing responses and handling the protocol. It has a read buffer and a write buffer,
//! and it uses them to read requests and write responses.

use std::collections::HashMap;
use std::fmt::Display;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::sync::PoisonError;
use std::sync::RwLock;
use std::time::Duration;

use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message::RawNetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_filter::CFilter;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::Magic;
use bitcoin::p2p::ServiceFlags;
use bitcoin::BlockHash;
use bitcoin::VarInt;
use log::debug;
use log::info;
use mio::net::TcpListener;
use mio::net::TcpStream;
use mio::Events;
use sha2::Digest;
use sha2::Sha256;

use crate::block_index::BlockIndex;
use crate::block_index::BlocksIndex;
use crate::blockfile::BlockFile;
use crate::blockfile::ProofFile;
use crate::chainview::ChainView;
use crate::udata::CompactBlockProof;

/// DEPRECATED: This is a constant that defines the filter type for Utreexo
pub const FILTER_TYPE_UTREEXO: u8 = 1;

/// How many workers we want to spawn
const WORKES_PER_CLUSTER: usize = 4;

const GET_UTREEXO_PROOF_COMMAND: &str = "getuproof";
const UTREEXO_PROOF_COMMAND: &str = "uproof";
const NODE_UTREEXO: u64 = 1 << 12;
const REQUEST_TARGETS: u8 = 1 << 0;
const REQUEST_PROOF_HASHES: u8 = 1 << 1;
const REQUEST_LEAF_DATA: u8 = 1 << 2;

#[derive(Debug)]
/// A minimal version of the message header
///
/// We need this because `rust-bitcoin` won't let us read only the reader, only the full message.
/// But we may need this to figure out whether we have all the data, or should just wait for a
/// while.
pub struct P2PMessageHeader {
    /// Magic data that's always in the beginning of a message
    ///
    /// This constant is defined per-network, and if it doesn't match what we expected, we'll
    /// disconnect with that peer
    _magic: Magic,

    /// A command string telling what this message should be (e.g.: block, inv, tx)
    _command: [u8; 12],

    /// How long this message is
    length: u32,

    /// The payload's checksum
    _checksum: u32,
}

#[derive(Clone)]
pub enum ProofBackend {
    LegacyBlocks(Arc<RwLock<BlockFile>>),
    CompactProofs(Arc<RwLock<ProofFile>>),
}

impl ProofBackend {
    fn get(&self, index: BlockIndex) -> Option<CompactBlockProof> {
        match self {
            Self::LegacyBlocks(blocks) => {
                let block = blocks.read().ok()?.get_block(index)?;
                let proof = block.udata?;
                Some(CompactBlockProof {
                    proof: proof.proof,
                    leaves: proof.leaves,
                })
            }
            Self::CompactProofs(proofs) => proofs.read().ok()?.get(&index),
        }
    }
}

#[derive(Clone)]
/// Data required by our peers to handle requests
pub struct WorkerContext {
    /// Compact proofs retained after the hintsfile boundary, or legacy block-plus-proof storage.
    pub proof_backend: ProofBackend,

    /// An index on the selected proof backend.
    pub proof_index: Arc<BlocksIndex>,

    /// Our chain metadata. Things like our height, and  an index height -> hash
    pub chainview: Arc<ChainView>,

    /// The magic bits for the network we are on
    pub magic: Magic,
}

impl Decodable for P2PMessageHeader {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> std::result::Result<Self, bitcoin::consensus::encode::Error> {
        let _magic = Magic::consensus_decode(reader)?;
        let _command = <[u8; 12]>::consensus_decode(reader)?;
        let length = u32::consensus_decode(reader)?;
        let _checksum = u32::consensus_decode(reader)?;
        Ok(Self {
            _checksum,
            _command,
            length,
            _magic,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
struct GetUtreexoProof {
    block_hash: BlockHash,
    request_mask: u8,
    proof_hashes_bitmap: Vec<u8>,
    leaf_data_bitmap: Vec<u8>,
}

impl Decodable for GetUtreexoProof {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        Ok(Self {
            block_hash: BlockHash::consensus_decode(reader)?,
            request_mask: u8::consensus_decode(reader)?,
            proof_hashes_bitmap: Vec::<u8>::consensus_decode(reader)?,
            leaf_data_bitmap: Vec::<u8>::consensus_decode(reader)?,
        })
    }
}

fn request_field(mask: u8, field: u8) -> bool {
    mask & field != 0
}

fn bitmap_requests(bitmap: &[u8], index: usize) -> bool {
    bitmap.is_empty()
        || bitmap
            .get(index / u8::BITS as usize)
            .is_some_and(|byte| byte & (1 << (index % u8::BITS as usize)) != 0)
}

fn selected_count(bitmap: &[u8], length: usize) -> usize {
    (0..length)
        .filter(|index| bitmap_requests(bitmap, *index))
        .count()
}

fn encode_utreexo_proof(
    block_hash: BlockHash,
    request: &GetUtreexoProof,
    proof: &CompactBlockProof,
) -> Result<Vec<u8>, bitcoin::io::Error> {
    let mut payload = Vec::new();
    block_hash.consensus_encode(&mut payload)?;

    let include_proof_hashes = request_field(request.request_mask, REQUEST_PROOF_HASHES);
    let proof_hash_count = if include_proof_hashes {
        selected_count(&request.proof_hashes_bitmap, proof.proof.hashes.len())
    } else {
        0
    };
    VarInt(proof_hash_count as u64).consensus_encode(&mut payload)?;
    if include_proof_hashes {
        for (index, hash) in proof.proof.hashes.iter().enumerate() {
            if bitmap_requests(&request.proof_hashes_bitmap, index) {
                hash.consensus_encode(&mut payload)?;
            }
        }
    }

    let include_targets = request_field(request.request_mask, REQUEST_TARGETS);
    VarInt(if include_targets {
        proof.proof.targets.len() as u64
    } else {
        0
    })
    .consensus_encode(&mut payload)?;
    if include_targets {
        for target in &proof.proof.targets {
            target.consensus_encode(&mut payload)?;
        }
    }

    let include_leaf_data = request_field(request.request_mask, REQUEST_LEAF_DATA);
    let leaf_data_count = if include_leaf_data {
        selected_count(&request.leaf_data_bitmap, proof.leaves.len())
    } else {
        0
    };
    VarInt(leaf_data_count as u64).consensus_encode(&mut payload)?;
    if include_leaf_data {
        for (index, leaf) in proof.leaves.iter().enumerate() {
            if bitmap_requests(&request.leaf_data_bitmap, index) {
                leaf.header_code.consensus_encode(&mut payload)?;
                leaf.amount.consensus_encode(&mut payload)?;
                leaf.spk_ty.consensus_encode(&mut payload)?;
            }
        }
    }
    Ok(payload)
}

fn advertised_services() -> ServiceFlags {
    ServiceFlags::WITNESS | ServiceFlags::from(NODE_UTREEXO)
}

/// A struct that will set everything up and running. It doesn't have any state nor runs on any
/// thread, but after calling `run` you should have everything set.
pub struct Node;

impl Node {
    /// Spawn a reactor and some workers to handle requests.
    ///
    /// If we can't set things up, this function will panic
    pub fn run(
        address: SocketAddr,
        worker_context: WorkerContext,
        block_notifier: Receiver<BlockHash>,
    ) {
        let listener = TcpListener::bind(address).expect("Failed to bind to address");
        let reactor = Acceptor {
            block_notifier,
            listener,
            worker_pool: Self::create_workers(&worker_context),
        };

        std::thread::Builder::new()
            .name("bridge - acceptor thread".to_string())
            .spawn(move || reactor.run())
            .expect("Failed to spawn reactor");
    }

    /// spawns our workers
    fn create_workers(worker_context: &WorkerContext) -> [Sender<Message>; WORKES_PER_CLUSTER] {
        let mut workers = Vec::new();
        for i in 0..WORKES_PER_CLUSTER {
            let (tx, rx) = std::sync::mpsc::channel();
            let worker = Worker::new(i, worker_context.clone(), rx);

            std::thread::Builder::new()
                .name(format!("bridge - worker {}", i))
                .spawn(move || worker.run())
                .expect("Failed to spawn worker");

            workers.push(tx);
        }

        workers.try_into().expect("Failed to create workers")
    }
}

#[derive(Debug)]
/// Messages sent from [Reactor] to [Worker]
pub enum Message {
    /// The server got a new connection
    ///
    /// Once a worker gets this, it'll construct a [Peer] struct and schedule it for the next
    /// message
    NewConnection(TcpStream),

    NewBlock(BlockHash),
}

/// A struct that will run and wait for work to do. Once it gets a new work from [Reactor], it will
/// call the relevant functions and use its cpu share to make progress
struct Worker {
    /// A unique per-worker identifier
    id: usize,

    /// A channel to receive messages from the [Acceptor]
    ///
    /// We use it to tell about new connections and new blocks. The worker will
    /// process those messages and notify the relevant [Peer]s
    peer_receiver: Receiver<Message>,

    /// A map of all the peers we are watching
    peers: HashMap<usize, (TcpStream, Peer)>,

    /// We use those to build [Peer]
    context: WorkerContext,

    /// A mio poller to watch for events
    ///
    /// Each worker has a local reactor, that keeps polling for events on the sockets
    /// it is watching. Connections are sent from the [Acceptor] to a random worker,
    /// that should then follow it for as long as it is alive.
    pooler: mio::Poll,

    /// A counter to assign unique IDs to each peer
    id_count: usize,
}

impl Worker {
    /// Creates a new worker
    ///
    /// This function doesn't spawn any thread, the caller is responsible for running [Worker::run]
    /// inside a thread
    fn new(id: usize, context: WorkerContext, peer_receiver: Receiver<Message>) -> Self {
        Self {
            peers: HashMap::new(),
            id,
            context,
            peer_receiver,
            pooler: mio::Poll::new().expect("can't create a mio Poller"),
            id_count: 0,
        }
    }

    fn run(mut self) {
        loop {
            if let Ok(message) = self.peer_receiver.try_recv() {
                match message {
                    Message::NewConnection(socket) => {
                        debug!("worker {}: got a new peer to watch", self.id);
                        self.handle_new_peer(socket);
                        self.id_count += 1;
                    }

                    Message::NewBlock(block_hash) => {
                        debug!(
                            "worker {}: got a new block notification: {}",
                            self.id, block_hash
                        );
                        let block_msg =
                            NetworkMessage::Inv(vec![Inventory::WitnessBlock(block_hash)]);
                        // Notify all peers about the new block
                        for (_, (_, peer)) in self.peers.iter_mut() {
                            if let Err(e) = peer.send_message(block_msg.clone()) {
                                log::error!("Failed to send new block to peer: {}", e);
                            }
                        }
                    }
                }
            }

            self.handle_peers();
        }
    }

    fn handle_new_peer(&mut self, mut stream: TcpStream) {
        debug!("worker {}: got a new peer to watch", self.id);

        let token = mio::Token(self.id_count);
        self.pooler
            .registry()
            .register(
                &mut stream,
                token,
                mio::Interest::READABLE | mio::Interest::WRITABLE,
            )
            .expect("Failed to register socket");

        let peer = Peer::new(self.context.clone());

        self.peers.insert(token.0, (stream, peer));
    }

    /// Takes ownership of the worker and runs until this thread dies
    fn handle_peers(&mut self) {
        let mut events = Events::with_capacity(1024);

        self.pooler
            .poll(&mut events, Some(Duration::from_secs(1)))
            .expect("Failed to poll events");

        for event in events.iter() {
            let token = event.token();
            let (stream, peer) = self.peers.get_mut(&token.0).unwrap();

            if event.is_readable() {
                debug!("worker {}: got read event for peer {}", self.id, token.0);
                if let Err(err) = peer.handle_request(stream) {
                    log::error!("Error handling request: {}", err);
                    if let PeerError::Io(ref e) = err {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            continue;
                        }
                    }

                    self.peers.remove(&token.0);
                    continue;
                }
            }

            if event.is_writable() {
                match peer.write_back(stream) {
                    Err(err) => {
                        log::error!("Error handling request: {}", err);
                        if let PeerError::Io(ref e) = err {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                continue;
                            }
                        }

                        self.peers.remove(&token.0);
                        continue;
                    }

                    Ok(_) => continue,
                }
            }
        }
    }
}

/// Keep watching sockets for new connections
struct Acceptor {
    /// Our server's listener
    ///
    /// Used to accept new p2p connections
    listener: TcpListener,

    /// Channels to our workers
    worker_pool: [Sender<Message>; WORKES_PER_CLUSTER],

    /// A channel to notify us about new blocks
    block_notifier: Receiver<BlockHash>,
}

impl Acceptor {
    fn run(mut self) {
        let mut poll = mio::Poll::new().expect("can't create a mio Poller");
        poll.registry()
            .register(&mut self.listener, mio::Token(0), mio::Interest::READABLE)
            .expect("Failed to register listener");

        let mut events = mio::Events::with_capacity(1024);
        loop {
            poll.poll(&mut events, Some(Duration::from_secs(1)))
                .expect("Failed to poll events");

            for event in events.iter() {
                match event.token() {
                    mio::Token(0) => {
                        debug!("acceptor: our listener got a new event");

                        let Ok((stream, address)) = self.listener.accept() else {
                            log::error!("Failed to accept connection");
                            continue;
                        };
                        let worker = rand::random::<u32>() as usize % WORKES_PER_CLUSTER;
                        info!("acceptor: saw new connection from {address}, sending to worker {worker}");
                        self.worker_pool[worker]
                            .send(Message::NewConnection(stream))
                            .expect("Failed to send new connection to worker");
                    }

                    _ => {}
                }
            }

            // Check for new blocks and notify workers
            if let Ok(block_hash) = self.block_notifier.try_recv() {
                debug!("acceptor: got new block notification: {}", block_hash);
                for worker in &self.worker_pool {
                    worker
                        .send(Message::NewBlock(block_hash.clone()))
                        .expect("Failed to send new block to worker");
                }
            }
        }
    }
}

/// Local context for each peer
///
/// This will perform all the processing and IO related to a given peer, it can will be owned by
/// our workers and used every time the reactor tell us there's something available
pub struct Peer {
    /// Data that we've read, but didn't process
    read_buffer: Vec<u8>,

    /// Data that we need to write into the socket
    write_buffer: Vec<u8>,

    /// The context
    context: WorkerContext,
}

#[derive(Debug)]
/// Errors returned by the [Peer] when processing requests
enum PeerError {
    /// Io Error
    Io(std::io::Error),

    /// Can't decode the message
    Decode(bitcoin::consensus::encode::Error),

    /// Some lock is poisoned (a thread died while holding it)
    Poison,

    /// The provided magic value is invalid
    InvalidMagic,

    /// The message we got is too big
    MessageTooLarge,
}

impl Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerError::Io(e) => write!(f, "IO error: {}", e),
            PeerError::Decode(e) => write!(f, "Decode error: {}", e),
            PeerError::Poison => write!(f, "Lock is poisoned"),
            PeerError::InvalidMagic => write!(f, "Invalid magic"),
            PeerError::MessageTooLarge => write!(f, "Message too large"),
        }
    }
}

impl From<std::io::Error> for PeerError {
    fn from(e: std::io::Error) -> Self {
        PeerError::Io(e)
    }
}

impl From<bitcoin::consensus::encode::Error> for PeerError {
    fn from(e: bitcoin::consensus::encode::Error) -> Self {
        PeerError::Decode(e)
    }
}

impl From<bitcoin::io::Error> for PeerError {
    fn from(error: bitcoin::io::Error) -> Self {
        PeerError::Decode(bitcoin::consensus::encode::Error::Io(error))
    }
}

impl<T> From<PoisonError<T>> for PeerError {
    fn from(_: PoisonError<T>) -> Self {
        PeerError::Poison
    }
}

impl Peer {
    pub fn new(context: WorkerContext) -> Self {
        Self {
            context,
            write_buffer: Vec::new(),
            read_buffer: Vec::new(),
        }
    }

    fn consume_message(&mut self) -> Result<Option<RawNetworkMessage>, PeerError> {
        let mut reader = self.read_buffer.as_slice();
        let header = P2PMessageHeader::consensus_decode(&mut reader)?;
        if header.length > 32_000_000 {
            return Err(PeerError::MessageTooLarge);
        }

        if header._magic != self.context.magic {
            return Err(PeerError::InvalidMagic);
        }

        if self.read_buffer.len() < (header.length + 24) as usize {
            return Ok(None);
        }

        let data = self.read_buffer.drain(0..(24 + header.length as usize));
        let message = RawNetworkMessage::consensus_decode(&mut data.as_slice())?;
        Ok(Some(message))
    }

    fn send_message(&mut self, message: NetworkMessage) -> Result<(), PeerError> {
        let msg = RawNetworkMessage::new(self.context.magic, message);
        self.write_buffer.extend(&serialize(&msg));

        Ok(())
    }

    fn send_raw_message(&mut self, command: &str, payload: &[u8]) -> Result<(), PeerError> {
        if command.len() > 12 || payload.len() > u32::MAX as usize {
            return Err(PeerError::MessageTooLarge);
        }
        let checksum = Self::sha256d_payload(payload);
        let mut header = [0u8; 24];
        header[..4].copy_from_slice(&self.context.magic.to_bytes());
        header[4..4 + command.len()].copy_from_slice(command.as_bytes());
        header[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        header[20..24].copy_from_slice(&checksum[..4]);
        self.write_buffer.extend_from_slice(&header);
        self.write_buffer.extend_from_slice(payload);
        Ok(())
    }

    fn read_pending(&mut self, stream: &mut TcpStream) -> Result<usize, PeerError> {
        let mut buffer = vec![0; 4_000_000];
        let read = stream.read(&mut buffer)?;

        self.read_buffer.extend(buffer.drain(0..read));
        Ok(read)
    }

    fn sha256d_payload(payload: &[u8]) -> [u8; 32] {
        let mut sha = Sha256::new();
        sha.update(payload);

        let hash = sha.finalize();
        let mut sha = sha2::Sha256::new();
        sha.update(hash);

        sha.finalize().into()
    }

    fn write_back(&mut self, stream: &mut TcpStream) -> Result<bool, PeerError> {
        debug!("peer: writing back {} bytes", self.write_buffer.len());

        let writen = stream.write(&self.write_buffer)?;
        self.write_buffer.drain(0..writen);
        Ok(self.write_buffer.is_empty())
    }

    fn handle_request(&mut self, stream: &mut TcpStream) -> Result<(), PeerError> {
        let read = self.read_pending(stream)?;
        debug!("peer: read {read} bytes");

        loop {
            if self.read_buffer.len() < 24 {
                break;
            }

            let Some(request) = self.consume_message()? else {
                break;
            };

            self.handle_request_inner(request)?;
        }

        Ok(())
    }

    fn handle_request_inner(&mut self, request: RawNetworkMessage) -> Result<(), PeerError> {
        match request.payload() {
            NetworkMessage::Ping(nonce) => {
                let pong = NetworkMessage::Pong(*nonce);
                self.send_message(pong)?;
            }

            NetworkMessage::Unknown { command, payload }
                if command.as_ref() == GET_UTREEXO_PROOF_COMMAND =>
            {
                let proof_request: GetUtreexoProof = deserialize(payload)?;
                let Some(index) = self.context.proof_index.get_index(proof_request.block_hash)
                else {
                    debug!(
                        "peer requested unavailable proof {}",
                        proof_request.block_hash
                    );
                    return Ok(());
                };
                let Some(proof) = self.context.proof_backend.get(index) else {
                    debug!(
                        "proof index for {} points to unavailable data",
                        proof_request.block_hash
                    );
                    return Ok(());
                };
                let payload =
                    encode_utreexo_proof(proof_request.block_hash, &proof_request, &proof)?;
                self.send_raw_message(UTREEXO_PROOF_COMMAND, &payload)?;
            }

            NetworkMessage::GetHeaders(locator) => {
                let mut headers = vec![];
                let Some(block) = locator.locator_hashes.first() else {
                    return Ok(());
                };

                let height = self
                    .context
                    .chainview
                    .get_height(*block)
                    .unwrap()
                    .unwrap_or(0);

                let height = height + 1;
                for h in height..(height + 2_000) {
                    let Ok(Some(block_hash)) = self.context.chainview.get_block_hash(h) else {
                        break;
                    };

                    let Ok(Some(header_info)) = self.context.chainview.get_block(block_hash) else {
                        break;
                    };

                    let header = deserialize(&header_info)?;
                    headers.push(header);
                }

                let headers = NetworkMessage::Headers(headers);
                self.send_message(headers)?;
            }

            NetworkMessage::Version(version) => {
                info!(
                    "Handshake success version={} blocks={} services={} address={:?} address_our={:?}",
                    version.user_agent,
                    version.start_height,
                    version.services,
                    version.receiver.address,
                    version.sender.address
                );

                let version = NetworkMessage::Version(VersionMessage {
                    version: 70001,
                    services: advertised_services(),
                    timestamp: version.timestamp + 1,
                    receiver: version.sender.clone(),
                    sender: version.receiver.clone(),
                    nonce: version.nonce + 100,
                    user_agent: "/bridge:0.1.0/".to_string(),
                    start_height: self.context.proof_index.load_height() as i32,
                    relay: false,
                });

                let our_version = version;
                self.send_message(our_version)?;

                let verack = NetworkMessage::Verack;
                self.send_message(verack)?;
            }

            NetworkMessage::GetCFilters(req) => {
                if req.filter_type == FILTER_TYPE_UTREEXO {
                    let Ok(Some(acc)) = self.context.chainview.get_acc(req.stop_hash) else {
                        // if this block is not in the chainview, ignore the request
                        return Ok(());
                    };

                    let cfilters = NetworkMessage::CFilter(CFilter {
                        filter_type: FILTER_TYPE_UTREEXO,
                        block_hash: req.stop_hash,
                        filter: acc,
                    });

                    self.send_message(cfilters)?;
                }

                // ignore unknown filter types
            }

            _ => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::Hash;

    use super::*;
    use crate::udata::BatchProof;
    use crate::udata::CompactLeafData;
    use crate::udata::ScriptPubkeyType;

    fn sample_proof() -> CompactBlockProof {
        CompactBlockProof {
            proof: BatchProof {
                targets: vec![VarInt(3), VarInt(9)],
                hashes: vec![
                    BlockHash::from_byte_array([1; 32]),
                    BlockHash::from_byte_array([2; 32]),
                ],
            },
            leaves: vec![
                CompactLeafData {
                    header_code: 10,
                    amount: 20,
                    spk_ty: ScriptPubkeyType::PubKeyHash,
                },
                CompactLeafData {
                    header_code: 11,
                    amount: 21,
                    spk_ty: ScriptPubkeyType::WitnessV0PubKeyHash,
                },
            ],
        }
    }

    #[test]
    fn decodes_floresta_getuproof_request() {
        let block_hash = BlockHash::from_byte_array([3; 32]);
        let mut payload = Vec::new();
        block_hash.consensus_encode(&mut payload).unwrap();
        7u8.consensus_encode(&mut payload).unwrap();
        vec![0b10u8].consensus_encode(&mut payload).unwrap();
        vec![0b01u8].consensus_encode(&mut payload).unwrap();

        let request: GetUtreexoProof = deserialize(&payload).unwrap();
        assert_eq!(
            request,
            GetUtreexoProof {
                block_hash,
                request_mask: 7,
                proof_hashes_bitmap: vec![0b10],
                leaf_data_bitmap: vec![0b01],
            }
        );
    }

    #[test]
    fn encodes_requested_proof_fields_in_bip183_order() {
        let block_hash = BlockHash::from_byte_array([3; 32]);
        let request = GetUtreexoProof {
            block_hash,
            request_mask: REQUEST_TARGETS | REQUEST_PROOF_HASHES | REQUEST_LEAF_DATA,
            proof_hashes_bitmap: vec![0b10],
            leaf_data_bitmap: vec![0b01],
        };
        let payload = encode_utreexo_proof(block_hash, &request, &sample_proof()).unwrap();
        let mut reader = payload.as_slice();

        assert_eq!(
            BlockHash::consensus_decode(&mut reader).unwrap(),
            block_hash
        );
        assert_eq!(VarInt::consensus_decode(&mut reader).unwrap().0, 1);
        assert_eq!(
            BlockHash::consensus_decode(&mut reader).unwrap(),
            BlockHash::from_byte_array([2; 32])
        );
        assert_eq!(VarInt::consensus_decode(&mut reader).unwrap().0, 2);
        assert_eq!(VarInt::consensus_decode(&mut reader).unwrap().0, 3);
        assert_eq!(VarInt::consensus_decode(&mut reader).unwrap().0, 9);
        assert_eq!(VarInt::consensus_decode(&mut reader).unwrap().0, 1);
        assert_eq!(u32::consensus_decode(&mut reader).unwrap(), 10);
        assert_eq!(u64::consensus_decode(&mut reader).unwrap(), 20);
        assert_eq!(
            ScriptPubkeyType::consensus_decode(&mut reader).unwrap(),
            ScriptPubkeyType::PubKeyHash
        );
        assert!(reader.is_empty());
    }

    #[test]
    fn advertises_only_witness_and_utreexo_services() {
        let services = advertised_services();
        assert!(services.has(ServiceFlags::WITNESS));
        assert!(services.has(ServiceFlags::from(NODE_UTREEXO)));
        assert!(!services.has(ServiceFlags::NETWORK));
        assert!(!services.has(ServiceFlags::NETWORK_LIMITED));
    }
}
