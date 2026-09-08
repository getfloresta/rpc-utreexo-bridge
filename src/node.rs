// SPDX-License-Identifier: MIT

//! BIP 324 encrypted, P2PV2-only proof server.

use std::collections::HashMap;
use std::fmt::Display;
use std::io::BufReader;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::TrySendError;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;

use bip324::io::Payload;
use bip324::io::Protocol;
use bip324::io::ProtocolError;
use bip324::PacketType;
use bip324::Role;
use bitcoin::block::Header;
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
use log::info;
use log::warn;

use crate::block_index::BlockIndex;
use crate::block_index::BlocksIndex;
use crate::blockfile::ProofFile;
use crate::chaininterface::Blockchain;
use crate::chainview::ChainView;
use crate::header_index::HeaderIndex;
use crate::udata::CompactBlockProof;

/// Deprecated Utreexo compact-filter type retained for compatibility.
pub const FILTER_TYPE_UTREEXO: u8 = 1;

const GET_UTREEXO_PROOF_COMMAND: &str = "getuproof";
const UTREEXO_PROOF_COMMAND: &str = "uproof";
const NODE_UTREEXO: u64 = 1 << 12;
const REQUEST_TARGETS: u8 = 1 << 0;
const MAX_FOREST_ROWS: u8 = 63;
const REQUEST_PROOF_HASHES: u8 = 1 << 1;
const REQUEST_LEAF_DATA: u8 = 1 << 2;
const P2PV2_UTREEXO_PROOF: u8 = 29;
const P2PV2_GET_UTREEXO_PROOF: u8 = 30;
const OUTBOUND_QUEUE_SIZE: usize = 64;
const MAX_HEADERS: u64 = 2_000;

type PeerWriters = Arc<Mutex<HashMap<u64, SyncSender<Vec<u8>>>>>;

#[derive(Clone)]
pub enum ProofBackend {
    CompactProofs(Arc<ProofFile>),
}

impl ProofBackend {
    fn get(&self, index: BlockIndex) -> Option<CompactBlockProof> {
        match self {
            Self::CompactProofs(proofs) => proofs.get(&index),
        }
    }
}

#[derive(Clone)]
/// Data required by a peer connection to answer requests.
pub struct WorkerContext {
    pub proof_backend: ProofBackend,
    pub proof_index: Arc<BlocksIndex>,
    pub chainview: Arc<ChainView>,
    pub header_index: Option<Arc<HeaderIndex>>,
    pub header_source: Option<Arc<dyn Blockchain>>,
    pub proof_forest_rows: Option<u8>,
    pub magic: Magic,
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

fn translate_position_to_wire(position: u64, forest_rows: u8) -> u64 {
    let mut marker = 1u64 << forest_rows;
    let mut row = 0u8;
    while position & marker != 0 {
        marker >>= 1;
        row += 1;
    }
    if row == 0 {
        return position;
    }
    let row_start = |rows: u8| {
        u64::try_from((2u128 << rows) - (2u128 << (rows - row)))
            .expect("63-row forest positions fit in u64")
    };
    position - row_start(forest_rows) + row_start(MAX_FOREST_ROWS)
}

fn encode_utreexo_proof(
    block_hash: BlockHash,
    request: &GetUtreexoProof,
    proof: &CompactBlockProof,
    proof_forest_rows: Option<u8>,
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
            let target = proof_forest_rows
                .map(|forest_rows| translate_position_to_wire(target.0, forest_rows))
                .unwrap_or(target.0);
            VarInt(target).consensus_encode(&mut payload)?;
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
    ServiceFlags::WITNESS | ServiceFlags::P2P_V2 | ServiceFlags::from(NODE_UTREEXO)
}

/// Starts the inbound P2PV2 proof server.
pub struct Node;

impl Node {
    pub fn run(
        address: SocketAddr,
        worker_context: WorkerContext,
        block_notifier: Receiver<BlockHash>,
    ) {
        let listener = TcpListener::bind(address).expect("Failed to bind to address");
        let peers = PeerWriters::default();
        let notification_peers = peers.clone();
        std::thread::Builder::new()
            .name("bridge-p2pv2-notifications".to_string())
            .spawn(move || broadcast_blocks(block_notifier, notification_peers))
            .expect("Failed to spawn block notification thread");

        std::thread::Builder::new()
            .name("bridge-p2pv2-acceptor".to_string())
            .spawn(move || accept_connections(listener, worker_context, peers))
            .expect("Failed to spawn P2PV2 acceptor");
    }
}

fn accept_connections(listener: TcpListener, context: WorkerContext, peers: PeerWriters) {
    let next_peer = AtomicU64::new(0);
    for accepted in listener.incoming() {
        let Ok(stream) = accepted else {
            warn!("Failed to accept P2PV2 connection");
            continue;
        };
        let address = stream.peer_addr().ok();
        let peer_id = next_peer.fetch_add(1, Ordering::Relaxed);
        let context = context.clone();
        let peers = peers.clone();
        info!("Accepted inbound P2PV2 connection peer={peer_id} address={address:?}");
        if let Err(error) = std::thread::Builder::new()
            .name(format!("bridge-p2pv2-peer-{peer_id}"))
            .spawn(move || {
                if let Err(error) = run_connection(peer_id, stream, context, peers) {
                    debug!("P2PV2 peer {peer_id} disconnected: {error}");
                }
            })
        {
            warn!("Failed to spawn P2PV2 peer thread: {error}");
        }
    }
}

fn broadcast_blocks(block_notifier: Receiver<BlockHash>, peers: PeerWriters) {
    while let Ok(block_hash) = block_notifier.recv() {
        let message = NetworkMessage::Inv(vec![Inventory::WitnessBlock(block_hash)]);
        let Ok(encoded) = encode_v2_message(&message) else {
            continue;
        };
        let Ok(mut peers) = peers.lock() else {
            return;
        };
        peers.retain(|_, sender| match sender.try_send(encoded.clone()) {
            Ok(()) | Err(TrySendError::Full(_)) => true,
            Err(TrySendError::Disconnected(_)) => false,
        });
    }
}

fn run_connection(
    peer_id: u64,
    stream: TcpStream,
    context: WorkerContext,
    peers: PeerWriters,
) -> Result<(), PeerError> {
    stream.set_nodelay(true)?;
    let reader = BufReader::new(stream.try_clone()?);
    let protocol = Protocol::new(
        context.magic.to_bytes(),
        Role::Responder,
        None,
        None,
        reader,
        stream,
    )?;
    info!("Completed inbound P2PV2 handshake peer={peer_id}");
    let (mut protocol_reader, mut protocol_writer) = protocol.into_split();
    let (outbound_tx, outbound_rx) = std::sync::mpsc::sync_channel(OUTBOUND_QUEUE_SIZE);
    peers.lock()?.insert(peer_id, outbound_tx.clone());

    let reader_context = context.clone();
    let reader_peers = peers.clone();
    let reader_handle = std::thread::Builder::new()
        .name(format!("bridge-p2pv2-reader-{peer_id}"))
        .spawn(move || {
            let result = (|| -> Result<(), PeerError> {
                loop {
                    let payload = protocol_reader.read()?;
                    if payload.packet_type() == PacketType::Decoy {
                        continue;
                    }
                    let request = decode_v2_message(payload.contents())?;
                    for response in handle_message(&reader_context, request)? {
                        outbound_tx
                            .send(encode_v2_message(&response)?)
                            .map_err(|_| PeerError::ChannelClosed)?;
                    }
                }
            })();
            if let Ok(mut peers) = reader_peers.lock() {
                peers.remove(&peer_id);
            }
            result
        })?;

    let mut writer_error = None;
    while let Ok(message) = outbound_rx.recv() {
        if let Err(error) = protocol_writer.write(&Payload::genuine(message)) {
            writer_error = Some(PeerError::Protocol(error));
            break;
        }
    }
    if let Ok(mut peers) = peers.lock() {
        peers.remove(&peer_id);
    }
    let (_, stream) = protocol_writer.into_inner();
    let _ = stream.shutdown(Shutdown::Both);
    let reader_result = reader_handle.join().map_err(|_| PeerError::ThreadPanic)?;
    if let Some(error) = writer_error {
        return Err(error);
    }
    reader_result
}

fn handle_message(
    context: &WorkerContext,
    request: NetworkMessage,
) -> Result<Vec<NetworkMessage>, PeerError> {
    match request {
        NetworkMessage::Ping(nonce) => Ok(vec![NetworkMessage::Pong(nonce)]),
        NetworkMessage::Unknown { command, payload }
            if command.as_ref() == GET_UTREEXO_PROOF_COMMAND =>
        {
            let proof_request: GetUtreexoProof = deserialize(&payload)?;
            let Some(index) = context.proof_index.get_index(proof_request.block_hash)? else {
                debug!(
                    "Peer requested unavailable proof {}",
                    proof_request.block_hash
                );
                return Ok(Vec::new());
            };
            let proof_forest_rows = index.proof_forest_rows.or(context.proof_forest_rows);
            let Some(proof) = context.proof_backend.get(index) else {
                debug!(
                    "Proof index for {} points to unavailable data",
                    proof_request.block_hash
                );
                return Ok(Vec::new());
            };
            let payload = encode_utreexo_proof(
                proof_request.block_hash,
                &proof_request,
                &proof,
                proof_forest_rows,
            )?;
            Ok(vec![NetworkMessage::Unknown {
                command: CommandString::try_from_static(UTREEXO_PROOF_COMMAND)
                    .expect("valid uproof command"),
                payload,
            }])
        }
        NetworkMessage::GetHeaders(locator) => {
            Ok(vec![NetworkMessage::Headers(headers_for_request(
                &context.chainview,
                context.header_index.as_deref(),
                context.header_source.as_deref(),
                &locator,
            )?)])
        }
        NetworkMessage::Version(version) => {
            info!(
                "P2PV2 handshake version={} blocks={} services={} address={:?}",
                version.user_agent,
                version.start_height,
                version.services,
                version.receiver.address
            );
            Ok(vec![
                NetworkMessage::Version(VersionMessage {
                    version: 70016,
                    services: advertised_services(),
                    timestamp: version.timestamp + 1,
                    receiver: version.sender.clone(),
                    sender: version.receiver.clone(),
                    nonce: version.nonce + 100,
                    user_agent: "/bridge:0.1.3/".to_string(),
                    start_height: i32::try_from(context.proof_index.load_height()?)
                        .unwrap_or(i32::MAX),
                    relay: false,
                }),
                NetworkMessage::Verack,
            ])
        }
        NetworkMessage::GetCFilters(request) if request.filter_type == FILTER_TYPE_UTREEXO => {
            let Some(acc) = context.chainview.get_acc(request.stop_hash)? else {
                return Ok(Vec::new());
            };
            Ok(vec![NetworkMessage::CFilter(CFilter {
                filter_type: FILTER_TYPE_UTREEXO,
                block_hash: request.stop_hash,
                filter: acc,
            })])
        }

        _ => Ok(Vec::new()),
    }
}
fn headers_for_request(
    chainview: &ChainView,
    header_index: Option<&HeaderIndex>,
    header_source: Option<&dyn Blockchain>,
    request: &GetHeadersMessage,
) -> Result<Vec<Header>, PeerError> {
    let common_height = active_locator_height(
        chainview,
        header_index,
        header_source,
        &request.locator_hashes,
    )?;
    let start = common_height.saturating_add(1);
    let end = match header_source {
        Some(source) => (source.get_block_count()? as u32)
            .saturating_add(1)
            .min(start.saturating_add(MAX_HEADERS as u32)),
        None => start.saturating_add(MAX_HEADERS as u32),
    };
    let mut headers = Vec::with_capacity((end - start) as usize);
    for height in start..end {
        let Some((block_hash, header)) =
            header_at_height(chainview, header_index, header_source, height)?
        else {
            break;
        };
        headers.push(header);
        if request.stop_hash != BlockHash::all_zeros() && request.stop_hash == block_hash {
            break;
        }
    }
    Ok(headers)
}

fn active_locator_height(
    chainview: &ChainView,
    header_index: Option<&HeaderIndex>,
    header_source: Option<&dyn Blockchain>,
    locator_hashes: &[BlockHash],
) -> Result<u32, PeerError> {
    for block_hash in locator_hashes {
        if let Some(index) = header_index {
            if let Some(height) = index.get_height(*block_hash)? {
                return Ok(height);
            }
        }
        if let Some(height) = chainview.get_height(*block_hash)? {
            return Ok(height);
        }
        let Some(source) = header_source else {
            continue;
        };
        let Ok(height) = source.get_block_height(*block_hash) else {
            continue;
        };
        let Ok(active_hash) = source.get_block_hash(height as u64) else {
            continue;
        };
        if active_hash == *block_hash {
            let header = source.get_block_header(*block_hash)?;
            if let Some(index) = header_index {
                index.put(height, &header)?;
            }
            chainview.save_height(*block_hash, height)?;
            chainview.save_block_hash(height, *block_hash)?;
            return Ok(height);
        }
    }
    Ok(0)
}

fn header_at_height(
    chainview: &ChainView,
    header_index: Option<&HeaderIndex>,
    header_source: Option<&dyn Blockchain>,
    height: u32,
) -> Result<Option<(BlockHash, Header)>, PeerError> {
    if let Some(index) = header_index {
        if let Some(header) = index.get_by_height(height)? {
            return Ok(Some((header.block_hash(), header)));
        }
    }
    if let Some(block_hash) = chainview.get_block_hash(height)? {
        if let Some(header) = chainview.get_block(block_hash)? {
            return Ok(Some((block_hash, deserialize(&header)?)));
        }
    }
    let Some(source) = header_source else {
        return Ok(None);
    };
    let block_hash = source.get_block_hash(height as u64)?;
    let header = source.get_block_header(block_hash)?;
    if let Some(index) = header_index {
        index.put(height, &header)?;
    }
    chainview.save_block_hash(height, block_hash)?;
    chainview.save_height(block_hash, height)?;
    chainview.save_header(block_hash, bitcoin::consensus::serialize(&header))?;
    Ok(Some((block_hash, header)))
}

fn encode_v2_message(message: &NetworkMessage) -> Result<Vec<u8>, PeerError> {
    let mut buffer = Vec::new();
    if let NetworkMessage::Unknown { command, payload } = message {
        let short_id = match command.as_ref() {
            UTREEXO_PROOF_COMMAND => Some(P2PV2_UTREEXO_PROOF),
            GET_UTREEXO_PROOF_COMMAND => Some(P2PV2_GET_UTREEXO_PROOF),
            _ => None,
        };
        if let Some(short_id) = short_id {
            buffer.push(short_id);
            buffer.extend_from_slice(payload);
            return Ok(buffer);
        }
    }

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

fn decode_v2_message(buffer: &[u8]) -> Result<NetworkMessage, PeerError> {
    let Some((&short_id, payload)) = buffer.split_first() else {
        return Err(PeerError::MissingShortId);
    };
    if short_id == P2PV2_UTREEXO_PROOF || short_id == P2PV2_GET_UTREEXO_PROOF {
        let command = if short_id == P2PV2_UTREEXO_PROOF {
            UTREEXO_PROOF_COMMAND
        } else {
            GET_UTREEXO_PROOF_COMMAND
        };
        return Ok(NetworkMessage::Unknown {
            command: CommandString::try_from_static(command).expect("valid Utreexo command"),
            payload: payload.to_vec(),
        });
    }

    let mut payload = payload;
    match short_id {
        0 => decode_long_command(payload),
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
        13 => decode_headers(payload),
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

#[derive(Debug)]
enum PeerError {
    Io(std::io::Error),
    Protocol(ProtocolError),
    Decode(bitcoin::consensus::encode::Error),
    Storage(kv::Error),
    Rpc(anyhow::Error),
    Poison,
    ChannelClosed,
    ThreadPanic,
    MissingShortId,
    MissingCommand,
    UnknownShortId(u8),
    TooManyHeaders(u64),
    HeadersContainTransactions,
}

impl Display for PeerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Protocol(error) => write!(formatter, "BIP 324 error: {error}"),
            Self::Decode(error) => write!(formatter, "message decode error: {error}"),
            Self::Rpc(error) => write!(formatter, "header RPC error: {error:#}"),
            Self::Storage(error) => write!(formatter, "peer storage error: {error}"),
            Self::Poison => formatter.write_str("shared peer state is poisoned"),
            Self::ChannelClosed => formatter.write_str("peer writer stopped"),
            Self::ThreadPanic => formatter.write_str("peer reader panicked"),
            Self::MissingShortId => formatter.write_str("P2PV2 message has no short ID"),
            Self::MissingCommand => formatter.write_str("P2PV2 long message has no command"),
            Self::UnknownShortId(id) => write!(formatter, "unknown P2PV2 short ID {id}"),
            Self::TooManyHeaders(count) => {
                write!(formatter, "headers message contains {count} headers")
            }
            Self::HeadersContainTransactions => {
                formatter.write_str("headers message contains a nonzero transaction count")
            }
        }
    }
}

impl From<std::io::Error> for PeerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProtocolError> for PeerError {
    fn from(error: ProtocolError) -> Self {
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

impl From<anyhow::Error> for PeerError {
    fn from(error: anyhow::Error) -> Self {
        Self::Rpc(error)
    }
}

impl From<kv::Error> for PeerError {
    fn from(error: kv::Error) -> Self {
        Self::Storage(error)
    }
}

impl<T> From<PoisonError<T>> for PeerError {
    fn from(_: PoisonError<T>) -> Self {
        Self::Poison
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use bitcoin::block;
    use bitcoin::consensus::deserialize;
    use bitcoin::constants::genesis_block;
    use bitcoin::hashes::Hash;
    use bitcoin::network::Network;
    use bitcoin::Txid;

    use super::*;
    use crate::udata::BatchProof;
    use crate::udata::CompactLeafData;
    use crate::udata::ScriptPubkeyType;

    struct HeaderSource {
        headers: Vec<Header>,
        side_hash: BlockHash,
        calls: AtomicUsize,
    }

    impl Blockchain for HeaderSource {
        fn get_block(&self, _block_hash: BlockHash) -> anyhow::Result<bitcoin::Block> {
            anyhow::bail!("unexpected get_block")
        }

        fn get_block_hash(&self, height: u64) -> anyhow::Result<BlockHash> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.headers
                .get(height as usize)
                .map(Header::block_hash)
                .ok_or_else(|| anyhow::anyhow!("unknown height {height}"))
        }

        fn get_block_height(&self, block_hash: BlockHash) -> anyhow::Result<u32> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if block_hash == self.side_hash {
                return Ok(2);
            }
            self.headers
                .iter()
                .position(|header| header.block_hash() == block_hash)
                .map(|height| height as u32)
                .ok_or_else(|| anyhow::anyhow!("unknown block {block_hash}"))
        }

        fn get_block_header(&self, block_hash: BlockHash) -> anyhow::Result<Header> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.headers
                .iter()
                .find(|header| header.block_hash() == block_hash)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("unknown block {block_hash}"))
        }

        fn get_block_count(&self) -> anyhow::Result<u64> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.headers.len() as u64 - 1)
        }

        fn get_raw_transaction_info(
            &self,
            _txid: &Txid,
        ) -> anyhow::Result<crate::chaininterface::TransactionInfo> {
            anyhow::bail!("unexpected get_raw_transaction_info")
        }

        fn get_mtp(&self, _block_hash: BlockHash) -> anyhow::Result<u32> {
            anyhow::bail!("unexpected get_mtp")
        }
    }

    fn header_chain(length: usize) -> Vec<Header> {
        let mut headers = vec![genesis_block(Network::Signet).header];
        while headers.len() < length {
            let previous = *headers.last().unwrap();
            headers.push(Header {
                version: block::Version::ONE,
                prev_blockhash: previous.block_hash(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: previous.time + 1,
                bits: previous.bits,
                nonce: headers.len() as u32,
            });
        }
        headers
    }

    fn test_chainview(name: &str) -> (ChainView, std::path::PathBuf) {
        let path =
            std::env::temp_dir().join(format!("bridge-header-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let store = kv::Store::new(kv::Config {
            path: path.clone(),
            temporary: false,
            use_compression: false,
            flush_every_ms: None,
            cache_capacity: None,
            segment_size: None,
        })
        .unwrap();
        (ChainView::new(store), path)
    }

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
    fn bip324_protocol_encrypts_a_p2pv2_message_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let magic = Magic::SIGNET.to_bytes();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let reader = BufReader::new(stream.try_clone().unwrap());
            let mut protocol =
                Protocol::new(magic, Role::Responder, None, None, reader, stream).unwrap();
            let request = protocol.read().unwrap();
            assert_eq!(
                decode_v2_message(request.contents()).unwrap(),
                NetworkMessage::Ping(42)
            );
            protocol
                .write(&Payload::genuine(
                    encode_v2_message(&NetworkMessage::Pong(42)).unwrap(),
                ))
                .unwrap();
        });

        let stream = TcpStream::connect(address).unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        let mut protocol =
            Protocol::new(magic, Role::Initiator, None, None, reader, stream).unwrap();
        protocol
            .write(&Payload::genuine(
                encode_v2_message(&NetworkMessage::Ping(42)).unwrap(),
            ))
            .unwrap();
        let response = protocol.read().unwrap();
        assert_eq!(
            decode_v2_message(response.contents()).unwrap(),
            NetworkMessage::Pong(42)
        );
        server.join().unwrap();
    }

    #[test]
    fn p2pv2_short_message_roundtrip() {
        for message in [NetworkMessage::Ping(42), NetworkMessage::Pong(43)] {
            let encoded = encode_v2_message(&message).unwrap();
            assert_eq!(decode_v2_message(&encoded).unwrap(), message);
        }
    }

    #[test]
    fn p2pv2_utreexo_short_ids_match_floresta() {
        let getuproof = NetworkMessage::Unknown {
            command: CommandString::try_from_static(GET_UTREEXO_PROOF_COMMAND).unwrap(),
            payload: vec![1, 2, 3],
        };
        let uproof = NetworkMessage::Unknown {
            command: CommandString::try_from_static(UTREEXO_PROOF_COMMAND).unwrap(),
            payload: vec![4, 5, 6],
        };
        assert_eq!(encode_v2_message(&getuproof).unwrap()[0], 30);
        assert_eq!(encode_v2_message(&uproof).unwrap()[0], 29);
        assert_eq!(
            decode_v2_message(&encode_v2_message(&getuproof).unwrap()).unwrap(),
            getuproof
        );
        assert_eq!(
            decode_v2_message(&encode_v2_message(&uproof).unwrap()).unwrap(),
            uproof
        );
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
        let payload = encode_utreexo_proof(block_hash, &request, &sample_proof(), Some(3)).unwrap();
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
        assert_eq!(
            VarInt::consensus_decode(&mut reader).unwrap().0,
            (1u64 << 63) + 1
        );
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
    fn serves_active_locator_headers_through_stop_hash_and_caches_them() {
        let headers = header_chain(8);
        let side_hash = BlockHash::from_byte_array([9; 32]);
        let source = HeaderSource {
            headers: headers.clone(),
            side_hash,
            calls: AtomicUsize::new(0),
        };
        let (chainview, path) = test_chainview("active-locator");
        chainview
            .save_block_hash(0, headers[0].block_hash())
            .unwrap();
        chainview.save_height(headers[0].block_hash(), 0).unwrap();
        chainview
            .save_header(
                headers[0].block_hash(),
                bitcoin::consensus::serialize(&headers[0]),
            )
            .unwrap();
        let request = GetHeadersMessage::new(
            vec![side_hash, headers[2].block_hash()],
            headers[5].block_hash(),
        );

        let served = headers_for_request(&chainview, None, Some(&source), &request).unwrap();
        assert_eq!(served, headers[3..=5]);
        assert_eq!(
            chainview.get_block_hash(5).unwrap(),
            Some(headers[5].block_hash())
        );

        let cached = headers_for_request(&chainview, None, None, &request).unwrap();
        assert_eq!(cached, served);
        drop(chainview);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn serves_headers_from_positioned_header_index_without_rpc() {
        let headers = header_chain(8);
        let root =
            std::env::temp_dir().join(format!("bridge-node-header-index-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let header_file = root.join("headers.dat");
        let hash_index = root.join("hashes");
        let index = HeaderIndex::create(&header_file, &hash_index, 7, 1).unwrap();
        for (height, header) in headers.iter().enumerate() {
            index.put(height as u32, header).unwrap();
        }
        index.sync().unwrap();
        let (chainview, chainview_path) = test_chainview("flat-header-index");
        let request =
            GetHeadersMessage::new(vec![headers[2].block_hash()], headers[5].block_hash());

        let served = headers_for_request(&chainview, Some(&index), None, &request).unwrap();
        assert_eq!(served, headers[3..=5]);

        drop(index);
        drop(chainview);
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(chainview_path).unwrap();
    }

    #[test]
    fn advertises_only_witness_utreexo_and_p2pv2_services() {
        let services = advertised_services();
        assert!(services.has(ServiceFlags::WITNESS));
        assert!(services.has(ServiceFlags::P2P_V2));
        assert!(services.has(ServiceFlags::from(NODE_UTREEXO)));
        assert!(!services.has(ServiceFlags::NETWORK));
        assert!(!services.has(ServiceFlags::NETWORK_LIMITED));
    }
}
