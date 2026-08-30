// SPDX-License-Identifier: MIT

use bitcoin::consensus;
use bitcoin::consensus::encode::Error;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use bitcoin::VarInt;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LeafContext {
    #[allow(dead_code)]
    pub block_hash: BlockHash,
    pub txid: Txid,
    pub vout: u32,
    pub value: u64,
    pub pk_script: ScriptBuf,
    pub block_height: u32,
    pub median_time_past: u32,
    pub is_coinbase: bool,
}

/// Commitment of the leaf data, but in a compact way
///
/// The serialized format is:
/// [<header_code><amount><spk_type>]
///
/// The serialized header code format is:
///   bit 0 - containing transaction is a coinbase
///   bits 1-x - height of the block that contains the spent txout
///
/// It's calculated with:
///   header_code = <<= 1
///   if IsCoinBase {
///       header_code |= 1 // only set the bit 0 if it's a coinbase.
///   }
/// ScriptPubkeyType is the output's scriptPubkey, but serialized in a more efficient way
/// to save bandwidth. If the type is recoverable from the scriptSig, don't download the
/// scriptPubkey.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct CompactLeafData {
    /// Header code tells the height of creating for this UTXO and whether it's a coinbase
    pub header_code: u32,
    /// The amount locked in this UTXO
    pub amount: u64,
    /// The type of the locking script for this UTXO
    pub spk_ty: ScriptPubkeyType,
}

/// A recoverable scriptPubkey type, this avoids copying over data that are already
/// present or can be computed from the transaction itself.
/// An example is a p2pkh, the public key is serialized in the scriptSig, so we can just
/// grab it and hash to obtain the actual scriptPubkey. Since this data is committed in
/// the Utreexo leaf hash, it is still authenticated
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum ScriptPubkeyType {
    /// An non-specified type, in this case the script is just copied over
    Other(Box<[u8]>),
    /// p2pkh
    PubKeyHash,
    /// p2wsh
    WitnessV0PubKeyHash,
    /// p2sh
    ScriptHash,
    /// p2wsh
    WitnessV0ScriptHash,
}

impl Decodable for ScriptPubkeyType {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<ScriptPubkeyType, bitcoin::consensus::encode::Error> {
        let ty = u8::consensus_decode(reader)?;
        match ty {
            0x00 => Ok(ScriptPubkeyType::Other(Box::consensus_decode(reader)?)),
            0x01 => Ok(ScriptPubkeyType::PubKeyHash),
            0x02 => Ok(ScriptPubkeyType::WitnessV0PubKeyHash),
            0x03 => Ok(ScriptPubkeyType::ScriptHash),
            0x04 => Ok(ScriptPubkeyType::WitnessV0ScriptHash),
            _ => Err(bitcoin::consensus::encode::Error::ParseFailed(
                "Invalid script type",
            )),
        }
    }
}

impl Encodable for ScriptPubkeyType {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 1;

        match self {
            ScriptPubkeyType::Other(script) => {
                00_u8.consensus_encode(writer)?;
                len += script.consensus_encode(writer)?;
            }
            ScriptPubkeyType::PubKeyHash => {
                0x01_u8.consensus_encode(writer)?;
            }
            ScriptPubkeyType::WitnessV0PubKeyHash => {
                0x02_u8.consensus_encode(writer)?;
            }
            ScriptPubkeyType::ScriptHash => {
                0x03_u8.consensus_encode(writer)?;
            }
            ScriptPubkeyType::WitnessV0ScriptHash => {
                0x04_u8.consensus_encode(writer)?;
            }
        }
        Ok(len)
    }
}

/// BatchProof serialization defines how the utreexo accumulator proof will be
/// serialized both for i/o.
///
/// Note that this serialization format differs from the one from
/// github.com/mit-dci/utreexo/accumulator as this serialization method uses
/// varints and the one in that package does not.  They are not compatible and
/// should not be used together.  The serialization method here is more compact
/// and thus is better for wire and disk storage.
///
/// The serialized format is:
/// [<target count><targets><proof count><proofs>]
///
/// All together, the serialization looks like so:
/// Field          Type       Size
/// target count   varint     1-8 bytes
/// targets        []uint64   variable
/// hash count     varint     1-8 bytes
/// hashes         []32 byte  variable
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct BatchProof {
    /// All targets that'll be deleted
    pub targets: Vec<VarInt>,
    /// The inner hashes of a proof
    pub hashes: Vec<BlockHash>,
}

/// UData contains data needed to prove the existence and validity of all inputs
/// for a Bitcoin block.  With this data, a full node may only keep the utreexo
/// roots and still be able to fully validate a block.
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct UData {
    /// All the indexes of new utxos to remember.
    pub remember_idx: Vec<u64>,
    /// AccProof is the utreexo accumulator proof for all the inputs.
    pub proof: BatchProof,
    /// LeafData are the tx validation data for every input.
    pub leaves: Vec<CompactLeafData>,
}

/// A block plus some udata
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct UtreexoBlock {
    /// A actual block
    pub block: Block,
    /// The utreexo specific data
    pub udata: Option<UData>,
}

impl Decodable for UtreexoBlock {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, consensus::encode::Error> {
        let block = Block::consensus_decode(reader)?;

        if let Err(Error::Io(_remember)) = VarInt::consensus_decode(reader) {
            return Ok(block.into());
        };

        let n_positions = VarInt::consensus_decode(reader)?;
        let mut targets = vec![];
        for _ in 0..n_positions.0 {
            let pos = VarInt::consensus_decode(reader)?;
            targets.push(pos);
        }

        let n_hashes = VarInt::consensus_decode(reader)?;
        let mut hashes = vec![];
        for _ in 0..n_hashes.0 {
            let hash = BlockHash::consensus_decode(reader)?;
            hashes.push(hash);
        }

        let n_leaves = VarInt::consensus_decode(reader)?;
        let mut leaves = vec![];
        for _ in 0..n_leaves.0 {
            let header_code = u32::consensus_decode(reader)?;
            let amount = u64::consensus_decode(reader)?;
            let spk_ty = ScriptPubkeyType::consensus_decode(reader)?;

            leaves.push(CompactLeafData {
                header_code,
                amount,
                spk_ty,
            });
        }

        Ok(Self {
            block,
            udata: Some(UData {
                remember_idx: vec![],
                proof: BatchProof { targets, hashes },
                leaves,
            }),
        })
    }
}

impl Encodable for UtreexoBlock {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = self.block.consensus_encode(writer)?;

        if let Some(udata) = &self.udata {
            len += VarInt(udata.remember_idx.len() as u64).consensus_encode(writer)?;
            len += VarInt(udata.proof.targets.len() as u64).consensus_encode(writer)?;
            for target in &udata.proof.targets {
                len += target.consensus_encode(writer)?;
            }

            len += VarInt(udata.proof.hashes.len() as u64).consensus_encode(writer)?;
            for hash in &udata.proof.hashes {
                len += hash.consensus_encode(writer)?;
            }

            len += VarInt(udata.leaves.len() as u64).consensus_encode(writer)?;
            for leaf in &udata.leaves {
                len += leaf.header_code.consensus_encode(writer)?;
                len += leaf.amount.consensus_encode(writer)?;
                len += leaf.spk_ty.consensus_encode(writer)?;
            }
        }

        Ok(len)
    }
}

impl From<UtreexoBlock> for Block {
    fn from(block: UtreexoBlock) -> Self {
        block.block
    }
}

impl From<Block> for UtreexoBlock {
    fn from(block: Block) -> Self {
        UtreexoBlock { block, udata: None }
    }
}

#[cfg(not(feature = "shinigami"))]
pub mod bitcoin_leaf_data {
    use bitcoin::consensus::Decodable;
    use bitcoin::consensus::Encodable;
    use bitcoin::Amount;
    use bitcoin::BlockHash;
    use bitcoin::OutPoint;
    use bitcoin::TxOut;
    use rustreexo::accumulator::node_hash::BitcoinNodeHash;
    use serde::Deserialize;
    use serde::Serialize;
    use sha2::Digest;
    use sha2::Sha512_256;

    use super::LeafContext;

    /// The version tag to be prepended to the leafhash. It's just the sha512 hash of the string
    /// `UtreexoV1` represented as a vector of [u8] ([85 116 114 101 101 120 111 86 49]).
    /// The same tag is "5574726565786f5631" as a hex string.
    pub const UTREEXO_TAG_V1: [u8; 64] = [
        0x5b, 0x83, 0x2d, 0xb8, 0xca, 0x26, 0xc2, 0x5b, 0xe1, 0xc5, 0x42, 0xd6, 0xcc, 0xed, 0xdd,
        0xa8, 0xc1, 0x45, 0x61, 0x5c, 0xff, 0x5c, 0x35, 0x72, 0x7f, 0xb3, 0x46, 0x26, 0x10, 0x80,
        0x7e, 0x20, 0xae, 0x53, 0x4d, 0xc3, 0xf6, 0x42, 0x99, 0x19, 0x99, 0x31, 0x77, 0x2e, 0x03,
        0x78, 0x7d, 0x18, 0x15, 0x6e, 0xb3, 0x15, 0x1e, 0x0e, 0xd1, 0xb3, 0x09, 0x8b, 0xdc, 0x84,
        0x45, 0x86, 0x18, 0x85,
    ];

    /// Leaf data is the data that is hashed when adding to utreexo state. It contains validation
    /// data and some commitments to make it harder to attack an utreexo-only node.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct BitcoinLeafData {
        /// A commitment to the block creating this utxo
        pub block_hash: BlockHash,
        /// The utxo's outpoint
        pub prevout: OutPoint,
        /// Header code is a compact commitment to the block height and whether or not this
        /// transaction is coinbase. It's defined as
        ///
        /// ```
        /// header_code: u32 = if transaction.is_coinbase() {
        ///     (block_height << 1 ) | 1
        /// } else {
        ///     block_height << 1
        /// };
        /// ```
        pub header_code: u32,
        /// The actual utxo
        pub utxo: TxOut,
    }

    pub(crate) fn get_leaf_hash(
        block_hash: BlockHash,
        prevout: OutPoint,
        header_code: u32,
        utxo: &TxOut,
        serialized_utxo: &mut Vec<u8>,
    ) -> BitcoinNodeHash {
        serialized_utxo.clear();
        let _ = utxo.consensus_encode(serialized_utxo);
        let leaf_hash = Sha512_256::new()
            .chain_update(UTREEXO_TAG_V1)
            .chain_update(UTREEXO_TAG_V1)
            .chain_update(block_hash)
            .chain_update(prevout.txid)
            .chain_update(prevout.vout.to_le_bytes())
            .chain_update(header_code.to_le_bytes())
            .chain_update(serialized_utxo)
            .finalize();
        BitcoinNodeHash::from(leaf_hash.as_slice())
    }

    impl BitcoinLeafData {
        pub fn get_leaf_hashes(leaf: &LeafContext) -> BitcoinNodeHash {
            let leaf_data = BitcoinLeafData::from(leaf.clone());
            leaf_data.compute_hash()
        }

        fn compute_hash(&self) -> BitcoinNodeHash {
            get_leaf_hash(
                self.block_hash,
                self.prevout,
                self.header_code,
                &self.utxo,
                &mut Vec::new(),
            )
        }
    }

    impl Decodable for BitcoinLeafData {
        fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
            reader: &mut R,
        ) -> Result<Self, bitcoin::consensus::encode::Error> {
            Self::consensus_decode_from_finite_reader(reader)
        }

        fn consensus_decode_from_finite_reader<R: bitcoin::io::Read + ?Sized>(
            reader: &mut R,
        ) -> Result<Self, bitcoin::consensus::encode::Error> {
            let block_hash = BlockHash::consensus_decode(reader)?;
            let prevout = OutPoint::consensus_decode(reader)?;
            let header_code = u32::consensus_decode(reader)?;
            let utxo = TxOut::consensus_decode(reader)?;
            Ok(BitcoinLeafData {
                block_hash,
                prevout,
                header_code,
                utxo,
            })
        }
    }

    impl Encodable for BitcoinLeafData {
        fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
            &self,
            writer: &mut W,
        ) -> Result<usize, bitcoin::io::Error> {
            let mut len = 0;
            len += self.block_hash.consensus_encode(writer)?;
            len += self.prevout.consensus_encode(writer)?;
            len += self.header_code.consensus_encode(writer)?;
            len += self.utxo.consensus_encode(writer)?;
            Ok(len)
        }
    }

    impl From<LeafContext> for BitcoinLeafData {
        fn from(value: LeafContext) -> Self {
            BitcoinLeafData {
                block_hash: value.block_hash,
                prevout: OutPoint {
                    txid: value.txid,
                    vout: value.vout,
                },
                header_code: (value.block_height << 1) | value.is_coinbase as u32,
                utxo: TxOut {
                    value: Amount::from_sat(value.value),
                    script_pubkey: value.pk_script,
                },
            }
        }
    }
}

#[cfg(feature = "shinigami")]
pub mod shinigami_udata {
    use bitcoin::consensus::Encodable;
    use bitcoin::hashes::Hash;
    use bitcoin::Script;
    use bitcoin::Txid;
    use rustreexo::accumulator::node_hash::AccumulatorHash;
    use serde::Serialize;
    use starknet_crypto::poseidon_hash;
    use starknet_crypto::poseidon_hash_many;
    use starknet_crypto::Felt;

    use super::LeafContext;

    #[derive(Debug, Clone)]
    pub struct ByteArray {
        pub data: Vec<Felt>,
        pub pending_word: Felt,
        pub pending_word_len: usize,
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub struct ShinigamiLeafData {
        txid: Txid,
        vout: u32,
        value: u64,
        pk_script: ByteArray,
        block_height: u32,
        median_time_past: u32,
        is_coinbase: bool,
    }

    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    /// We need a stateful wrapper around the actual hash, this is because we use those different
    /// values inside our accumulator. Here we use an enum to represent the different states, you
    /// may want to use a struct with more data, depending on your needs.
    pub enum PoseidonHash {
        /// This means this holds an actual value
        ///
        /// It usually represents a node in the accumulator that haven't been deleted.
        Hash(Felt),
        /// Placeholder is a value that haven't been deleted, but we don't have the actual value.
        /// The only thing that matters about it is that it's not empty. You can implement this
        /// the way you want, just make sure that [BitcoinNodeHash::is_placeholder] and [NodeHash::placeholder]
        /// returns sane values (that is, if we call [BitcoinNodeHash::placeholder] calling [NodeHash::is_placeholder]
        /// on the result should return true).
        Placeholder,
        /// This is an empty value, it represents a node that was deleted from the accumulator.
        ///
        /// Same as the placeholder, you can implement this the way you want, just make sure that
        /// [BitcoinNodeHash::is_empty] and [NodeHash::empty] returns sane values.
        #[default]
        Empty,
    }

    // you'll need to implement Display for your hash type, so you can print it.
    impl std::fmt::Display for PoseidonHash {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                PoseidonHash::Hash(h) => write!(f, "Hash({})", h.to_hex_string()),
                PoseidonHash::Placeholder => write!(f, "Placeholder"),
                PoseidonHash::Empty => write!(f, "Empty"),
            }
        }
    }

    // this is the implementation of the BitcoinNodeHash trait for our custom hash type. And it's the only
    // thing you need to do to use your custom hash type with the accumulator data structures.
    impl AccumulatorHash for PoseidonHash {
        // returns a new placeholder type such that is_placeholder returns true
        fn placeholder() -> Self {
            PoseidonHash::Placeholder
        }

        // returns an empty hash such that is_empty returns true
        fn empty() -> Self {
            PoseidonHash::Empty
        }

        // returns true if this is a placeholder. This should be true iff this type was created by
        // calling placeholder.
        fn is_placeholder(&self) -> bool {
            matches!(self, PoseidonHash::Placeholder)
        }

        // returns true if this is an empty hash. This should be true iff this type was created by
        // calling empty.
        fn is_empty(&self) -> bool {
            matches!(self, PoseidonHash::Empty)
        }

        // used for serialization, writes the hash to the writer
        //
        // if you don't want to use serialization, you can just return an error here.
        fn write<W>(&self, writer: &mut W) -> std::io::Result<()>
        where
            W: std::io::Write,
        {
            match self {
                PoseidonHash::Hash(h) => writer.write_all(&h.to_bytes_be()),
                PoseidonHash::Placeholder => writer.write_all(&[0u8; 32]),
                PoseidonHash::Empty => writer.write_all(&[0u8; 32]),
            }
        }

        // used for deserialization, reads the hash from the reader
        //
        // if you don't want to use serialization, you can just return an error here.
        fn read<R>(reader: &mut R) -> std::io::Result<Self>
        where
            R: std::io::Read,
        {
            let mut buf = [0u8; 32];
            reader.read_exact(&mut buf)?;
            if buf.iter().all(|&b| b == 0) {
                Ok(PoseidonHash::Empty)
            } else {
                Ok(PoseidonHash::Hash(Felt::from_bytes_be(&buf)))
            }
        }

        // the main thing about the hash type, it returns the next node's hash, given it's children.
        // The implementation of this method is highly consensus critical, so everywhere should use the
        // exact same algorithm to calculate the next hash. Rustreexo won't call this method, unless
        // **both** children are not empty.
        fn parent_hash(left: &Self, right: &Self) -> Self {
            if let (PoseidonHash::Hash(left), PoseidonHash::Hash(right)) = (left, right) {
                return PoseidonHash::Hash(poseidon_hash(*left, *right));
            }

            // This should never happen, since rustreexo won't call this method unless both children
            // are not empty.
            unreachable!()
        }
    }

    impl Serialize for PoseidonHash {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match self {
                PoseidonHash::Hash(h) => {
                    let inner = h.to_fixed_hex_string();
                    inner.serialize(serializer)
                }
                PoseidonHash::Placeholder => serializer.serialize_none(),
                PoseidonHash::Empty => serializer.serialize_none(),
            }
        }
    }

    impl Encodable for PoseidonHash {
        fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
            &self,
            writer: &mut W,
        ) -> Result<usize, bitcoin::io::Error> {
            match self {
                PoseidonHash::Hash(h) => {
                    let inner = h.to_bytes_be();
                    inner.consensus_encode(writer)
                }
                PoseidonHash::Placeholder => Ok(0),
                PoseidonHash::Empty => Ok(0),
            }
        }
    }

    fn convert_hash256_to_felt(hash: [u8; 32]) -> [Felt; 2] {
        let (hight, low) = hash.split_at(16);

        [
            Felt::from_bytes_be_slice(hight),
            Felt::from_bytes_be_slice(low),
        ]
    }

    fn convert_spk_to_byte_array(pk_script: &Script) -> ByteArray {
        let mut iter = pk_script.as_bytes().chunks_exact(31);
        let mut data = vec![];

        #[allow(clippy::while_let_on_iterator)]
        while let Some(chunk) = iter.next() {
            let mut word = [0u8; 31];
            word.copy_from_slice(chunk);
            data.push(Felt::from_bytes_be_slice(&word));
        }

        let pending_word = iter.remainder();
        let pending_word_len = pending_word.len();
        let pending_word = if pending_word_len > 0 {
            let mut word = [0u8; 31];
            word[(31 - pending_word_len)..].copy_from_slice(pending_word);
            Felt::from_bytes_be_slice(&word)
        } else {
            Felt::from(0u64)
        };

        ByteArray {
            data,
            pending_word,
            pending_word_len,
        }
    }

    impl ShinigamiLeafData {
        pub fn get_leaf_hashes(data: &LeafContext) -> PoseidonHash {
            // rouding up to the next multiple of 2
            let mut data_to_hash = Vec::with_capacity(16);
            let pk_script = convert_spk_to_byte_array(&data.pk_script);
            let mut txid = data.txid.to_byte_array();
            txid.reverse();

            data_to_hash.extend(convert_hash256_to_felt(txid));
            data_to_hash.push(Felt::from(data.vout));
            data_to_hash.push(Felt::from(data.value));
            data_to_hash.push(Felt::from(pk_script.data.len()));
            data_to_hash.extend(pk_script.data);
            data_to_hash.push(pk_script.pending_word);
            data_to_hash.push(Felt::from(pk_script.pending_word_len as u64));
            data_to_hash.push(Felt::from(data.block_height));
            data_to_hash.push(Felt::from(data.median_time_past));
            data_to_hash.push(Felt::from(data.is_coinbase as u64));

            let leaf_hash = poseidon_hash_many(&data_to_hash);

            PoseidonHash::Hash(leaf_hash)
        }
    }
}

#[cfg(not(feature = "shinigami"))]
pub use bitcoin_leaf_data::BitcoinLeafData as LeafData;
#[cfg(feature = "shinigami")]
pub use shinigami_udata::ShinigamiLeafData as LeafData;

#[cfg(all(feature = "shinigami", test))]
mod shinigami_tests {
    use bitcoin::ScriptBuf;
    use starknet_crypto::Felt;

    use super::LeafContext;
    use crate::udata::shinigami_udata::PoseidonHash;

    #[test]
    fn test_node_hash() {
        let leaf = LeafContext {
            txid: "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9".parse().unwrap(),
            vout: 0,
            value: 5000000000,
            pk_script:  ScriptBuf::from_hex("410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac").unwrap(),
            block_height: 9,
            median_time_past: 1231473279,
            is_coinbase: true,
            block_hash: "00000000839a8e6886ab5951d76f4114754285bd7a81a48d0d722cb5b0c5e3a7".parse().unwrap(), // unused here
        };

        let leaf_hash = super::LeafData::get_leaf_hashes(&leaf);
        let expected = PoseidonHash::Hash(
            Felt::from_hex("3945D2584EE5EF0B482B70CD63E0E8CD18827CB348F839D1E6EB8ECBB2B397D")
                .unwrap(),
        );

        assert_eq!(leaf_hash, expected);
    }
}
