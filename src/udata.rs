// SPDX-License-Identifier: MIT

use bitcoin::consensus;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
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

impl From<&LeafContext> for CompactLeafData {
    fn from(leaf: &LeafContext) -> Self {
        let spk_ty = if leaf.pk_script.is_p2pkh() {
            ScriptPubkeyType::PubKeyHash
        } else if leaf.pk_script.is_p2sh() {
            ScriptPubkeyType::ScriptHash
        } else if leaf.pk_script.is_p2wpkh() {
            ScriptPubkeyType::WitnessV0PubKeyHash
        } else if leaf.pk_script.is_p2wsh() {
            ScriptPubkeyType::WitnessV0ScriptHash
        } else {
            ScriptPubkeyType::Other(leaf.pk_script.to_bytes().into_boxed_slice())
        };

        Self {
            header_code: (leaf.block_height << 1) | u32::from(leaf.is_coinbase),
            amount: leaf.value,
            spk_ty,
        }
    }
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

/// A block proof retained independently from the block fetched through Bitcoin Core.
///
/// Its consensus encoding is exactly `<targets><proof hashes><leaf data>`.
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct CompactBlockProof {
    pub proof: BatchProof,
    pub leaves: Vec<CompactLeafData>,
}

impl Encodable for CompactBlockProof {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = VarInt(self.proof.targets.len() as u64).consensus_encode(writer)?;
        for target in &self.proof.targets {
            len += target.consensus_encode(writer)?;
        }
        len += VarInt(self.proof.hashes.len() as u64).consensus_encode(writer)?;
        for hash in &self.proof.hashes {
            len += hash.consensus_encode(writer)?;
        }
        len += VarInt(self.leaves.len() as u64).consensus_encode(writer)?;
        for leaf in &self.leaves {
            len += leaf.header_code.consensus_encode(writer)?;
            len += leaf.amount.consensus_encode(writer)?;
            len += leaf.spk_ty.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl Decodable for CompactBlockProof {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, consensus::encode::Error> {
        let target_count = VarInt::consensus_decode(reader)?.0;
        let mut targets = Vec::with_capacity(target_count as usize);
        for _ in 0..target_count {
            targets.push(VarInt::consensus_decode(reader)?);
        }

        let hash_count = VarInt::consensus_decode(reader)?.0;
        let mut hashes = Vec::with_capacity(hash_count as usize);
        for _ in 0..hash_count {
            hashes.push(BlockHash::consensus_decode(reader)?);
        }

        let leaf_count = VarInt::consensus_decode(reader)?.0;
        let mut leaves = Vec::with_capacity(leaf_count as usize);
        for _ in 0..leaf_count {
            leaves.push(CompactLeafData {
                header_code: u32::consensus_decode(reader)?,
                amount: u64::consensus_decode(reader)?,
                spk_ty: ScriptPubkeyType::consensus_decode(reader)?,
            });
        }

        Ok(Self {
            proof: BatchProof { targets, hashes },
            leaves,
        })
    }
}

pub mod bitcoin_leaf_data {
    use bitcoin::consensus::Decodable;
    use bitcoin::consensus::Encodable;
    use bitcoin::hashes::Hash;
    use bitcoin::Amount;
    use bitcoin::BlockHash;
    use bitcoin::OutPoint;
    use bitcoin::TxOut;
    use rustreexo::node_hash::BitcoinNodeHash;
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

    pub(crate) fn get_leaf_hash_from_parts(
        block_hash: [u8; 32],
        txid: [u8; 32],
        vout: u32,
        header_code: u32,
        value: u64,
        script_pubkey: &[u8],
    ) -> BitcoinNodeHash {
        let mut compact_size = [0u8; 9];
        let compact_size_len = match script_pubkey.len() as u64 {
            value @ 0..=0xfc => {
                compact_size[0] = value as u8;
                1
            }
            value @ 0xfd..=0xffff => {
                compact_size[0] = 0xfd;
                compact_size[1..3].copy_from_slice(&(value as u16).to_le_bytes());
                3
            }
            value @ 0x1_0000..=0xffff_ffff => {
                compact_size[0] = 0xfe;
                compact_size[1..5].copy_from_slice(&(value as u32).to_le_bytes());
                5
            }
            value => {
                compact_size[0] = 0xff;
                compact_size[1..9].copy_from_slice(&value.to_le_bytes());
                9
            }
        };
        let leaf_hash = Sha512_256::new()
            .chain_update(UTREEXO_TAG_V1)
            .chain_update(UTREEXO_TAG_V1)
            .chain_update(block_hash)
            .chain_update(txid)
            .chain_update(vout.to_le_bytes())
            .chain_update(header_code.to_le_bytes())
            .chain_update(value.to_le_bytes())
            .chain_update(&compact_size[..compact_size_len])
            .chain_update(script_pubkey)
            .finalize();
        BitcoinNodeHash::from(leaf_hash.as_slice())
    }

    impl BitcoinLeafData {
        pub fn get_leaf_hashes(leaf: &LeafContext) -> BitcoinNodeHash {
            let leaf_data = BitcoinLeafData::from(leaf.clone());
            leaf_data.compute_hash()
        }

        fn compute_hash(&self) -> BitcoinNodeHash {
            get_leaf_hash_from_parts(
                self.block_hash.to_byte_array(),
                self.prevout.txid.to_byte_array(),
                self.prevout.vout,
                self.header_code,
                self.utxo.value.to_sat(),
                self.utxo.script_pubkey.as_bytes(),
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

pub use bitcoin_leaf_data::BitcoinLeafData as LeafData;
