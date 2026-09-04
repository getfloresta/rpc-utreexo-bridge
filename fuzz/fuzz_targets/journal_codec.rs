#![no_main]
#[allow(dead_code)]
#[path = "../../src/forest_journal.rs"]
mod forest_journal;

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::Txid;
use forest_journal::JournalEntry;
use forest_journal::JournalForestDelta;
use forest_journal::JournalIndexDelta;
use forest_journal::JournalNodeState;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(decoded) = JournalEntry::decode(data) {
        let encoded = decoded.encode().expect("decoded entry must encode");
        assert_eq!(JournalEntry::decode(&encoded).unwrap(), decoded);
        assert_eq!(decoded.encode().unwrap(), encoded);
    }

    let mut input = Input::new(data);
    let forest = (0..input.count(8))
        .map(|_| JournalForestDelta {
            position: input.u64(),
            before: input.state(),
            after: input.state(),
        })
        .collect::<Vec<_>>();
    let removed = (0..input.count(8))
        .map(|_| input.index_delta())
        .collect::<Vec<_>>();
    let added = (0..input.count(8))
        .map(|_| input.index_delta())
        .collect::<Vec<_>>();
    let entry = JournalEntry {
        block_hash: BlockHash::from_byte_array(input.array()),
        num_leaves: input.u64().saturating_add(added.len() as u64),
        height: input.u32(),
        previous_block_hash: BlockHash::from_byte_array(input.array()),
        forest,
        removed,
        added,
    };
    let encoded = entry.encode().expect("bounded entry must encode");
    assert_eq!(JournalEntry::decode(&encoded).unwrap(), entry);
    assert_eq!(entry.encode().unwrap(), encoded);

    let mut with_trailing_byte = encoded;
    with_trailing_byte.push(input.byte());
    assert!(JournalEntry::decode(&with_trailing_byte).is_err());
});

struct Input<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Input<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn byte(&mut self) -> u8 {
        if self.bytes.is_empty() {
            return 0;
        }
        let byte = self.bytes[self.cursor % self.bytes.len()];
        self.cursor = self.cursor.wrapping_add(1);
        byte
    }

    fn count(&mut self, limit: usize) -> usize {
        usize::from(self.byte()) % (limit + 1)
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        std::array::from_fn(|_| self.byte())
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.array())
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.array())
    }

    fn state(&mut self) -> JournalNodeState {
        let flags = self.byte();
        JournalNodeState {
            ready: flags & 1 != 0,
            spent: flags & 2 != 0,
            hash: self.array(),
        }
    }

    fn index_delta(&mut self) -> JournalIndexDelta {
        JournalIndexDelta {
            outpoint: OutPoint {
                txid: Txid::from_byte_array(self.array()),
                vout: self.u32(),
            },
            position: self.u64(),
        }
    }
}
