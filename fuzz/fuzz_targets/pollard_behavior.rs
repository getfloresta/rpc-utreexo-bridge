#![no_main]

mod fast_hash;

use fast_hash::FastHash;
use libfuzzer_sys::fuzz_target;
use rustreexo::mem_forest::MemForest;
use rustreexo::pollard::Pollard;
use rustreexo::pollard::PollardAddition;
use rustreexo::stump::Stump;

fuzz_target!(|data: &[u8]| {
    let mut pollard = Pollard::<FastHash>::new();
    let mut stump = Stump::<FastHash>::new_with_hash();
    let mut forest = MemForest::<FastHash>::new_with_hash();
    let mut live = Vec::<FastHash>::new();
    let mut next_leaf = 1u64;
    let mut cursor = 0usize;

    while cursor < data.len().min(256) {
        let control = data[cursor];
        cursor += 1;

        let requested_deletions = usize::from(control >> 4) & 3;
        let mut deletion_indices = Vec::with_capacity(requested_deletions);
        for offset in 0..requested_deletions {
            if live.is_empty() {
                break;
            }
            let selector = data
                .get(cursor + offset)
                .copied()
                .unwrap_or(control.wrapping_add(offset as u8));
            deletion_indices.push(usize::from(selector) % live.len());
        }
        cursor = cursor.saturating_add(requested_deletions).min(data.len());
        deletion_indices.sort_unstable();
        deletion_indices.dedup();
        let deletions = deletion_indices
            .iter()
            .map(|index| live[*index])
            .collect::<Vec<_>>();

        let addition_count = usize::from(control & 3);
        let mut addition_hashes = Vec::with_capacity(addition_count);
        for offset in 0..addition_count {
            let entropy = data
                .get(cursor + offset)
                .copied()
                .unwrap_or(control.wrapping_sub(offset as u8));
            addition_hashes.push(FastHash::leaf(next_leaf, entropy));
            next_leaf += 1;
        }
        cursor = cursor.saturating_add(addition_count).min(data.len());

        let proof = forest
            .prove(&deletions)
            .expect("model contains every live leaf");
        assert!(stump.verify(&proof, &deletions).unwrap());
        let expected = stump
            .modify(&addition_hashes, &deletions, &proof)
            .expect("Pollard-generated proof must update the stump");
        let additions = addition_hashes
            .iter()
            .map(|hash| PollardAddition {
                hash: *hash,
                remember: true,
            })
            .collect::<Vec<_>>();
        pollard
            .modify(&additions, &deletions, proof)
            .expect("verified update must modify the Pollard");

        live.retain(|hash| !deletions.contains(hash));
        forest
            .modify(&addition_hashes, &deletions)
            .expect("model contains every deleted leaf");
        live.extend(addition_hashes);
        stump = expected;

        let mut pollard_roots = pollard.roots();
        pollard_roots.reverse();
        assert_eq!(pollard.leaves(), stump.leaves);
        assert_eq!(pollard_roots, stump.roots);
        let forest_roots = forest
            .get_roots()
            .iter()
            .map(|root| root.get_data())
            .collect::<Vec<_>>();
        assert_eq!(forest.leaves, stump.leaves);
        assert_eq!(forest_roots, stump.roots);
        assert!(live
            .iter()
            .all(|hash| pollard.leaf_position(hash).is_some()));
    }
});
