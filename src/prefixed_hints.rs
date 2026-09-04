// SPDX-License-Identifier: MIT

//! Bridge-owned leaf-count prefix followed by an unmodified `hintsfile` payload.

use std::io::Read;
use std::io::Write;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use hintsfile::Hintsfile;

const MAGIC: [u8; 8] = *b"BRLFCT01";
const COUNT_SIZE: usize = size_of::<u32>();

#[derive(Debug)]
pub struct BridgeHints {
    hints: Hintsfile,
    leaf_counts: Vec<u8>,
}

impl BridgeHints {
    pub fn from_reader<R: Read>(reader: &mut R) -> Result<Self> {
        let mut magic = [0u8; MAGIC.len()];
        reader
            .read_exact(&mut magic)
            .context("failed to read bridge hints magic")?;
        if magic != MAGIC {
            bail!("hintsfile is missing the bridge leaf-count prefix");
        }

        let mut height = [0u8; size_of::<u32>()];
        reader
            .read_exact(&mut height)
            .context("failed to read bridge hints stop height")?;
        let stop_height = u32::from_le_bytes(height);
        if stop_height == 0 {
            bail!("bridge hints stop height must be greater than zero");
        }
        let count_bytes = usize::try_from(stop_height)
            .context("bridge hints stop height exceeds usize")?
            .checked_mul(COUNT_SIZE)
            .context("bridge leaf-count section length overflow")?;
        let mut leaf_counts = vec![0u8; count_bytes];
        reader
            .read_exact(&mut leaf_counts)
            .context("failed to read bridge per-block leaf counts")?;

        let hints = Hintsfile::from_reader(reader).context("failed to read hintsfile payload")?;
        if hints.stop_height() != stop_height {
            bail!(
                "bridge leaf counts stop at height {stop_height}, but hints payload stops at {}",
                hints.stop_height()
            );
        }
        Ok(Self { hints, leaf_counts })
    }

    pub fn stop_height(&self) -> u32 {
        self.hints.stop_height()
    }

    pub fn leaf_count_at_height(&self, height: u32) -> Option<u32> {
        let index = height.checked_sub(1)?;
        if height > self.stop_height() {
            return None;
        }
        let offset = usize::try_from(index).ok()?.checked_mul(COUNT_SIZE)?;
        let bytes: [u8; COUNT_SIZE] = self
            .leaf_counts
            .get(offset..offset + COUNT_SIZE)?
            .try_into()
            .ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    pub fn indices_at_height(&self, height: u32) -> Option<Vec<u32>> {
        self.hints.indices_at_height(height)
    }
}

pub fn write_leaf_count_prefix<W: Write>(
    writer: &mut W,
    stop_height: u32,
    leaf_counts: &[u32],
) -> Result<()> {
    let expected = usize::try_from(stop_height)
        .context("bridge hints stop height exceeds usize")?
        .checked_add(1)
        .context("bridge leaf-count length overflow")?;
    if leaf_counts.len() != expected {
        bail!(
            "expected {expected} leaf counts including height zero, got {}",
            leaf_counts.len()
        );
    }
    if leaf_counts[0] != 0 {
        bail!("height-zero leaf count must be zero");
    }

    writer.write_all(&MAGIC)?;
    writer.write_all(&stop_height.to_le_bytes())?;
    const COUNTS_PER_WRITE: usize = 1024;
    let mut encoded = [0u8; COUNTS_PER_WRITE * COUNT_SIZE];
    for counts in leaf_counts[1..].chunks(COUNTS_PER_WRITE) {
        for (slot, count) in encoded.chunks_exact_mut(COUNT_SIZE).zip(counts) {
            slot.copy_from_slice(&count.to_le_bytes());
        }
        writer.write_all(&encoded[..counts.len() * COUNT_SIZE])?;
    }
    Ok(())
}
