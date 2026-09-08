use std::fmt;
use std::io;
use std::io::Read;
use std::io::Write;

use rustreexo::node_hash::AccumulatorHash;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FastHash {
    #[default]
    Empty,
    Placeholder,
    Value(u64, u64),
}

impl FastHash {
    pub fn leaf(sequence: u64, entropy: u8) -> Self {
        Self::Value(
            mix(sequence ^ u64::from(entropy)),
            mix(sequence.rotate_left(29) ^ (!u64::from(entropy))),
        )
    }

    fn words(self) -> (u64, u64) {
        match self {
            Self::Empty => (0, 0),
            Self::Placeholder => (u64::MAX, u64::MAX),
            Self::Value(high, low) => (high, low),
        }
    }
}

impl fmt::Display for FastHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("empty"),
            Self::Placeholder => formatter.write_str("placeholder"),
            Self::Value(high, low) => write!(formatter, "{high:016x}{low:016x}"),
        }
    }
}

impl AccumulatorHash for FastHash {
    fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    fn empty() -> Self {
        Self::Empty
    }

    fn is_placeholder(&self) -> bool {
        matches!(self, Self::Placeholder)
    }

    fn placeholder() -> Self {
        Self::Placeholder
    }

    fn parent_hash(left: &Self, right: &Self) -> Self {
        let (left_high, left_low) = left.words();
        let (right_high, right_low) = right.words();
        Self::Value(
            mix(left_high ^ right_low.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15),
            mix(left_low.rotate_left(31) ^ right_high ^ 0xd6e8_feb8_6659_fd93),
        )
    }

    fn write<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        match self {
            Self::Empty => writer.write_all(&[0]),
            Self::Placeholder => writer.write_all(&[1]),
            Self::Value(high, low) => {
                writer.write_all(&[2])?;
                writer.write_all(&high.to_le_bytes())?;
                writer.write_all(&low.to_le_bytes())
            }
        }
    }

    fn read<R>(reader: &mut R) -> io::Result<Self>
    where
        R: Read,
    {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            0 => Ok(Self::Empty),
            1 => Ok(Self::Placeholder),
            2 => {
                let mut high = [0u8; 8];
                let mut low = [0u8; 8];
                reader.read_exact(&mut high)?;
                reader.read_exact(&mut low)?;
                Ok(Self::Value(
                    u64::from_le_bytes(high),
                    u64::from_le_bytes(low),
                ))
            }
            tag => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid fast hash tag {tag}"),
            )),
        }
    }
}

fn mix(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
