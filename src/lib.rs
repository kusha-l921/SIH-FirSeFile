pub mod error;
pub mod io;
pub mod util;
pub mod xfs;

pub use error::{Error, Result};
pub use io::{FileImage, ImageRead, MemImage};
pub use util::be::{be_u16, be_u16_at, be_u32, be_u32_at, be_u64, be_u64_at};
pub use util::crc32c::crc32c;
pub use xfs::{CrcStatus, Geometry, Superblock, SuperblockIssue};
