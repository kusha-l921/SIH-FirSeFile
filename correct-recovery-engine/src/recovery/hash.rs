use crate::error::{Error, Result};
use crate::io::ImageRead;
use crate::recovery::classify::{RecoveryCandidate, RecoveryConfidence, RecoveryMethod};
use crate::util::sha256::{Sha256, sha256_hex};
use crate::xfs::dinode::{FileType, Timestamp};
use crate::xfs::extents::ExtentReader;
use crate::xfs::inode_addr::InodeLocation;
use crate::xfs::superblock::Geometry;

const HASH_CHUNK_BYTES: usize = 64 * 1024;

pub fn sha256_image<R: ImageRead>(reader: &mut R) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; HASH_CHUNK_BYTES];

    if let Some(total_len) = reader.image_len() {
        let mut offset = 0u64;
        while offset < total_len {
            let chunk_len = ((total_len - offset) as usize).min(buf.len());
            reader.read_at(offset, &mut buf[..chunk_len])?;
            hasher.update(&buf[..chunk_len]);
            offset += chunk_len as u64;
        }
    } else {
        let mut offset = 0u64;
        loop {
            match reader.read_at(offset, &mut buf) {
                Ok(()) => {
                    hasher.update(&buf);
                    offset = match offset.checked_add(buf.len() as u64) {
                        Some(next) => next,
                        None => break,
                    };
                }
                Err(Error::OutOfBounds { image_len, .. }) => {
                    if image_len > offset {
                        let remaining = (image_len - offset) as usize;
                        if remaining > 0 && remaining <= buf.len() {
                            reader.read_at(offset, &mut buf[..remaining])?;
                            hasher.update(&buf[..remaining]);
                        }
                    }
                    break;
                }
                Err(e) => return Err(e),
            }
        }
    }

    Ok(hasher.finalize_hex())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentHash {
    pub sha256: String,
    pub hashed_bytes: u64,
    pub is_exact_logical_size: bool,
}

pub fn sha256_candidate_content<R: ImageRead>(
    reader: &mut R,
    fs_base_offset: u64,
    geometry: &Geometry,
    candidate: &RecoveryCandidate,
) -> Result<ContentHash> {
    let (target_length, is_exact) = match candidate.original_size {
        Some(sz) => (sz, true),
        None => (candidate.observed_extent_bytes, false),
    };

    if target_length == 0 {
        return Ok(ContentHash {
            sha256: sha256_hex(b""),
            hashed_bytes: 0,
            is_exact_logical_size: is_exact,
        });
    }

    let mut extent_reader = ExtentReader::new(
        reader,
        fs_base_offset,
        geometry,
        &candidate.extents.extents,
        target_length,
    );

    let mut hasher = Sha256::new();
    let mut buf = [0u8; HASH_CHUNK_BYTES];
    let mut offset = 0u64;

    while offset < target_length {
        let n = extent_reader.read_at(offset, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        offset += n as u64;
    }

    Ok(ContentHash {
        sha256: hasher.finalize_hex(),
        hashed_bytes: offset,
        is_exact_logical_size: is_exact,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateHandoff {
    pub ino: u64,
    pub source_location: InodeLocation,
    pub ag_number: u32,
    pub file_type: FileType,
    pub mode: u16,
    pub permissions: u16,
    pub uid: u32,
    pub gid: u32,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub crtime: Option<Timestamp>,
    pub original_size: Option<u64>,
    pub observed_extent_bytes: u64,
    pub content_sha256: Option<String>,
    pub content_hash_exact: bool,
    pub method: RecoveryMethod,
    pub confidence: RecoveryConfidence,
    pub is_experimental: bool,
}

impl CandidateHandoff {
    pub fn new(candidate: &RecoveryCandidate, content_hash: Option<ContentHash>) -> Self {
        let (content_sha256, content_hash_exact) = match content_hash {
            Some(ch) => (Some(ch.sha256), ch.is_exact_logical_size),
            None => (None, false),
        };
        Self {
            ino: candidate.ino,
            source_location: candidate.location,
            ag_number: candidate.ag_number,
            file_type: candidate.file_type,
            mode: candidate.mode,
            permissions: candidate.permissions,
            uid: candidate.uid,
            gid: candidate.gid,
            atime: candidate.atime,
            mtime: candidate.mtime,
            ctime: candidate.ctime,
            crtime: candidate.crtime,
            original_size: candidate.original_size,
            observed_extent_bytes: candidate.observed_extent_bytes,
            content_sha256,
            content_hash_exact,
            method: candidate.method,
            confidence: candidate.confidence,
            is_experimental: candidate.is_experimental,
        }
    }
}
