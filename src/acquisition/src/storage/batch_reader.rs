//! Batch block reader.
//!
//! On Linux: uses `io_uring` for high-throughput async I/O.
//! On other platforms: falls back to standard synchronous `pread`-style I/O
//! so the crate compiles and tests pass everywhere.
//!
//! Source: param-part3 storage-engine/src/storage/batch_reader.rs
//! Change: added `#[cfg]` gates and a portable fallback implementation.

use anyhow::Result;

use super::Block;

pub struct BatchReader {
    #[cfg(target_os = "linux")]
    ring: io_uring::IoUring,
    #[cfg(not(target_os = "linux"))]
    _queue_depth: u32,
}

impl BatchReader {
    pub fn new(queue_depth: u32) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                ring: io_uring::IoUring::new(queue_depth)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self {
                _queue_depth: queue_depth,
            })
        }
    }

    pub fn read_blocks(
        &mut self,
        file_path: &str,
        start_offset: u64,
        block_size: usize,
        count: usize,
    ) -> Result<Vec<Block>> {
        #[cfg(target_os = "linux")]
        {
            self.read_blocks_uring(file_path, start_offset, block_size, count)
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.read_blocks_std(file_path, start_offset, block_size, count)
        }
    }

    // ------------------------------------------------------------------
    // Linux io_uring path
    // ------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn read_blocks_uring(
        &mut self,
        file_path: &str,
        start_offset: u64,
        block_size: usize,
        count: usize,
    ) -> Result<Vec<Block>> {
        use anyhow::Context;
        use io_uring::{opcode, types};
        use std::fs::OpenOptions;
        use std::os::fd::AsRawFd;

        let file = OpenOptions::new()
            .read(true)
            .open(file_path)
            .with_context(|| format!("Failed to open {file_path}"))?;

        let fd = types::Fd(file.as_raw_fd());
        let mut buffers: Vec<Vec<u8>> = (0..count).map(|_| vec![0u8; block_size]).collect();

        for (index, buffer) in buffers.iter_mut().enumerate() {
            let offset = start_offset + index as u64 * block_size as u64;
            let req = opcode::Read::new(fd, buffer.as_mut_ptr(), block_size as u32)
                .offset(offset)
                .build()
                .user_data(index as u64);
            unsafe {
                self.ring
                    .submission()
                    .push(&req)
                    .context("Failed to submit read request")?;
            }
        }

        self.ring.submit_and_wait(count)?;

        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            let cqe = self
                .ring
                .completion()
                .next()
                .context("Missing completion event")?;
            let result = cqe.result();
            if result < 0 {
                anyhow::bail!("Read failed for request {}: {}", cqe.user_data(), result);
            }
            let index = cqe.user_data() as usize;
            buffers[index].resize(result as usize, 0);
            let offset = start_offset + index as u64 * block_size as u64;
            blocks.push(Block::new(index as u64, offset, buffers[index].clone()));
        }

        blocks.sort_by_key(|b| b.offset);
        Ok(blocks)
    }

    // ------------------------------------------------------------------
    // Portable fallback (non-Linux)
    // ------------------------------------------------------------------

    #[cfg(not(target_os = "linux"))]
    fn read_blocks_std(
        &self,
        file_path: &str,
        start_offset: u64,
        block_size: usize,
        count: usize,
    ) -> Result<Vec<Block>> {
        use anyhow::Context;
        use std::fs::OpenOptions;
        use std::io::{Read, Seek, SeekFrom};

        let mut file = OpenOptions::new()
            .read(true)
            .open(file_path)
            .with_context(|| format!("Failed to open {file_path}"))?;

        let mut blocks = Vec::with_capacity(count);
        for index in 0..count {
            let offset = start_offset + index as u64 * block_size as u64;
            file.seek(SeekFrom::Start(offset))
                .context("seek failed")?;
            let mut buf = vec![0u8; block_size];
            let n = file.read(&mut buf).context("read failed")?;
            buf.resize(n, 0);
            blocks.push(Block::new(index as u64, offset, buf));
        }
        Ok(blocks)
    }
}
