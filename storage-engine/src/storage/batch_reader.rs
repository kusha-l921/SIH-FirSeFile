use anyhow::{Context, Result};
use io_uring::{opcode, types, IoUring};
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;

use super::Block;

pub struct BatchReader {
    ring: IoUring,
}

impl BatchReader {
    pub fn new(queue_depth: u32) -> Result<Self> {
        Ok(Self {
            ring: IoUring::new(queue_depth)?,
        })
    }

    pub fn read_blocks(
        &mut self,
        file_path: &str,
        start_offset: u64,
        block_size: usize,
        count: usize,
    ) -> Result<Vec<Block>> {
        let file = OpenOptions::new()
            .read(true)
            .open(file_path)
            .with_context(|| format!("Failed to open {}", file_path))?;

        let fd = types::Fd(file.as_raw_fd());

        let mut buffers: Vec<Vec<u8>> =
            (0..count).map(|_| vec![0u8; block_size]).collect();

        for (index, buffer) in buffers.iter_mut().enumerate() {
            let offset = start_offset + index as u64 * block_size as u64;

            let request = opcode::Read::new(
                fd,
                buffer.as_mut_ptr(),
                block_size as u32,
            )
            .offset(offset)
            .build()
            .user_data(index as u64);

            unsafe {
                self.ring
                    .submission()
                    .push(&request)
                    .context("Failed to submit read request")?;
            }
        }

        self.ring.submit_and_wait(count)?;

        let mut blocks = Vec::with_capacity(count);

        for _ in 0..count {
            let completion = self
                .ring
                .completion()
                .next()
                .context("Missing completion event")?;

            let result = completion.result();

            if result < 0 {
                anyhow::bail!(
                    "Read failed for request {}: {}",
                    completion.user_data(),
                    result
                );
            }

            let index = completion.user_data() as usize;

            buffers[index].truncate(result as usize);

            let offset =
                start_offset + index as u64 * block_size as u64;

            blocks.push(Block::new(
                index as u64,
                offset,
                buffers[index].clone(),
            ));
        }

        blocks.sort_by_key(|block| block.offset);

        Ok(blocks)
    }
}
