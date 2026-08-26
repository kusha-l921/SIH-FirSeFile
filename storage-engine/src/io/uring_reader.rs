use anyhow::{Context, Result};
use io_uring::{opcode, types, IoUring};
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;

pub fn read_block(path: &str, offset: u64, size: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("Failed to open {}", path))?;

    let fd = types::Fd(file.as_raw_fd());

    let mut buffer = vec![0u8; size];

    let mut ring = IoUring::new(8)?;

    let read_e = opcode::Read::new(
        fd,
        buffer.as_mut_ptr(),
        size as u32,
    )
    .offset(offset)
    .build()
    .user_data(0x01);

    unsafe {
        ring.submission()
            .push(&read_e)
            .context("Failed to submit read operation")?;
    }

    ring.submit_and_wait(1)?;

    let cqe = ring
        .completion()
        .next()
        .context("No completion event received")?;

    let result = cqe.result();

    if result < 0 {
        anyhow::bail!("io_uring read failed: {}", result);
    }

    buffer.truncate(result as usize);

    Ok(buffer)
}
