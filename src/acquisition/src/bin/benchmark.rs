// Source: param-part3 storage-engine/src/bin/benchmark.rs (unchanged)
use std::time::Instant;

fn main() {
    const BLOCK_SIZE: usize = 4096;
    const NUM_BLOCKS: usize = 100_000;

    let mut data = vec![0u8; BLOCK_SIZE * NUM_BLOCKS];
    for i in (0..data.len()).step_by(8192) {
        if i + 4 <= data.len() {
            data[i..i + 4].copy_from_slice(b"\x89PNG");
        }
    }

    println!("Acquisition Benchmark");
    println!("=====================");
    println!("Data size   : {:.2} MB", data.len() as f64 / 1_048_576.0);
    println!("Block size  : {} bytes", BLOCK_SIZE);
    println!("Block count : {}", NUM_BLOCKS);

    let start = Instant::now();
    let mut baseline_matches = 0usize;
    for block in data.chunks_exact(BLOCK_SIZE) {
        let mut pos = 0;
        while pos + 4 <= block.len() {
            if &block[pos..pos + 4] == b"\x89PNG" { baseline_matches += 1; }
            pos += 1;
        }
    }
    let baseline_time = start.elapsed();

    let start = Instant::now();
    let mut simd_matches = 0usize;
    for block in data.chunks_exact(BLOCK_SIZE) {
        simd_matches += scan_png_simd(block);
    }
    let simd_time = start.elapsed();

    let total_mb = data.len() as f64 / 1_048_576.0;
    println!("\nResults");
    println!("-------");
    println!("Baseline matches : {baseline_matches}");
    println!("SIMD matches     : {simd_matches}");
    println!("Baseline time    : {:.3} ms", baseline_time.as_secs_f64() * 1000.0);
    println!("SIMD time        : {:.3} ms", simd_time.as_secs_f64() * 1000.0);
    println!("Baseline         : {:.2} MB/s", total_mb / baseline_time.as_secs_f64());
    println!("SIMD             : {:.2} MB/s", total_mb / simd_time.as_secs_f64());
    println!("Speedup          : {:.2}x",
        baseline_time.as_secs_f64() / simd_time.as_secs_f64());
}

#[cfg(target_arch = "aarch64")]
fn scan_png_simd(data: &[u8]) -> usize {
    use std::arch::aarch64::*;
    if data.len() < 4 { return 0; }
    let mut matches = 0usize;
    unsafe {
        let target = vdup_n_u8(0x89);
        let mut offset = 0;
        while offset + 16 <= data.len() {
            let chunk = vld1_u8(data.as_ptr().add(offset));
            let cmp = vceq_u8(chunk, target);
            let mut mask = [0u8; 8];
            vst1_u8(mask.as_mut_ptr(), cmp);
            for lane in 0..8 {
                if mask[lane] != 0 {
                    let pos = offset + lane;
                    if pos + 4 <= data.len() && &data[pos..pos + 4] == b"\x89PNG" {
                        matches += 1;
                    }
                }
            }
            offset += 16;
        }
        while offset + 4 <= data.len() {
            if &data[offset..offset + 4] == b"\x89PNG" { matches += 1; }
            offset += 1;
        }
    }
    matches
}

#[cfg(not(target_arch = "aarch64"))]
fn scan_png_simd(_data: &[u8]) -> usize { 0 }
