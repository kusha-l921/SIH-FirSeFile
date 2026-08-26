// Source: param-part3 storage-engine/src/filter/signature.rs (unchanged)
use memchr::memmem;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Jpeg,
    Png,
    Pdf,
    Zip,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub source: String,
    pub region_id: u64,
    pub block_id: u64,
    pub block_offset: u64,
    /// Absolute byte offset of the detected signature in the source image.
    pub absolute_offset: u64,
    pub file_type: FileType,
    pub detection_method: String,
    pub confidence: f32,
    /// Copy of the block data for provenance-preserving fragment extraction.
    pub block_data: Vec<u8>,
}

pub fn scan_signatures(
    data: &[u8],
    source: &str,
    region_id: u64,
    block_id: u64,
    block_offset: u64,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();

    for (pattern, file_type) in [
        (b"\xFF\xD8\xFF".as_slice(), FileType::Jpeg),
        (b"\x89PNG".as_slice(),      FileType::Png),
        (b"%PDF".as_slice(),         FileType::Pdf),
        (b"PK\x03\x04".as_slice(),  FileType::Zip),
    ] {
        scan_pattern(data, pattern, file_type, &mut candidates,
                     source, region_id, block_id, block_offset);
    }

    candidates.sort_by_key(|c| c.absolute_offset);
    candidates
}

fn scan_pattern(
    data: &[u8],
    pattern: &[u8],
    file_type: FileType,
    candidates: &mut Vec<Candidate>,
    source: &str,
    region_id: u64,
    block_id: u64,
    block_offset: u64,
) {
    let mut position = 0;
    while position + pattern.len() <= data.len() {
        match memmem::find(&data[position..], pattern) {
            Some(relative) => {
                let offset = position + relative;
                candidates.push(Candidate {
                    source: source.to_string(),
                    region_id,
                    block_id,
                    block_offset,
                    absolute_offset: block_offset + offset as u64,
                    file_type,
                    detection_method: "Signature".to_string(),
                    confidence: 1.0,
                    block_data: data.to_vec(),
                });
                position = offset + 1;
            }
            None => break,
        }
    }
}
