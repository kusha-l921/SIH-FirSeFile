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

    /// Filesystem/storage-engine region containing the candidate.
    pub region_id: u64,

    /// Block containing the candidate.
    pub block_id: u64,

    /// Starting offset of the block.
    pub block_offset: u64,

    /// Absolute byte offset of the detected signature.
    pub absolute_offset: u64,

    pub file_type: FileType,

    pub detection_method: String,

    pub confidence: f32,

    /// Copy of the block data used for provenance-preserving
    /// fragment extraction.
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

    scan_pattern(
        data,
        b"\xFF\xD8\xFF",
        FileType::Jpeg,
        &mut candidates,
        source,
        region_id,
        block_id,
        block_offset,
    );

    scan_pattern(
        data,
        b"\x89PNG",
        FileType::Png,
        &mut candidates,
        source,
        region_id,
        block_id,
        block_offset,
    );

    scan_pattern(
        data,
        b"%PDF",
        FileType::Pdf,
        &mut candidates,
        source,
        region_id,
        block_id,
        block_offset,
    );

    scan_pattern(
        data,
        b"PK\x03\x04",
        FileType::Zip,
        &mut candidates,
        source,
        region_id,
        block_id,
        block_offset,
    );

    candidates.sort_by_key(|candidate| candidate.absolute_offset);

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
