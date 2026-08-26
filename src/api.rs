use crate::error::Result;
use crate::io::ImageRead;
use crate::recovery::classify::{
    CandidateClass, RecoveryCandidate, RecoveryConfidence, RecoveryReport, RecoverySummary,
    Rejection, RejectionReason, collect_recovery_candidates,
};
use crate::xfs::WalkMode;
use crate::xfs::extents::ExtentReader;
use crate::xfs::superblock::{CrcStatus, Geometry, Superblock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryOptions {
    pub base_offset: u64,
    pub walk_mode: WalkMode,
    pub enable_experimental: bool,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            base_offset: 0,
            walk_mode: WalkMode::Strict,
            enable_experimental: false,
        }
    }
}

impl RecoveryOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_base_offset(mut self, base_offset: u64) -> Self {
        self.base_offset = base_offset;
        self
    }

    pub fn with_walk_mode(mut self, walk_mode: WalkMode) -> Self {
        self.walk_mode = walk_mode;
        self
    }

    pub fn with_experimental(mut self, enable_experimental: bool) -> Self {
        self.enable_experimental = enable_experimental;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsInfo {
    pub version_raw: u16,
    pub is_v5: bool,
    pub block_size: u32,
    pub sector_size: u32,
    pub inode_size: u32,
    pub ag_count: u32,
    pub ag_blocks: u32,
    pub dblocks: u64,
    pub total_bytes: u64,
    pub uuid: [u8; 16],
    pub crc_status: CrcStatus,
    pub root_inode: u64,
    pub has_finobt: bool,
    pub has_sparse_inobt: bool,
    pub has_nrext64: bool,
}

pub struct RecoveryEngine<R: ImageRead> {
    reader: R,
    options: RecoveryOptions,
    sb: Superblock,
    geometry: Geometry,
    fs_info: FsInfo,
}

impl<R: ImageRead> RecoveryEngine<R> {
    pub fn open(mut reader: R, options: RecoveryOptions) -> Result<Self> {
        let (sb, geometry) = Superblock::parse(&mut reader, options.base_offset)?;

        let fs_info = FsInfo {
            version_raw: sb.version_num_raw,
            is_v5: sb.version5(),
            block_size: sb.block_size,
            sector_size: sb.sector_size,
            inode_size: sb.inode_size,
            ag_count: sb.ag_count,
            ag_blocks: sb.ag_blocks,
            dblocks: sb.dblocks,
            total_bytes: geometry.total_bytes(),
            uuid: sb.uuid,
            crc_status: sb.crc_status,
            root_inode: sb.root_inode,
            has_finobt: sb.finobt_enabled(),
            has_sparse_inobt: sb.sparse_inodes_enabled(),
            has_nrext64: sb.nrext64_enabled(),
        };

        Ok(Self {
            reader,
            options,
            sb,
            geometry,
            fs_info,
        })
    }

    pub fn fs_info(&self) -> &FsInfo {
        &self.fs_info
    }

    pub fn options(&self) -> &RecoveryOptions {
        &self.options
    }

    pub fn collect_candidates(&mut self) -> Result<RecoveryReport> {
        let mut report = collect_recovery_candidates(
            &mut self.reader,
            self.options.base_offset,
            &self.sb,
            &self.geometry,
            self.options.walk_mode,
        )?;

        if !self.options.enable_experimental {
            let mut filtered_candidates = Vec::new();
            for candidate in report.candidates {
                if candidate.is_experimental {
                    report.rejections.push(Rejection {
                        ino: Some(candidate.ino),
                        ag_number: candidate.ag_number,
                        reason: RejectionReason::InsufficientEvidence,
                        details: "experimental candidate skipped because experimental features are disabled".to_string(),
                    });
                } else {
                    filtered_candidates.push(candidate);
                }
            }
            report.candidates = filtered_candidates;

            // Recalculate summary counts
            let mut summary = RecoverySummary {
                total_inodes_scanned: report.summary.total_inodes_scanned,
                total_candidates: report.candidates.len(),
                total_rejections: report.rejections.len(),
                ..Default::default()
            };

            for c in &report.candidates {
                match c.candidate_class {
                    CandidateClass::UnlinkedChainResidue => summary.unlinked_chain_candidates += 1,
                    CandidateClass::FreedWithResidualExtents => {
                        summary.residual_extent_candidates += 1
                    }
                    CandidateClass::ZeroLinkAnomaly => summary.zero_link_candidates += 1,
                }
                match c.confidence {
                    RecoveryConfidence::High => summary.high_confidence += 1,
                    RecoveryConfidence::Medium => summary.medium_confidence += 1,
                    RecoveryConfidence::Low => summary.low_confidence += 1,
                }
            }
            report.summary = summary;
        }

        Ok(report)
    }

    pub fn read_candidate_content(&mut self, candidate: &RecoveryCandidate) -> Result<Vec<u8>> {
        let size = candidate
            .original_size
            .unwrap_or(candidate.observed_extent_bytes);
        let mut reader = ExtentReader::new(
            &mut self.reader,
            self.options.base_offset,
            &self.geometry,
            &candidate.extents.extents,
            size,
        );
        reader.read_all()
    }

    pub fn reader_for_candidate<'a>(
        &'a mut self,
        candidate: &RecoveryCandidate,
    ) -> ExtentReader<'a, R> {
        let size = candidate
            .original_size
            .unwrap_or(candidate.observed_extent_bytes);
        ExtentReader::new(
            &mut self.reader,
            self.options.base_offset,
            &self.geometry,
            &candidate.extents.extents,
            size,
        )
    }

    pub fn into_reader(self) -> R {
        self.reader
    }
}
