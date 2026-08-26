use std::collections::BTreeMap;

use crate::error::Result;
use crate::io::ImageRead;
use crate::xfs::ag::parse_agi;
use crate::xfs::alloc_records::collect_inode_allocation;
use crate::xfs::dinode::{Dinode, FileType, Timestamp, parse_dinode};
use crate::xfs::extents::{
    ExtentMap, ExtentState, ResidualConfidence, ResidualInterpretation, interpret_residual_extents,
    parse_data_fork,
};
use crate::xfs::inode_addr::{InodeLocation, NULLAGINO, absolute_inode, locate_inode};
use crate::xfs::inode_scan::{DiscoveryOptions, discover_inode_slots};
use crate::xfs::superblock::{CrcStatus, Geometry, Superblock};
use crate::xfs::{SlotState, WalkMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateClass {
    UnlinkedChainResidue,
    FreedWithResidualExtents,
    ZeroLinkAnomaly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMethod {
    XfsUnlinkedChain,
    XfsResidualExtents,
    XfsZeroLinkAnomaly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecoveryConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryEvidence {
    UnlinkedChain { bucket: u32, position: usize },
    FreeInodeSlot,
    FinobtVerified,
    ValidDinodeCore,
    ResidualExtentsFound { count: usize },
    ValidExtentBounds,
    ZeroLinkOnAllocated,
    CrcVerified,
    CrcMismatch,
    NonZeroGeneration(u32),
    ValidTimestamps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    LiveAllocatedInode,
    InvalidDinode,
    InvalidExtentMap,
    InvalidInodeLocation,
    CorruptUnlinkedChain,
    ResidualInterpretationFailed,
    UnsupportedFormat,
    InsufficientEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub ino: Option<u64>,
    pub ag_number: u32,
    pub reason: RejectionReason,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct RecoveryCandidate {
    pub ino: u64,
    pub location: InodeLocation,
    pub ag_number: u32,
    pub file_type: FileType,
    pub mode: u16,
    pub permissions: u16,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub generation: u32,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub crtime: Option<Timestamp>,
    pub original_size: Option<u64>,
    pub observed_extent_bytes: u64,
    pub extents: ExtentMap,
    pub method: RecoveryMethod,
    pub candidate_class: CandidateClass,
    pub confidence: RecoveryConfidence,
    pub evidence: Vec<RecoveryEvidence>,
    pub issues: Vec<String>,
    pub is_experimental: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RecoverySummary {
    pub total_inodes_scanned: usize,
    pub unlinked_chain_candidates: usize,
    pub residual_extent_candidates: usize,
    pub zero_link_candidates: usize,
    pub total_candidates: usize,
    pub total_rejections: usize,
    pub high_confidence: usize,
    pub medium_confidence: usize,
    pub low_confidence: usize,
}

#[derive(Debug, Clone)]
pub struct RecoveryReport {
    pub candidates: Vec<RecoveryCandidate>,
    pub rejections: Vec<Rejection>,
    pub summary: RecoverySummary,
}

pub fn classify_inode_candidate(
    dinode: &Dinode,
    block_size: u64,
    slot_state: Option<SlotState>,
    ext_map: Option<&ExtentMap>,
    residual: Option<&ResidualInterpretation>,
    unlinked_info: Option<(u32, usize)>,
) -> Option<RecoveryCandidate> {
    let mut evidence = Vec::new();
    let mut issues = Vec::new();

    evidence.push(RecoveryEvidence::ValidDinodeCore);
    if dinode.core.generation > 0 {
        evidence.push(RecoveryEvidence::NonZeroGeneration(dinode.core.generation));
    }
    if dinode.core.mtime.sec != 0 || dinode.core.ctime.sec != 0 {
        evidence.push(RecoveryEvidence::ValidTimestamps);
    }

    match dinode.core.crc_status {
        CrcStatus::Verified => evidence.push(RecoveryEvidence::CrcVerified),
        CrcStatus::Mismatch { stored, computed } => {
            evidence.push(RecoveryEvidence::CrcMismatch);
            issues.push(format!(
                "CRC mismatch: stored 0x{stored:08x}, computed 0x{computed:08x}"
            ));
        }
        CrcStatus::NotApplicable => {}
    }

    for iss in &dinode.core.issues {
        issues.push(format!("{iss:?}"));
    }

    // Branch 1: Unlinked Chain
    if let Some((bucket, position)) = unlinked_info {
        evidence.push(RecoveryEvidence::UnlinkedChain { bucket, position });
        let active_extents = ext_map.cloned().unwrap_or_else(|| ExtentMap {
            extents: Vec::new(),
            issues: Vec::new(),
        });

        for iss in &active_extents.issues {
            issues.push(format!("ExtentIssue: {iss:?}"));
        }

        let mut observed_bytes = 0u64;
        for e in &active_extents.extents {
            if e.state == ExtentState::Normal {
                observed_bytes =
                    observed_bytes.saturating_add(e.block_count.saturating_mul(block_size));
            }
        }

        let confidence = if issues.is_empty() {
            RecoveryConfidence::High
        } else if issues.len() <= 2 {
            RecoveryConfidence::Medium
        } else {
            RecoveryConfidence::Low
        };

        return Some(RecoveryCandidate {
            ino: dinode.location.ino,
            location: dinode.location,
            ag_number: dinode.location.ag_number,
            file_type: dinode.core.file_type,
            mode: dinode.core.mode,
            permissions: dinode.core.permissions,
            uid: dinode.core.uid,
            gid: dinode.core.gid,
            nlink: dinode.core.nlink,
            generation: dinode.core.generation,
            atime: dinode.core.atime,
            mtime: dinode.core.mtime,
            ctime: dinode.core.ctime,
            crtime: dinode.core.crtime,
            original_size: if dinode.core.size > 0 {
                Some(dinode.core.size)
            } else {
                None
            },
            observed_extent_bytes: observed_bytes,
            extents: active_extents,
            method: RecoveryMethod::XfsUnlinkedChain,
            candidate_class: CandidateClass::UnlinkedChainResidue,
            confidence,
            evidence,
            issues,
            is_experimental: false,
        });
    }

    // Branch 2: Free Inode with Residual Extents
    if slot_state == Some(SlotState::Free) {
        evidence.push(RecoveryEvidence::FreeInodeSlot);
        if let Some(res) = residual {
            evidence.push(RecoveryEvidence::ResidualExtentsFound {
                count: res.extents.len(),
            });
            if res.issues.is_empty() {
                evidence.push(RecoveryEvidence::ValidExtentBounds);
            } else {
                for iss in &res.issues {
                    issues.push(format!("ResidualExtentIssue: {iss:?}"));
                }
            }

            let mut observed_bytes = 0u64;
            for e in &res.extents {
                if e.state == ExtentState::Normal {
                    observed_bytes =
                        observed_bytes.saturating_add(e.block_count.saturating_mul(block_size));
                }
            }

            let confidence = if res.confidence == ResidualConfidence::Probable && issues.is_empty()
            {
                RecoveryConfidence::Medium
            } else {
                RecoveryConfidence::Low
            };

            return Some(RecoveryCandidate {
                ino: dinode.location.ino,
                location: dinode.location,
                ag_number: dinode.location.ag_number,
                file_type: dinode.core.file_type,
                mode: dinode.core.mode,
                permissions: dinode.core.permissions,
                uid: dinode.core.uid,
                gid: dinode.core.gid,
                nlink: dinode.core.nlink,
                generation: dinode.core.generation,
                atime: dinode.core.atime,
                mtime: dinode.core.mtime,
                ctime: dinode.core.ctime,
                crtime: dinode.core.crtime,
                original_size: None, // zeroed upon deletion
                observed_extent_bytes: observed_bytes,
                extents: ExtentMap {
                    extents: res.extents.clone(),
                    issues: res.issues.clone(),
                },
                method: RecoveryMethod::XfsResidualExtents,
                candidate_class: CandidateClass::FreedWithResidualExtents,
                confidence,
                evidence,
                issues,
                is_experimental: true,
            });
        }
    }

    // Branch 3: Zero-Link Anomaly on Allocated Inode
    if slot_state == Some(SlotState::Allocated)
        && dinode.core.nlink == 0
        && dinode.core.file_type != FileType::Unallocated
    {
        evidence.push(RecoveryEvidence::ZeroLinkOnAllocated);
        let active_extents = ext_map.cloned().unwrap_or_else(|| ExtentMap {
            extents: Vec::new(),
            issues: Vec::new(),
        });

        for iss in &active_extents.issues {
            issues.push(format!("ExtentIssue: {iss:?}"));
        }

        let mut observed_bytes = 0u64;
        for e in &active_extents.extents {
            if e.state == ExtentState::Normal {
                observed_bytes =
                    observed_bytes.saturating_add(e.block_count.saturating_mul(block_size));
            }
        }

        let confidence = if issues.is_empty() {
            RecoveryConfidence::Medium
        } else {
            RecoveryConfidence::Low
        };

        return Some(RecoveryCandidate {
            ino: dinode.location.ino,
            location: dinode.location,
            ag_number: dinode.location.ag_number,
            file_type: dinode.core.file_type,
            mode: dinode.core.mode,
            permissions: dinode.core.permissions,
            uid: dinode.core.uid,
            gid: dinode.core.gid,
            nlink: 0,
            generation: dinode.core.generation,
            atime: dinode.core.atime,
            mtime: dinode.core.mtime,
            ctime: dinode.core.ctime,
            crtime: dinode.core.crtime,
            original_size: if dinode.core.size > 0 {
                Some(dinode.core.size)
            } else {
                None
            },
            observed_extent_bytes: observed_bytes,
            extents: active_extents,
            method: RecoveryMethod::XfsZeroLinkAnomaly,
            candidate_class: CandidateClass::ZeroLinkAnomaly,
            confidence,
            evidence,
            issues,
            is_experimental: false,
        });
    }

    None
}

fn merge_candidate(existing: &mut RecoveryCandidate, incoming: RecoveryCandidate) {
    let rank = |c: CandidateClass| match c {
        CandidateClass::UnlinkedChainResidue => 3,
        CandidateClass::FreedWithResidualExtents => 2,
        CandidateClass::ZeroLinkAnomaly => 1,
    };

    if rank(incoming.candidate_class) > rank(existing.candidate_class) {
        existing.candidate_class = incoming.candidate_class;
        existing.method = incoming.method;
        existing.is_experimental = incoming.is_experimental;
        if incoming.original_size.is_some() {
            existing.original_size = incoming.original_size;
        }
        if !incoming.extents.is_empty() {
            existing.extents = incoming.extents;
            existing.observed_extent_bytes = incoming.observed_extent_bytes;
        }
    }

    if incoming.confidence > existing.confidence {
        existing.confidence = incoming.confidence;
    }

    for ev in incoming.evidence {
        if !existing.evidence.contains(&ev) {
            existing.evidence.push(ev);
        }
    }

    for iss in incoming.issues {
        if !existing.issues.contains(&iss) {
            existing.issues.push(iss);
        }
    }
}

pub fn collect_recovery_candidates(
    reader: &mut dyn ImageRead,
    fs_base_offset: u64,
    sb: &Superblock,
    geometry: &Geometry,
    walk_mode: WalkMode,
) -> Result<RecoveryReport> {
    let mut candidates_map: BTreeMap<u64, RecoveryCandidate> = BTreeMap::new();
    let mut rejections = Vec::new();
    let mut total_scanned = 0usize;
    let block_size = geometry.fs_block_bytes() as u64;

    for ag in 0..sb.ag_count {
        // Step 1: Traverse AGI unlinked buckets
        if let Ok(agi) = parse_agi(reader, fs_base_offset, sb, geometry, ag) {
            for (b_idx, &head_agino) in agi.unlinked_buckets.iter().enumerate() {
                if head_agino == NULLAGINO {
                    continue;
                }

                let mut cur_agino = head_agino;
                let mut position = 0usize;
                let mut visited_chain = Vec::new();

                while cur_agino != NULLAGINO {
                    if visited_chain.contains(&cur_agino) {
                        rejections.push(Rejection {
                            ino: absolute_inode(geometry, ag, cur_agino).ok(),
                            ag_number: ag,
                            reason: RejectionReason::CorruptUnlinkedChain,
                            details: format!("cycle detected in AG {ag} unlinked bucket {b_idx}"),
                        });
                        break;
                    }
                    if visited_chain.len() >= 65536 {
                        rejections.push(Rejection {
                            ino: absolute_inode(geometry, ag, cur_agino).ok(),
                            ag_number: ag,
                            reason: RejectionReason::CorruptUnlinkedChain,
                            details: format!(
                                "unlinked chain exceeded max depth in AG {ag} bucket {b_idx}"
                            ),
                        });
                        break;
                    }
                    visited_chain.push(cur_agino);

                    let abs_ino = match absolute_inode(geometry, ag, cur_agino) {
                        Ok(ino) => ino,
                        Err(e) => {
                            rejections.push(Rejection {
                                ino: None,
                                ag_number: ag,
                                reason: RejectionReason::InvalidInodeLocation,
                                details: format!(
                                    "invalid absolute inode from AG {ag} agino {cur_agino}: {e}"
                                ),
                            });
                            break;
                        }
                    };

                    let loc = match locate_inode(sb, geometry, abs_ino) {
                        Ok(l) => l,
                        Err(e) => {
                            rejections.push(Rejection {
                                ino: Some(abs_ino),
                                ag_number: ag,
                                reason: RejectionReason::InvalidInodeLocation,
                                details: format!("locate_inode failed for {abs_ino}: {e}"),
                            });
                            break;
                        }
                    };

                    let dinode = match parse_dinode(reader, fs_base_offset, sb, &loc) {
                        Ok(d) => d,
                        Err(e) => {
                            rejections.push(Rejection {
                                ino: Some(abs_ino),
                                ag_number: ag,
                                reason: RejectionReason::InvalidDinode,
                                details: format!("parse_dinode failed for {abs_ino}: {e}"),
                            });
                            break;
                        }
                    };

                    let ext_map =
                        parse_data_fork(reader, fs_base_offset, sb, geometry, &dinode).ok();
                    if let Some(candidate) = classify_inode_candidate(
                        &dinode,
                        block_size,
                        None,
                        ext_map.as_ref(),
                        None,
                        Some((b_idx as u32, position)),
                    ) {
                        candidates_map
                            .entry(abs_ino)
                            .and_modify(|existing| merge_candidate(existing, candidate.clone()))
                            .or_insert(candidate);
                    }

                    cur_agino = dinode.core.next_unlinked_raw;
                    position += 1;
                }
            }
        }

        // Step 2: Traverse inobt allocation map and discovered slots
        let inobt_map =
            match collect_inode_allocation(reader, fs_base_offset, sb, geometry, ag, walk_mode) {
                Ok(m) => m,
                Err(e) => {
                    rejections.push(Rejection {
                        ino: None,
                        ag_number: ag,
                        reason: RejectionReason::InsufficientEvidence,
                        details: format!("collect_inode_allocation failed in AG {ag}: {e}"),
                    });
                    continue;
                }
            };

        let slots =
            match discover_inode_slots(&inobt_map, sb, geometry, &DiscoveryOptions::default()) {
                Ok(s) => s,
                Err(e) => {
                    rejections.push(Rejection {
                        ino: None,
                        ag_number: ag,
                        reason: RejectionReason::InsufficientEvidence,
                        details: format!("discover_inode_slots failed in AG {ag}: {e}"),
                    });
                    continue;
                }
            };

        for slot in slots {
            total_scanned += 1;
            let abs_ino = slot.location.ino;

            let dinode = match parse_dinode(reader, fs_base_offset, sb, &slot.location) {
                Ok(d) => d,
                Err(e) => {
                    rejections.push(Rejection {
                        ino: Some(abs_ino),
                        ag_number: ag,
                        reason: RejectionReason::InvalidDinode,
                        details: format!("parse_dinode failed for slot {abs_ino}: {e}"),
                    });
                    continue;
                }
            };

            let residual = if slot.state == SlotState::Free {
                interpret_residual_extents(&dinode, geometry)
            } else {
                None
            };

            let ext_map = if slot.state == SlotState::Allocated {
                parse_data_fork(reader, fs_base_offset, sb, geometry, &dinode).ok()
            } else {
                None
            };

            if let Some(candidate) = classify_inode_candidate(
                &dinode,
                block_size,
                Some(slot.state),
                ext_map.as_ref(),
                residual.as_ref(),
                None,
            ) {
                candidates_map
                    .entry(abs_ino)
                    .and_modify(|existing| merge_candidate(existing, candidate.clone()))
                    .or_insert(candidate);
            } else if slot.state == SlotState::Allocated {
                rejections.push(Rejection {
                    ino: Some(abs_ino),
                    ag_number: ag,
                    reason: RejectionReason::LiveAllocatedInode,
                    details: format!(
                        "inode {abs_ino} is a live allocated inode with nlink {}",
                        dinode.core.nlink
                    ),
                });
            } else if slot.state == SlotState::Free {
                rejections.push(Rejection {
                    ino: Some(abs_ino),
                    ag_number: ag,
                    reason: RejectionReason::ResidualInterpretationFailed,
                    details: format!("free inode {abs_ino} has no valid residual extents"),
                });
            }
        }
    }

    let candidates: Vec<RecoveryCandidate> = candidates_map.into_values().collect();

    let mut summary = RecoverySummary {
        total_inodes_scanned: total_scanned,
        total_candidates: candidates.len(),
        total_rejections: rejections.len(),
        ..Default::default()
    };

    for c in &candidates {
        match c.candidate_class {
            CandidateClass::UnlinkedChainResidue => summary.unlinked_chain_candidates += 1,
            CandidateClass::FreedWithResidualExtents => summary.residual_extent_candidates += 1,
            CandidateClass::ZeroLinkAnomaly => summary.zero_link_candidates += 1,
        }
        match c.confidence {
            RecoveryConfidence::High => summary.high_confidence += 1,
            RecoveryConfidence::Medium => summary.medium_confidence += 1,
            RecoveryConfidence::Low => summary.low_confidence += 1,
        }
    }

    Ok(RecoveryReport {
        candidates,
        rejections,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::crc32c::crc32c_with_zeroed_range;
    use crate::xfs::dinode::{DINODE_V3_CORE_SIZE, DataForkFormat, INODE_MAGIC, parse_dinode_core};
    use crate::xfs::extents::{FileExtent, encode_bmbt_record};

    fn sample_dinode(format: DataForkFormat, nlink: u32, next_unlinked: u32, size: u64) -> Dinode {
        let isize = 512;
        let mut buf = vec![0u8; isize];
        buf[0..2].copy_from_slice(&INODE_MAGIC.to_be_bytes());
        buf[2..4].copy_from_slice(&0o100644u16.to_be_bytes());
        buf[4] = 3;
        buf[5] = format.to_u8();
        buf[16..20].copy_from_slice(&nlink.to_be_bytes());
        buf[56..64].copy_from_slice(&size.to_be_bytes());
        buf[84..88].copy_from_slice(&next_unlinked.to_be_bytes());

        let crc = crc32c_with_zeroed_range(&buf, 100, 4);
        buf[100..104].copy_from_slice(&crc.to_le_bytes());

        let core = parse_dinode_core(&buf, isize).unwrap();
        Dinode {
            location: InodeLocation {
                ino: 128,
                ag_number: 0,
                ag_block: 16,
                slot: 0,
                byte_offset: 65536,
            },
            core,
            raw: buf,
        }
    }

    #[test]
    fn classifies_unlinked_chain_candidate() {
        let dinode = sample_dinode(DataForkFormat::Extents, 0, NULLAGINO, 4096);
        let candidate = classify_inode_candidate(
            &dinode,
            4096,
            Some(SlotState::Free),
            None,
            None,
            Some((3, 0)),
        )
        .expect("must classify unlinked candidate");

        assert_eq!(
            candidate.candidate_class,
            CandidateClass::UnlinkedChainResidue
        );
        assert_eq!(candidate.method, RecoveryMethod::XfsUnlinkedChain);
        assert_eq!(candidate.confidence, RecoveryConfidence::High);
        assert!(!candidate.is_experimental);
        assert_eq!(candidate.original_size, Some(4096));
        assert!(candidate.evidence.iter().any(|e| matches!(
            e,
            RecoveryEvidence::UnlinkedChain {
                bucket: 3,
                position: 0
            }
        )));
    }

    #[test]
    fn classifies_freed_with_residual_extents() {
        let mut dinode = sample_dinode(DataForkFormat::Extents, 0, NULLAGINO, 0);
        let ext = FileExtent {
            logical_start: 0,
            physical_start: 100,
            block_count: 5,
            state: ExtentState::Normal,
        };
        dinode.raw[DINODE_V3_CORE_SIZE..DINODE_V3_CORE_SIZE + 16]
            .copy_from_slice(&encode_bmbt_record(&ext));
        let crc = crc32c_with_zeroed_range(&dinode.raw, 100, 4);
        dinode.raw[100..104].copy_from_slice(&crc.to_le_bytes());
        dinode.core = parse_dinode_core(&dinode.raw, 512).unwrap();

        let residual = ResidualInterpretation {
            extents: vec![ext],
            confidence: ResidualConfidence::Probable,
            issues: Vec::new(),
        };

        let candidate = classify_inode_candidate(
            &dinode,
            4096,
            Some(SlotState::Free),
            None,
            Some(&residual),
            None,
        )
        .expect("must classify residual candidate");

        assert_eq!(
            candidate.candidate_class,
            CandidateClass::FreedWithResidualExtents
        );
        assert_eq!(candidate.method, RecoveryMethod::XfsResidualExtents);
        assert_eq!(candidate.confidence, RecoveryConfidence::Medium);
        assert!(candidate.is_experimental);
        assert_eq!(candidate.original_size, None); // size is zeroed upon deletion
        assert_eq!(candidate.observed_extent_bytes, 5 * 4096);
    }

    #[test]
    fn classifies_zero_link_anomaly() {
        let dinode = sample_dinode(DataForkFormat::Extents, 0, NULLAGINO, 8192);
        let candidate =
            classify_inode_candidate(&dinode, 4096, Some(SlotState::Allocated), None, None, None)
                .expect("must classify zero-link anomaly");

        assert_eq!(candidate.candidate_class, CandidateClass::ZeroLinkAnomaly);
        assert_eq!(candidate.method, RecoveryMethod::XfsZeroLinkAnomaly);
        assert_eq!(candidate.confidence, RecoveryConfidence::Medium);
        assert!(!candidate.is_experimental);
        assert_eq!(candidate.original_size, Some(8192));
    }

    #[test]
    fn rejects_live_allocated_inode() {
        let dinode = sample_dinode(DataForkFormat::Extents, 1, NULLAGINO, 8192);
        let candidate =
            classify_inode_candidate(&dinode, 4096, Some(SlotState::Allocated), None, None, None);
        assert!(candidate.is_none());
    }

    #[test]
    fn merges_evidence_and_selects_strongest_class() {
        let dinode = sample_dinode(DataForkFormat::Extents, 0, NULLAGINO, 4096);
        let c1 =
            classify_inode_candidate(&dinode, 4096, Some(SlotState::Allocated), None, None, None)
                .unwrap(); // ZeroLinkAnomaly

        let c2 = classify_inode_candidate(
            &dinode,
            4096,
            Some(SlotState::Free),
            None,
            None,
            Some((0, 0)),
        )
        .unwrap(); // UnlinkedChainResidue

        let mut merged = c1;
        merge_candidate(&mut merged, c2);

        assert_eq!(merged.candidate_class, CandidateClass::UnlinkedChainResidue);
        assert_eq!(merged.method, RecoveryMethod::XfsUnlinkedChain);
        assert_eq!(merged.confidence, RecoveryConfidence::High);
        assert!(
            merged
                .evidence
                .contains(&RecoveryEvidence::ZeroLinkOnAllocated)
        );
        assert!(merged.evidence.contains(&RecoveryEvidence::UnlinkedChain {
            bucket: 0,
            position: 0
        }));
    }

    #[test]
    fn crc_mismatch_downgrades_confidence() {
        let mut dinode = sample_dinode(DataForkFormat::Extents, 0, NULLAGINO, 4096);
        // Corrupt CRC
        dinode.raw[100..104].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        dinode.core = parse_dinode_core(&dinode.raw, 512).unwrap();

        let candidate = classify_inode_candidate(
            &dinode,
            4096,
            Some(SlotState::Free),
            None,
            None,
            Some((0, 0)),
        )
        .expect("must classify despite CRC mismatch");

        // High confidence downgraded to Medium due to CRC mismatch issue
        assert_eq!(candidate.confidence, RecoveryConfidence::Medium);
        assert!(candidate.evidence.contains(&RecoveryEvidence::CrcMismatch));
        assert!(!candidate.issues.is_empty());
    }
}
