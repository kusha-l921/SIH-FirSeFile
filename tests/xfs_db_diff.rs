use std::process::Command;
use xfs_recovery_engine::{CrcStatus, FileImage, Superblock};

fn xfs_db_available() -> bool {
    Command::new("xfs_db")
        .arg("-V")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn xfs_db_field(text: &str, field: &str) -> Option<String> {
    for line in text.lines() {
        let mut parts = line.split('=');
        if parts.next()?.trim() == field {
            return parts.next().map(|v| v.trim().to_string());
        }
    }
    None
}

#[test]
#[ignore]
fn differential_against_xfs_db_fixture() {
    let Some(image) = std::env::var_os("XRE_TEST_IMAGE") else {
        eprintln!("skipped: set XRE_TEST_IMAGE=<raw xfs image path>");
        return;
    };
    if !xfs_db_available() {
        eprintln!("skipped: xfs_db not installed");
        return;
    }

    let mut img = FileImage::open(&image).expect("open fixture image read-only");
    let (sb, geo) = Superblock::parse(&mut img, 0).expect("parse superblock");

    let out = Command::new("xfs_db")
        .args(["-r", "-f"])
        .arg(&image)
        .args(["-c", "sb 0", "-c", "print"])
        .output()
        .expect("run xfs_db");
    assert!(out.status.success(), "xfs_db failed");
    let text = String::from_utf8_lossy(&out.stdout);

    for (field, ours) in [
        ("blocksize", sb.block_size.to_string()),
        ("agblocks", sb.ag_blocks.to_string()),
        ("agcount", sb.ag_count.to_string()),
        ("inodesize", sb.inode_size.to_string()),
        ("dblocks", sb.dblocks.to_string()),
        ("rootino", sb.root_inode.to_string()),
        ("versionnum", format!("{:x}", sb.version_num_raw)),
    ] {
        let theirs =
            xfs_db_field(&text, &field).unwrap_or_else(|| panic!("xfs_db printed no {field}"));
        let theirs = theirs.trim_start_matches("0x");
        assert_eq!(ours, theirs, "field {field} mismatch");
    }

    let uuid_xfs = xfs_db_field(&text, "uuid").expect("xfs_db printed no uuid");
    let ours: String = sb.uuid.iter().map(|byte| format!("{byte:02x}")).collect();
    let theirs: String = uuid_xfs.chars().filter(|c| *c != '-').collect();
    assert_eq!(ours, theirs, "uuid mismatch");

    assert_eq!(sb.crc_status, CrcStatus::Verified, "v5 CRC must verify");
    assert!(sb.version5());
    assert!(sb.finobt_enabled());
    assert!(sb.sparse_inodes_enabled());
    assert!(sb.nrext64_enabled());
    assert!(
        sb.issues.is_empty(),
        "unexpected parser issues on stock mkfs image: {:?}",
        sb.issues
    );

    eprintln!("differential ok: fs total {} bytes", geo.total_bytes());
}

#[test]
#[ignore]
fn differential_ag_headers_against_xfs_db_fixture() {
    use xfs_recovery_engine::{parse_agf, parse_agfl, parse_agi};

    let Some(image) = std::env::var_os("XRE_TEST_IMAGE") else {
        eprintln!("skipped: set XRE_TEST_IMAGE=<raw xfs image path>");
        return;
    };
    if !xfs_db_available() {
        eprintln!("skipped: xfs_db not installed");
        return;
    }

    let mut img = FileImage::open(&image).expect("open fixture image read-only");
    let (sb, geo) = Superblock::parse(&mut img, 0).expect("parse superblock");

    let out = Command::new("xfs_db")
        .args(["-r", "-f"])
        .arg(&image)
        .output()
        .expect("run xfs_db");
    assert!(out.status.success());

    for ag in 0..sb.ag_count {
        let agf = parse_agf(&mut img, 0, &sb, &geo, ag).expect("agf");
        let agi = parse_agi(&mut img, 0, &sb, &geo, ag).expect("agi");
        let agfl = parse_agfl(&mut img, 0, &sb, &geo, ag, &agf).expect("agfl");

        let agf_out = Command::new("xfs_db")
            .args(["-r", "-f"])
            .arg(&image)
            .args(["-c", &format!("agf {ag}"), "-c", "print"])
            .output()
            .expect("run xfs_db agf");
        let text = String::from_utf8_lossy(&agf_out.stdout);
        for (field, ours) in [
            ("seqno", agf.seqno.to_string()),
            ("length", agf.length_blocks.to_string()),
            ("freeblks", agf.free_blocks.to_string()),
            ("longest", agf.longest_free.to_string()),
            ("bnoroot", agf.bnobt_root.to_string()),
            ("cntroot", agf.cntbt_root.to_string()),
            ("bnolevel", agf.bnobt_level.to_string()),
            ("cntlevel", agf.cntbt_level.to_string()),
            ("flfirst", agf.flfirst.to_string()),
            ("fllast", agf.fllast.to_string()),
            ("flcount", agf.flcount.to_string()),
        ] {
            let theirs =
                xfs_db_field(&text, &field).unwrap_or_else(|| panic!("xfs_db printed no {field}"));
            assert_eq!(ours, theirs, "agf {ag} field {field} mismatch");
        }

        let agi_out = Command::new("xfs_db")
            .args(["-r", "-f"])
            .arg(&image)
            .args(["-c", &format!("agi {ag}"), "-c", "print"])
            .output()
            .expect("run xfs_db agi");
        let text = String::from_utf8_lossy(&agi_out.stdout);
        for (field, ours) in [
            ("count", agi.inode_count.to_string()),
            ("freecount", agi.free_inode_count.to_string()),
            ("root", agi.inobt_root.to_string()),
            ("level", agi.inobt_level.to_string()),
        ] {
            let theirs =
                xfs_db_field(&text, &field).unwrap_or_else(|| panic!("xfs_db printed no {field}"));
            assert_eq!(ours, theirs, "agi {ag} field {field} mismatch");
        }

        assert_eq!(
            agf.crc_status,
            CrcStatus::Verified,
            "AGF {ag} CRC must verify on stock image"
        );
        assert_eq!(
            agi.crc_status,
            CrcStatus::Verified,
            "AGI {ag} CRC must verify on stock image"
        );
        assert_eq!(
            agfl.crc_status,
            CrcStatus::Verified,
            "AGFL {ag} CRC must verify on stock image"
        );
        assert_eq!(agfl.entries.len() as u32, agf.flcount);
        assert!(
            agf.issues.is_empty() && agi.issues.is_empty() && agfl.issues.is_empty(),
            "unexpected issues on stock image ag {ag}: {:?} {:?} {:?}",
            agf.issues,
            agi.issues,
            agfl.issues
        );
        eprintln!(
            "ag {ag}: freeblks={} flcount={}",
            agf.free_blocks, agf.flcount
        );
    }
}

#[test]
#[ignore]
fn differential_alloc_btrees_against_xfs_db_fixture() {
    use xfs_recovery_engine::{AllocBtreeKind, WalkMode, parse_agf, parse_agi, walk_alloc_btree};

    let Some(image) = std::env::var_os("XRE_TEST_IMAGE") else {
        eprintln!("skipped: set XRE_TEST_IMAGE=<raw xfs image path>");
        return;
    };
    if !xfs_db_available() {
        eprintln!("skipped: xfs_db not installed");
        return;
    }

    let mut img = FileImage::open(&image).expect("open fixture image read-only");
    let (sb, geo) = Superblock::parse(&mut img, 0).expect("parse superblock");

    let tree_dump = |cmds: &[&str]| {
        let out = Command::new("xfs_db")
            .args(["-r", "-f"])
            .arg(&image)
            .args(
                cmds.iter()
                    .flat_map(|c| vec!["-c".to_string(), c.to_string()]),
            )
            .args(["-c", "print"])
            .output()
            .expect("run xfs_db");
        assert!(out.status.success(), "xfs_db tree dump failed");
        String::from_utf8_lossy(&out.stdout).to_string()
    };

    let root_bb_level = |height: u32| -> u32 {
        assert!(height >= 1, "tree height zero makes no sense");
        height - 1
    };

    for ag in 0..sb.ag_count {
        let agf = parse_agf(&mut img, 0, &sb, &geo, ag).expect("agf");
        let agi = parse_agi(&mut img, 0, &sb, &geo, ag).expect("agi");

        for (kind, root, height) in [
            (
                AllocBtreeKind::Bnobt,
                agf.bnobt_root,
                root_bb_level(agf.bnobt_level as u32),
            ),
            (
                AllocBtreeKind::Cntbt,
                agf.cntbt_root,
                root_bb_level(agf.cntbt_level as u32),
            ),
        ] {
            let mut found = Vec::new();
            let out = walk_alloc_btree(
                &mut img,
                0,
                &sb,
                &geo,
                ag,
                root,
                height,
                kind,
                WalkMode::Strict,
                &mut |view| {
                    let start =
                        u32::from_be_bytes([view.raw[0], view.raw[1], view.raw[2], view.raw[3]]);
                    let count =
                        u32::from_be_bytes([view.raw[4], view.raw[5], view.raw[6], view.raw[7]]);
                    found.push((start as u64, count as u64));
                    Ok(())
                },
            )
            .unwrap_or_else(|e| panic!("{kind:?} ag {ag} walk failed: {e}"));
            assert!(out.issues.is_empty(), "{kind:?} ag {ag}: {:?}", out.issues);
            assert!(!out.records.is_empty(), "{kind:?} ag {ag} empty");

            let type_name = match kind {
                AllocBtreeKind::Bnobt => "bnobt",
                _ => "cntbt",
            };
            let abs_fsb = ag as u64 * geo.ag_blocks() as u64 + root as u64;
            let typed = tree_dump(&[&format!("fsblock {abs_fsb}"), &format!("type {type_name}")]);
            let expected = parse_pairs(&typed);
            assert_eq!(
                found, expected,
                "{kind:?} ag {ag} records differ from xfs_db"
            );
        }

        let mut startinos = Vec::new();
        let out = walk_alloc_btree(
            &mut img,
            0,
            &sb,
            &geo,
            ag,
            agi.inobt_root,
            root_bb_level(agi.inobt_level as u32),
            AllocBtreeKind::Inobt,
            WalkMode::Strict,
            &mut |view| {
                startinos.push(u32::from_be_bytes([
                    view.raw[0],
                    view.raw[1],
                    view.raw[2],
                    view.raw[3],
                ]));
                Ok(())
            },
        )
        .expect("inobt walk");
        assert!(out.issues.is_empty());

        let abs_ino = ag as u64 * geo.ag_blocks() as u64 + agi.inobt_root as u64;
        let dump = tree_dump(&[&format!("fsblock {abs_ino}"), "type inobt"]);
        let expected: Vec<u32> = parse_inobt_startinos(&dump);
        assert_eq!(startinos, expected, "inobt ag {ag} differs from xfs_db");

        eprintln!("ag {ag}: bno/cnt/inobt traversals match xfs_db exactly");
    }
}

fn parse_pairs(text: &str) -> Vec<(u64, u64)> {
    text.lines()
        .filter_map(|line| {
            let bracket = line.trim().strip_prefix(|c: char| c.is_ascii_digit())?;
            let inner = bracket.strip_prefix(':')?.trim().strip_prefix('[')?;
            let inner = inner.strip_suffix(']')?;
            let mut parts = inner.split(',');
            let a = parts.next()?.trim().parse().ok()?;
            let b = parts.next()?.trim().parse().ok()?;
            Some((a, b))
        })
        .collect()
}

fn parse_inobt_startinos(text: &str) -> Vec<u32> {
    text.lines()
        .filter_map(|line| {
            let bracket = line.trim().strip_prefix(|c: char| c.is_ascii_digit())?;
            let inner = bracket.strip_prefix(':')?.trim().strip_prefix('[')?;
            let inner = inner.strip_suffix(']')?;
            let first = inner.split(',').next()?.trim();
            first.parse().ok()
        })
        .collect()
}

#[test]
#[ignore]
fn differential_allocation_records_against_xfs_db_fixture() {
    use xfs_recovery_engine::{WalkMode, collect_free_space, collect_inode_allocation};

    let Some(image) = std::env::var_os("XRE_TEST_IMAGE") else {
        eprintln!("skipped: set XRE_TEST_IMAGE=<raw xfs image path>");
        return;
    };
    if !xfs_db_available() {
        eprintln!("skipped: xfs_db not installed");
        return;
    }

    let mut img = FileImage::open(&image).expect("open fixture image read-only");
    let (sb, geo) = Superblock::parse(&mut img, 0).expect("parse superblock");

    let tree_recs = |cmds: &[&str]| -> Vec<(u64, u64)> {
        let out = Command::new("xfs_db")
            .args(["-r", "-f"])
            .arg(&image)
            .args(
                cmds.iter()
                    .flat_map(|c| vec!["-c".to_string(), c.to_string()]),
            )
            .args(["-c", "print"])
            .output()
            .expect("run xfs_db");
        let text = String::from_utf8_lossy(&out.stdout);
        parse_pairs(&text)
    };

    for ag in 0..sb.ag_count {
        let space = collect_free_space(&mut img, 0, &sb, &geo, ag, WalkMode::Strict)
            .unwrap_or_else(|e| panic!("free-space ag {ag}: {e}"));
        assert!(space.issues.is_empty(), "ag {ag}: {:?}", space.issues);

        let agf_abs = ag as u64 * geo.ag_blocks() as u64;
        let bno_expect = tree_recs(&[&format!("fsblock {}", agf_abs + 1), "type bnobt"]);
        let cnt_expect = tree_recs(&[&format!("fsblock {}", agf_abs + 2), "type cntbt"]);

        let ours_bno: Vec<(u64, u64)> = space
            .bno_extents
            .iter()
            .map(|e| (e.startblock as u64, e.blockcount as u64))
            .collect();
        let ours_cnt: Vec<(u64, u64)> = space
            .cnt_extents
            .iter()
            .map(|e| (e.startblock as u64, e.blockcount as u64))
            .collect();
        assert_eq!(ours_bno, bno_expect, "bnobt ag {ag} extents differ");
        assert_eq!(ours_cnt, cnt_expect, "cntbt ag {ag} extents differ");
        assert!(
            space.sums_match_agf(),
            "ag {ag}: sum(cnt)={} vs AGF freeblks={}",
            space.cnt_total_blocks(),
            space.agf_free_blocks
        );

        let map = collect_inode_allocation(&mut img, 0, &sb, &geo, ag, WalkMode::Strict)
            .unwrap_or_else(|e| panic!("inode allocation ag {ag}: {e}"));
        assert!(map.issues.is_empty(), "ag {ag}: {:?}", map.issues);

        eprintln!(
            "ag {ag}: bno={} cnt={} extents match xfs_db; freeblks={}; inode chunks={}",
            ours_bno.len(),
            ours_cnt.len(),
            space.agf_free_blocks,
            map.chunk_count()
        );
    }
}

#[test]
#[ignore]
fn differential_inode_discovery_against_xfs_db_fixture() {
    use xfs_recovery_engine::{
        DiscoveryOptions, ImageRead as _, SlotState, WalkMode, collect_free_space,
        collect_inode_allocation, discover_inode_slots, locate_inode,
    };

    let Some(image) = std::env::var_os("XRE_TEST_IMAGE") else {
        eprintln!("skipped: set XRE_TEST_IMAGE=<raw xfs image path>");
        return;
    };
    if !xfs_db_available() {
        eprintln!("skipped: xfs_db not installed");
        return;
    }

    let mut img = FileImage::open(&image).expect("open fixture image read-only");
    let (sb, geo) = Superblock::parse(&mut img, 0).expect("parse superblock");

    for ag in 0..sb.ag_count {
        let map = collect_inode_allocation(&mut img, 0, &sb, &geo, ag, WalkMode::Strict)
            .unwrap_or_else(|e| panic!("inode map ag {ag}: {e}"));
        let found =
            discover_inode_slots(&map, &sb, &geo, &DiscoveryOptions::default()).expect("discovery");

        let allocated = found
            .iter()
            .filter(|d| d.state == SlotState::Allocated)
            .count();
        assert_eq!(allocated as u64, map.allocated_inodes());
        assert_eq!((found.len() - allocated) as u64, map.free_inodes());
        assert_eq!(
            found.len() as u64,
            map.iter_chunks().map(|r| r.inode_count as u64).sum::<u64>()
        );

        for d in found.iter().step_by(97) {
            assert_ne!(d.location.byte_offset, 0);
            let ag_check = geo
                .ag_no_of_ino(d.location.ino)
                .expect("ag of discovered inode");
            assert_eq!(ag_check, d.location.ag_number);
        }

        if ag == 0 {
            let root_loc = locate_inode(&sb, &geo, sb.root_inode).expect("root location");
            assert_eq!(root_loc.ag_number, 0);

            let mut magic = [0u8; 2];
            img.read_at(root_loc.byte_offset, &mut magic)
                .expect("read inode magic");
            assert_eq!(&magic, b"IN", "located root inode lacks IN magic on disk");

            let out = Command::new("xfs_db")
                .args(["-r", "-f"])
                .arg(&image)
                .args([
                    "-c",
                    &format!("inode {}", sb.root_inode),
                    "-c",
                    "print core.magic",
                ])
                .output()
                .expect("run xfs_db");
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(
                text.contains("core.magic = 0x494e"),
                "xfs_db disagrees about root inode: {text}"
            );
        }

        let space =
            collect_free_space(&mut img, 0, &sb, &geo, ag, WalkMode::Strict).expect("space");
        let _ = space;

        eprintln!(
            "ag {ag}: chunks={} discovered={} allocated={free_hint}",
            map.chunk_count(),
            found.len(),
            free_hint = allocated
        );
    }
}

#[test]
#[ignore]
fn differential_dinode_parsing_against_xfs_db_fixture() {
    use xfs_recovery_engine::{
        CrcStatus, DiscoveryOptions, FileType, SlotState, WalkMode, collect_inode_allocation,
        discover_inode_slots, parse_dinode,
    };

    let Some(image) = std::env::var_os("XRE_TEST_IMAGE") else {
        eprintln!("skipped: set XRE_TEST_IMAGE=<raw xfs image path>");
        return;
    };
    if !xfs_db_available() {
        eprintln!("skipped: xfs_db not installed");
        return;
    }

    let mut img = FileImage::open(&image).expect("open fixture image read-only");
    let (sb, geo) = Superblock::parse(&mut img, 0).expect("parse superblock");

    for ag in 0..sb.ag_count {
        let map = collect_inode_allocation(&mut img, 0, &sb, &geo, ag, WalkMode::Strict)
            .unwrap_or_else(|e| panic!("inode map ag {ag}: {e}"));
        let found =
            discover_inode_slots(&map, &sb, &geo, &DiscoveryOptions::default()).expect("discovery");

        for d in found.iter().filter(|d| d.state == SlotState::Allocated) {
            let dinode = parse_dinode(&mut img, 0, &sb, &d.location)
                .unwrap_or_else(|e| panic!("parse dinode {} failed: {e}", d.location.ino));

            assert_eq!(dinode.core.magic, 0x494E);
            if sb.version5() {
                assert_eq!(dinode.core.version, 3);
                assert_eq!(
                    dinode.core.crc_status,
                    CrcStatus::Verified,
                    "inode {} CRC must verify",
                    d.location.ino
                );
                assert_eq!(dinode.core.ino, Some(d.location.ino));
                assert_eq!(dinode.core.uuid, Some(sb.uuid));
            } else {
                assert!(dinode.core.version <= 2);
                assert_eq!(dinode.core.crc_status, CrcStatus::NotApplicable);
            }

            let out = Command::new("xfs_db")
                .args(["-r", "-f"])
                .arg(&image)
                .args(["-c", &format!("inode {}", d.location.ino), "-c", "print"])
                .output()
                .expect("run xfs_db inode print");
            assert!(out.status.success(), "xfs_db inode print failed");
            let text = String::from_utf8_lossy(&out.stdout);

            let mode_str = xfs_db_field(&text, "core.mode").expect("core.mode");
            let mode_val = u16::from_str_radix(mode_str.trim_start_matches('0'), 8).unwrap_or(0);
            assert_eq!(
                dinode.core.mode, mode_val,
                "inode {} mode mismatch",
                d.location.ino
            );

            let size_str = xfs_db_field(&text, "core.size").expect("core.size");
            let size_val: u64 = size_str.parse().expect("parse size");
            assert_eq!(
                dinode.core.size, size_val,
                "inode {} size mismatch",
                d.location.ino
            );

            let nblocks_str = xfs_db_field(&text, "core.nblocks").expect("core.nblocks");
            let nblocks_val: u64 = nblocks_str.parse().expect("parse nblocks");
            assert_eq!(
                dinode.core.nblocks, nblocks_val,
                "inode {} nblocks mismatch",
                d.location.ino
            );

            let nextents_str = xfs_db_field(&text, "core.nextents").expect("core.nextents");
            let nextents_val: u64 = nextents_str.parse().expect("parse nextents");
            assert_eq!(
                dinode.core.nextents, nextents_val,
                "inode {} nextents mismatch",
                d.location.ino
            );

            let gen_str = xfs_db_field(&text, "core.gen").expect("core.gen");
            let gen_val: u32 = gen_str.parse().expect("parse gen");
            assert_eq!(
                dinode.core.generation, gen_val,
                "inode {} gen mismatch",
                d.location.ino
            );

            if dinode.core.is_dir() {
                assert_eq!(dinode.core.file_type, FileType::Directory);
            } else if dinode.core.is_file() {
                assert_eq!(dinode.core.file_type, FileType::RegularFile);
            }

            if let Some(format_str) = xfs_db_field(&text, "core.format") {
                let fmt_val = format_str
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .parse::<u8>()
                    .unwrap_or(255);
                assert_eq!(
                    dinode.core.format.to_u8(),
                    fmt_val,
                    "inode {} format mismatch",
                    d.location.ino
                );
            }
        }
    }
}

fn parse_xfs_db_bmap(text: &str) -> Vec<(u64, u64, u64, u8)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("data offset") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let mut offset = None;
            let mut startblock = None;
            let mut count = None;
            let mut flag = 0u8;

            let mut i = 0;
            while i < parts.len() {
                if parts[i] == "offset" && i + 1 < parts.len() {
                    offset = parts[i + 1].parse::<u64>().ok();
                    i += 2;
                } else if parts[i] == "startblock" && i + 1 < parts.len() {
                    startblock = parts[i + 1].parse::<u64>().ok();
                    i += 2;
                } else if parts[i] == "count" && i + 1 < parts.len() {
                    count = parts[i + 1].parse::<u64>().ok();
                    i += 2;
                } else if parts[i] == "flag" && i + 1 < parts.len() {
                    flag = parts[i + 1].parse::<u8>().unwrap_or(0);
                    i += 2;
                } else {
                    i += 1;
                }
            }

            if let (Some(o), Some(sb), Some(c)) = (offset, startblock, count) {
                out.push((o, sb, c, flag));
            }
        }
    }
    out
}

#[test]
#[ignore]
fn differential_extent_extraction_against_xfs_db_fixture() {
    use xfs_recovery_engine::{
        DataForkFormat, DiscoveryOptions, ExtentReader, ExtentState, FileType, SlotState, WalkMode,
        collect_inode_allocation, discover_inode_slots, parse_data_fork, parse_dinode,
    };

    let Some(image) = std::env::var_os("XRE_TEST_IMAGE") else {
        eprintln!("skipped: set XRE_TEST_IMAGE=<raw xfs image path>");
        return;
    };
    if !xfs_db_available() {
        eprintln!("skipped: xfs_db not installed");
        return;
    }

    let mut file = FileImage::open(&image).expect("open image");
    let (sb, geo) = Superblock::parse(&mut file, 0).expect("parse sb");

    for ag in 0..sb.ag_count {
        let map = collect_inode_allocation(&mut file, 0, &sb, &geo, ag, WalkMode::Strict)
            .unwrap_or_else(|e| panic!("collect inobt ag {ag}: {e}"));
        let found = discover_inode_slots(&map, &sb, &geo, &DiscoveryOptions::default())
            .expect("discover slots");

        for d in found.iter().filter(|d| d.state == SlotState::Allocated) {
            let dinode = parse_dinode(&mut file, 0, &sb, &d.location).expect("parse dinode");
            if dinode.core.format != DataForkFormat::Extents
                && dinode.core.format != DataForkFormat::Btree
            {
                continue;
            }

            let ext_map =
                parse_data_fork(&mut file, 0, &sb, &geo, &dinode).expect("parse data fork");

            let out = std::process::Command::new("xfs_db")
                .args(["-r", "-f"])
                .arg(&image)
                .args(["-c", &format!("inode {}", d.location.ino), "-c", "bmap"])
                .output()
                .expect("run xfs_db bmap");

            assert!(out.status.success(), "xfs_db bmap failed");
            let text = String::from_utf8_lossy(&out.stdout);
            let expected_bmaps = parse_xfs_db_bmap(&text);

            assert_eq!(
                ext_map.extents.len(),
                expected_bmaps.len(),
                "inode {} extent count mismatch",
                d.location.ino
            );

            for (i, (exp_off, exp_sb, exp_cnt, exp_flag)) in expected_bmaps.into_iter().enumerate()
            {
                let actual = &ext_map.extents[i];
                assert_eq!(
                    actual.logical_start, exp_off,
                    "inode {} extent {} logical_start mismatch",
                    d.location.ino, i
                );
                assert_eq!(
                    actual.physical_start, exp_sb,
                    "inode {} extent {} physical_start mismatch",
                    d.location.ino, i
                );
                assert_eq!(
                    actual.block_count, exp_cnt,
                    "inode {} extent {} block_count mismatch",
                    d.location.ino, i
                );

                let expected_state = if exp_flag != 0 {
                    ExtentState::Unwritten
                } else {
                    ExtentState::Normal
                };
                assert_eq!(
                    actual.state, expected_state,
                    "inode {} extent {} state mismatch",
                    d.location.ino, i
                );
            }

            if dinode.core.file_type == FileType::RegularFile && dinode.core.size > 0 {
                let mut reader =
                    ExtentReader::new(&mut file, 0, &geo, &ext_map.extents, dinode.core.size);
                let content = reader.read_all().expect("read content");
                assert_eq!(content.len() as u64, dinode.core.size);
            }
        }
    }
}

#[test]
#[ignore]
fn differential_recovery_candidates_against_fixture() {
    use xfs_recovery_engine::{
        CandidateClass, RecoveryMethod, WalkMode, collect_recovery_candidates,
    };

    let Some(image) = std::env::var_os("XRE_TEST_IMAGE") else {
        eprintln!("skipped: set XRE_TEST_IMAGE=<raw xfs image path>");
        return;
    };
    if !xfs_db_available() {
        eprintln!("skipped: xfs_db not installed");
        return;
    }

    let mut file = FileImage::open(&image).expect("open image");
    let (sb, geo) = Superblock::parse(&mut file, 0).expect("parse sb");

    let report = collect_recovery_candidates(&mut file, 0, &sb, &geo, WalkMode::Strict)
        .expect("collect recovery candidates");

    assert!(report.summary.total_inodes_scanned > 0);
    assert_eq!(
        report.candidates.len(),
        report.summary.total_candidates,
        "summary total_candidates mismatch"
    );
    assert_eq!(
        report.rejections.len(),
        report.summary.total_rejections,
        "summary total_rejections mismatch"
    );

    for c in &report.candidates {
        assert!(c.ino > 0);
        match c.candidate_class {
            CandidateClass::UnlinkedChainResidue => {
                assert_eq!(c.method, RecoveryMethod::XfsUnlinkedChain);
                assert!(!c.is_experimental);
            }
            CandidateClass::FreedWithResidualExtents => {
                assert_eq!(c.method, RecoveryMethod::XfsResidualExtents);
                assert!(c.is_experimental);
                assert!(c.original_size.is_none());
            }
            CandidateClass::ZeroLinkAnomaly => {
                assert_eq!(c.method, RecoveryMethod::XfsZeroLinkAnomaly);
                assert!(!c.is_experimental);
                assert_eq!(c.nlink, 0);
            }
        }
    }
}
