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

    let parse_pairs = |text: &str| -> Vec<(u64, u64)> {
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
