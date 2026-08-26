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
