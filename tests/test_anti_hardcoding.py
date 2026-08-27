#!/usr/bin/env python3
"""
test_anti_hardcoding.py
=======================
Regression tests verifying that the FirSeFile pipeline is genuinely data-driven:
  1. Different images produce different results
  2. Missing image_path is rejected
  3. Invalid image path returns error (not stale results)
  4. The 4-file test image produces results distinct from the presentation fixture
"""

import os
import sys
import json
import hashlib
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tools.run_recovery import run_forensic_pipeline


@pytest.fixture
def xfs_fixture_path():
    return str(PROJECT_ROOT / "tests" / "fixtures" / "xfs_deleted_synthetic.img")


@pytest.fixture
def fourfile_image_path():
    p = PROJECT_ROOT / "gui_4file_test.img"
    if not p.exists():
        # Generate the 4-file test image on the fly
        sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
        from create_4file_test_image import build_4file_xfs_image
        build_4file_xfs_image(p)
    return str(p)


class TestAntiHardcoding:
    """Ensure pipeline results change with different input images."""

    def test_different_images_produce_different_results(self, xfs_fixture_path, fourfile_image_path):
        """Scanning two different images MUST produce different file lists."""
        res_fixture = run_forensic_pipeline(xfs_fixture_path, output_dir=None)
        res_4file = run_forensic_pipeline(fourfile_image_path, output_dir=None)

        # Image hashes must differ
        assert res_fixture["image_sha256"] != res_4file["image_sha256"], \
            "Two different images must produce different SHA-256 hashes"

        # File IDs must differ
        fixture_ids = set(f["file_id"] for f in res_fixture["recovered_files"])
        fourfile_ids = set(f["file_id"] for f in res_4file["recovered_files"])
        assert fixture_ids != fourfile_ids, \
            "Two different images must produce different file_id sets"

        # Specifically: fixture has ino128/129; 4-file has ino200-203
        assert "xfs:ino128" in fixture_ids, "Fixture should have ino128"
        assert "xfs:ino200" in fourfile_ids, "4-file image should have ino200"
        assert "xfs:ino200" not in fixture_ids, "Fixture should NOT have ino200"
        assert "xfs:ino128" not in fourfile_ids, "4-file image should NOT have ino128"

    def test_fourfile_image_has_expected_candidates(self, fourfile_image_path):
        """The 4-file image should recover inodes 200, 201, 202, 203."""
        res = run_forensic_pipeline(fourfile_image_path, output_dir=None)

        assert res["detected_filesystem"] == "xfs"
        file_ids = [f["file_id"] for f in res["recovered_files"]]

        for expected_id in ["xfs:ino200", "xfs:ino201", "xfs:ino202", "xfs:ino203"]:
            assert expected_id in file_ids, f"Expected {expected_id} in recovery results"

        # Must NOT contain presentation fixture artifacts
        for fixture_id in ["xfs:ino128", "xfs:ino129"]:
            assert fixture_id not in file_ids, \
                f"4-file image must NOT contain fixture artifact {fixture_id}"

    def test_fourfile_sha256_matches_ground_truth(self, fourfile_image_path):
        """Recovered file hashes must match the known ground truth."""
        manifest_path = PROJECT_ROOT / "gui_4file_ground_truth.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            expected_hashes = {f["file_id"]: f["sha256"] for f in manifest["test_files"]}
        else:
            pytest.skip("Ground truth manifest not found")

        res = run_forensic_pipeline(fourfile_image_path, output_dir=None)
        for rf in res["recovered_files"]:
            fid = rf["file_id"]
            if fid in expected_hashes:
                assert rf["sha256"] == expected_hashes[fid], \
                    f"SHA-256 mismatch for {fid}: got {rf['sha256']}, expected {expected_hashes[fid]}"

    def test_invalid_image_path_raises_error(self):
        """A nonexistent image path must raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            run_forensic_pipeline("/tmp/THIS_FILE_DOES_NOT_EXIST_1234.img")

    def test_presentation_fixture_still_works(self, xfs_fixture_path):
        """The existing presentation fixture must still produce valid results."""
        res = run_forensic_pipeline(xfs_fixture_path, output_dir=None)
        assert res["detected_filesystem"] == "xfs"
        assert res["total_files_recovered"] > 0

        file_ids = [f["file_id"] for f in res["recovered_files"]]
        assert "xfs:ino128" in file_ids, "Fixture should recover ino128"
        assert "xfs:ino129" in file_ids, "Fixture should recover ino129"

    def test_each_scan_has_own_ledger(self, xfs_fixture_path, fourfile_image_path):
        """Each pipeline run must generate its own independent ledger."""
        res1 = run_forensic_pipeline(xfs_fixture_path, output_dir=None)
        res2 = run_forensic_pipeline(fourfile_image_path, output_dir=None)

        # Both must have genesis blocks
        assert len(res1["ledger_blocks"]) > 0
        assert len(res2["ledger_blocks"]) > 0

        # Genesis disk_baseline_sha256 must differ
        genesis1 = res1["ledger_blocks"][0]["payload"]["disk_baseline_sha256"]
        genesis2 = res2["ledger_blocks"][0]["payload"]["disk_baseline_sha256"]
        assert genesis1 != genesis2, \
            "Different images must produce different genesis block disk hashes"
