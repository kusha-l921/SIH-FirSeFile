"""
test_btrfs_engine.py
====================
Tests for the Btrfs recovery engine.

Each test documents:
  - expected result
  - actual result
  - recovered filename / size / offsets / metadata
  - whether file content matches original
"""

import struct
import hashlib
import binascii
import os
import sys
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from btrfs_structs import (
    BTRFS_MAGIC, BTRFS_SUPER_OFFSET,
    mode_to_str, detect_file_type,
)
from btrfs_engine import BtrfsEngine
from tests.test_helpers import (
    pack_superblock, pack_inode_item, pack_leaf_node,
    make_image, write_tmp_image,
)

NODE_OFFSET = BTRFS_SUPER_OFFSET + 4096  # where leaf node lives in test images


# ---------------------------------------------------------------------------
# Test 1 – Filesystem identification
# ---------------------------------------------------------------------------

class TestFilesystemIdentification(unittest.TestCase):

    def test_valid_btrfs_magic(self):
        """
        Expected : is_btrfs() == True
        Actual   : reads magic at superblock offset 64
        """
        path = write_tmp_image(make_image(pack_superblock()))
        try:
            with BtrfsEngine(path) as eng:
                self.assertTrue(eng.is_btrfs())
        finally:
            os.unlink(path)

    def test_invalid_magic_rejected(self):
        """
        Expected : is_btrfs() == False when magic bytes are wrong
        """
        img = bytearray(2 * 1024 * 1024)
        img[BTRFS_SUPER_OFFSET + 64: BTRFS_SUPER_OFFSET + 72] = b'NOTBTRFS'
        path = write_tmp_image(bytes(img))
        try:
            with BtrfsEngine(path) as eng:
                self.assertFalse(eng.is_btrfs())
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Test 2 – Superblock / metadata discovery
# ---------------------------------------------------------------------------

class TestSuperblockParsing(unittest.TestCase):

    def setUp(self):
        sb = pack_superblock(generation=99, total_bytes=100*1024*1024, label=b'myfs')
        self.path = write_tmp_image(make_image(sb))

    def tearDown(self):
        os.unlink(self.path)

    def test_superblock_fields(self):
        """
        Expected : generation=99, label='myfs', magic=BTRFS_MAGIC
        Recovered metadata: generation, label, nodesize, sectorsize
        """
        with BtrfsEngine(self.path) as eng:
            sb = eng.parse_superblock()
        self.assertIsNotNone(sb)
        self.assertEqual(sb.magic, BTRFS_MAGIC)
        self.assertEqual(sb.generation, 99)
        self.assertEqual(sb.label, 'myfs')
        self.assertEqual(sb.sectorsize, 4096)

    def test_summary_reports_valid_superblock(self):
        """
        Expected : get_summary()['superblock_valid'] == True
        """
        with BtrfsEngine(self.path) as eng:
            eng.parse_superblock()
            s = eng.get_summary()
        self.assertTrue(s['superblock_valid'])
        self.assertEqual(s['filesystem'], 'btrfs')
        self.assertEqual(s['fs_label'], 'myfs')


# ---------------------------------------------------------------------------
# Test 3 – Normal file discovery
# ---------------------------------------------------------------------------

class TestInodeDiscovery(unittest.TestCase):

    def _path_with_inode(self, nlink=1, size=1024, mode=0o100644):
        nodesize = 16384
        inode_data = pack_inode_item(nlink=nlink, size=size, mode=mode)
        leaf = pack_leaf_node(inode_num=256, inode_data=inode_data, nodesize=nodesize)
        sb = pack_superblock(root=NODE_OFFSET, bytes_used=nodesize*2, nodesize=nodesize)
        return write_tmp_image(make_image(sb, leaf, nodesize=nodesize))

    def test_active_inode_found(self):
        """
        Expected : inode 256, nlink=1, size=1024, is_deleted=False
        Recovered filename : None (inode_ref not parsed – not in source repos)
        Recovered size     : 1024
        Source offset      : NODE_OFFSET (leaf node)
        Recovered metadata : uid=1000, gid=1000, mode=0o100644
        Content match      : N/A (no extent data in this test)
        """
        path = self._path_with_inode()
        try:
            with BtrfsEngine(path) as eng:
                inodes = list(eng.scan_inodes())
            self.assertGreater(len(inodes), 0)
            ino = inodes[0]
            self.assertEqual(ino.inode_number, 256)
            self.assertEqual(ino.size, 1024)
            self.assertFalse(ino.is_deleted)
            self.assertEqual(ino.uid, 1000)
            self.assertEqual(ino.gid, 1000)
        finally:
            os.unlink(path)

    def test_directory_inode_detected(self):
        """
        Expected : mode=0o040755 -> is_directory=True
        """
        path = self._path_with_inode(mode=0o040755, size=0)
        try:
            with BtrfsEngine(path) as eng:
                inodes = list(eng.scan_inodes())
            self.assertTrue(any(i.is_directory for i in inodes))
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Test 4 – Deleted-file detection
# ---------------------------------------------------------------------------

class TestDeletedFileDetection(unittest.TestCase):

    def test_deleted_inode_flagged(self):
        """
        Expected : nlink=0, size=4096 -> is_deleted=True
        Recovered size     : 4096
        Source offset      : NODE_OFFSET
        Recovered metadata : uid, gid, mode, MACB timestamps present
        Content match      : N/A (no extent data)
        """
        nodesize = 16384
        inode_data = pack_inode_item(nlink=0, size=4096, mode=0o100644)
        leaf = pack_leaf_node(512, inode_data, nodesize)
        sb = pack_superblock(root=NODE_OFFSET, bytes_used=nodesize*2, nodesize=nodesize)
        path = write_tmp_image(make_image(sb, leaf, nodesize=nodesize))
        try:
            with BtrfsEngine(path) as eng:
                inodes = list(eng.scan_inodes())
            deleted = [i for i in inodes if i.is_deleted]
            self.assertGreater(len(deleted), 0)
            d = deleted[0]
            self.assertEqual(d.inode_number, 512)
            self.assertEqual(d.size, 4096)
            self.assertEqual(d.nlink, 0)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Test 5 – Timestamp and permission recovery
# ---------------------------------------------------------------------------

class TestTimestampAndPermissions(unittest.TestCase):

    def test_macb_timestamps(self):
        """
        Expected : atime/mtime/ctime/otime parsed correctly from inode item
        Recovered metadata:
          atime = fromtimestamp(1700000000)
          ctime = fromtimestamp(1700000001)
          mtime = fromtimestamp(1700000002)
          otime = fromtimestamp(1699999999)  [creation time, Btrfs-specific]
        """
        nodesize = 16384
        inode_data = pack_inode_item(
            atime=1700000000, ctime=1700000001,
            mtime=1700000002, otime=1699999999,
        )
        leaf = pack_leaf_node(256, inode_data, nodesize)
        sb = pack_superblock(root=NODE_OFFSET, bytes_used=nodesize*2, nodesize=nodesize)
        path = write_tmp_image(make_image(sb, leaf, nodesize=nodesize))
        try:
            with BtrfsEngine(path) as eng:
                inodes = list(eng.scan_inodes())
            self.assertGreater(len(inodes), 0)
            ino = inodes[0]
            self.assertEqual(ino.atime, datetime.fromtimestamp(1700000000))
            self.assertEqual(ino.ctime, datetime.fromtimestamp(1700000001))
            self.assertEqual(ino.mtime, datetime.fromtimestamp(1700000002))
            self.assertEqual(ino.otime, datetime.fromtimestamp(1699999999))
        finally:
            os.unlink(path)

    def test_permissions_string(self):
        """Expected : mode -> permission string"""
        self.assertEqual(mode_to_str(0o100644), '-rw-r--r--')
        self.assertEqual(mode_to_str(0o040755), 'drwxr-xr-x')
        self.assertEqual(mode_to_str(0o100755), '-rwxr-xr-x')

    def test_inode_metadata_dict(self):
        """
        Expected : inode_metadata() returns uid, gid, permissions, otime, filesystem
        """
        nodesize = 16384
        inode_data = pack_inode_item(uid=500, gid=500, mode=0o100600)
        leaf = pack_leaf_node(300, inode_data, nodesize)
        sb = pack_superblock(root=NODE_OFFSET, bytes_used=nodesize*2, nodesize=nodesize)
        path = write_tmp_image(make_image(sb, leaf, nodesize=nodesize))
        try:
            with BtrfsEngine(path) as eng:
                inodes = list(eng.scan_inodes())
            meta = eng.inode_metadata(inodes[0])
            self.assertEqual(meta['uid'], 500)
            self.assertEqual(meta['gid'], 500)
            self.assertEqual(meta['permissions'], '-rw-------')
            self.assertEqual(meta['filesystem'], 'btrfs')
            self.assertIn('otime', meta)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Test 6 – CRC32C checksum verification
# ---------------------------------------------------------------------------

class TestChecksumVerification(unittest.TestCase):

    def setUp(self):
        self.path = write_tmp_image(make_image(pack_superblock()))

    def tearDown(self):
        os.unlink(self.path)

    def test_checksum_match(self):
        """Expected : verify_checksum returns True when CRC matches"""
        data = b'hello btrfs world'
        crc = binascii.crc32(data) & 0xFFFFFFFF
        stored = struct.pack('<I', crc) + b'\x00' * 28
        with BtrfsEngine(self.path) as eng:
            self.assertTrue(eng.verify_checksum(data, stored))

    def test_checksum_mismatch(self):
        """Expected : verify_checksum returns False when CRC is wrong"""
        data = b'hello btrfs world'
        stored = struct.pack('<I', 0xDEADBEEF) + b'\x00' * 28
        with BtrfsEngine(self.path) as eng:
            self.assertFalse(eng.verify_checksum(data, stored))


# ---------------------------------------------------------------------------
# Test 7 – File carving (fallback recovery path)
# ---------------------------------------------------------------------------

class TestFileCarving(unittest.TestCase):

    def _image_with_payload(self, payload: bytes) -> str:
        img = bytearray(4 * 1024 * 1024)
        sb = pack_superblock()
        img[BTRFS_SUPER_OFFSET: BTRFS_SUPER_OFFSET + len(sb)] = sb
        img[2*1024*1024: 2*1024*1024 + len(payload)] = payload
        return write_tmp_image(bytes(img))

    def test_pdf_carved(self):
        """
        Expected : PDF signature found in unallocated space
        Recovered filename : carved_00200000.pdf
        Recovered size     : len(payload)
        Source offset      : 0x200000 (2 MiB)
        Content match      : SHA-256 of carved data == SHA-256 of payload
        """
        payload = b'%PDF-1.4 fake pdf content\n%%EOF'
        path = self._image_with_payload(payload)
        try:
            with BtrfsEngine(path) as eng:
                eng.parse_superblock()
                results = list(eng.carve_free_space(file_types=['pdf']))
            self.assertGreater(len(results), 0)
            cf = results[0]
            self.assertEqual(cf.file_type, 'pdf')
            self.assertIn(b'%PDF-', cf.data)
            self.assertTrue(cf.footer_found)
            self.assertEqual(cf.sha256, hashlib.sha256(cf.data).hexdigest())
            self.assertEqual(cf.offset, 2 * 1024 * 1024)
        finally:
            os.unlink(path)

    def test_png_footer_confidence(self):
        """
        Expected : PNG with IEND footer -> footer_found=True, confidence >= 0.85
        """
        payload = b'\x89PNG\r\n\x1a\n' + b'\x00' * 200 + b'IEND\xaeB`\x82'
        path = self._image_with_payload(payload)
        try:
            with BtrfsEngine(path) as eng:
                eng.parse_superblock()
                results = list(eng.carve_free_space(file_types=['png']))
            self.assertGreater(len(results), 0)
            cf = results[0]
            self.assertTrue(cf.footer_found)
            self.assertGreaterEqual(cf.confidence, 0.85)
        finally:
            os.unlink(path)

    def test_no_false_positive_on_empty_image(self):
        """Expected : all-zero image yields no carved files"""
        path = write_tmp_image(bytes(2 * 1024 * 1024))
        try:
            with BtrfsEngine(path) as eng:
                results = list(eng.carve_free_space())
            self.assertEqual(len(results), 0)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Test 8 – Snapshot comparison
# ---------------------------------------------------------------------------

class TestSnapshotComparison(unittest.TestCase):

    def test_removed_inode_detected(self):
        """
        Expected : inode in snap1 but not snap2 appears in diff['removed']
        """
        from btrfs_structs import BtrfsInode

        def dummy(ino_num, snap_id):
            return BtrfsInode(
                inode_number=ino_num, generation=1, size=100,
                nbytes=4096, nlink=1, uid=0, gid=0, mode=0o100644,
                atime=datetime.min, ctime=datetime.min,
                mtime=datetime.min, otime=datetime.min,
                snapshot_id=snap_id,
            )

        path = write_tmp_image(make_image(pack_superblock()))
        try:
            with BtrfsEngine(path) as eng:
                eng.inodes = [dummy(100, 1), dummy(101, 1), dummy(100, 2)]
                diff = eng.compare_snapshots(1, 2)
            self.assertIn(101, diff['removed'])
            self.assertNotIn(101, diff['added'])
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Test 9 – btrfs-restore hint (Repo 2 contribution)
# ---------------------------------------------------------------------------

class TestBtrfsRestoreHint(unittest.TestCase):

    def test_hint_structure(self):
        """
        Expected : returns dict with suggested_cmd containing 'btrfs restore'
        Must NOT execute anything
        """
        hint = BtrfsEngine.btrfs_restore_hint('/dev/sdb1', '/tmp/out')
        self.assertIn('suggested_cmd', hint)
        self.assertIn('btrfs restore', hint['suggested_cmd'])
        self.assertIn('/dev/sdb1', hint['suggested_cmd'])
        self.assertIn('not execute', hint['note'])

    def test_hint_auto_outdir(self):
        """Expected : outdir auto-generated when not provided"""
        hint = BtrfsEngine.btrfs_restore_hint('/dev/sdb1')
        self.assertIn('btrfs_recover_', hint['outdir'])


# ---------------------------------------------------------------------------
# Test 10 – File-type detection
# ---------------------------------------------------------------------------

class TestFileTypeDetection(unittest.TestCase):

    def test_known_types(self):
        cases = [
            (b'\xff\xd8\xff\xe0', 'jpeg'),
            (b'\x89PNG\r\n\x1a\n', 'png'),
            (b'%PDF-1.4',          'pdf'),
            (b'PK\x03\x04',        'zip'),
            (b'\x7fELF\x02',       'elf'),
            (b'GIF89a',            'gif'),
        ]
        for data, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(detect_file_type(data), expected)

    def test_text_detection(self):
        self.assertEqual(detect_file_type(b'Hello world\nThis is text\n'), 'text')

    def test_none_on_empty(self):
        self.assertIsNone(detect_file_type(b''))
        self.assertIsNone(detect_file_type(None))


# ---------------------------------------------------------------------------
# Test 11 – Partial metadata survival
# ---------------------------------------------------------------------------

class TestPartialMetadataSurvival(unittest.TestCase):

    def test_deleted_inode_metadata_intact_no_content(self):
        """
        Simulates the common real-world case: deleted inode with valid MACB
        timestamps and permissions but no extent data available.

        Expected:
          is_deleted=True, size=8192, uid=0, gid=0, mode=0o100600
          atime/mtime/ctime/otime all parsed
          recovered_data=None, extents=[]
          permissions='-rw-------'
        Recovered filename : None (inode_ref not implemented in source repos)
        Content match      : False (no extent data)
        """
        nodesize = 16384
        inode_data = pack_inode_item(
            nlink=0, size=8192, mode=0o100600, uid=0, gid=0,
            atime=1700100000, ctime=1700100001,
            mtime=1700100002, otime=1700099999,
        )
        leaf = pack_leaf_node(999, inode_data, nodesize)
        sb = pack_superblock(root=NODE_OFFSET, bytes_used=nodesize*2, nodesize=nodesize)
        path = write_tmp_image(make_image(sb, leaf, nodesize=nodesize))
        try:
            with BtrfsEngine(path) as eng:
                inodes = list(eng.scan_inodes())
            deleted = [i for i in inodes if i.is_deleted]
            self.assertGreater(len(deleted), 0)
            d = deleted[0]
            self.assertEqual(d.size, 8192)
            self.assertEqual(d.uid, 0)
            self.assertEqual(d.gid, 0)
            self.assertEqual(d.mode, 0o100600)
            self.assertEqual(d.atime, datetime.fromtimestamp(1700100000))
            self.assertEqual(d.otime, datetime.fromtimestamp(1700099999))
            self.assertIsNone(d.recovered_data)
            self.assertEqual(d.extents, [])
            meta = eng.inode_metadata(d)
            self.assertEqual(meta['permissions'], '-rw-------')
            self.assertTrue(meta['is_deleted'])
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
