"""Tests for binary format handling."""

import unittest
from gpmaster.format import LockboxFormat


class TestLockboxFormat(unittest.TestCase):
    """Test binary format pack/unpack operations."""

    def test_pack_unpack_basic(self):
        """Test basic pack and unpack."""
        fmt = LockboxFormat()
        fmt.key_id = "TESTKEY123"
        fmt.titles = ["secret1", "secret2"]
        fmt.note_content = "Note 1"
        fmt.note_signature = b"note_signature"
        fmt.encrypted_data = b"encrypted_data_here"
        fmt.signature = b"signature_bytes"

        packed = fmt.pack()
        unpacked = LockboxFormat.unpack(packed)

        self.assertEqual(unpacked.key_id, "TESTKEY123")
        self.assertEqual(unpacked.titles, ["secret1", "secret2"])
        self.assertEqual(unpacked.note_content, "Note 1")
        self.assertEqual(unpacked.note_signature, b"note_signature")
        self.assertEqual(unpacked.encrypted_data, b"encrypted_data_here")
        self.assertEqual(unpacked.signature, b"signature_bytes")

    def test_pack_without_signature(self):
        """Test packing without signature."""
        fmt = LockboxFormat()
        fmt.key_id = "TESTKEY"
        fmt.titles = []
        fmt.note_content = None
        fmt.encrypted_data = b"data"

        packed = fmt.pack()
        unpacked = LockboxFormat.unpack(packed)

        self.assertEqual(unpacked.key_id, "TESTKEY")
        self.assertIsNone(unpacked.signature)
        self.assertIsNone(unpacked.note_signature)

    def test_invalid_magic(self):
        """Test invalid magic header."""
        with self.assertRaises(ValueError):
            LockboxFormat.unpack(b"INVALID_HEADER")

    def test_checksum_validation(self):
        """Test checksum validation fails on corruption."""
        fmt = LockboxFormat()
        fmt.key_id = "KEY"
        fmt.titles = []
        fmt.note_content = None
        fmt.encrypted_data = b"data"

        packed = fmt.pack()
        corrupted = packed[:-10] + b"X" * 10

        with self.assertRaises(ValueError):
            LockboxFormat.unpack(corrupted)

    def test_empty_metadata(self):
        """Test with empty titles and note content."""
        fmt = LockboxFormat()
        fmt.key_id = "KEY123"
        fmt.titles = []
        fmt.note_content = None
        fmt.encrypted_data = b"test_data"

        packed = fmt.pack()
        unpacked = LockboxFormat.unpack(packed)

        self.assertEqual(unpacked.titles, [])
        self.assertIsNone(unpacked.note_content)

    def test_get_metadata(self):
        """Test metadata extraction."""
        fmt = LockboxFormat()
        fmt.key_id = "KEY"
        fmt.titles = ["s1", "s2"]
        fmt.note_content = "n1"

        metadata = fmt.get_metadata()

        self.assertEqual(metadata["key_id"], "KEY")
        self.assertEqual(metadata["titles"], ["s1", "s2"])
        self.assertEqual(metadata["note_content"], "n1")


if __name__ == "__main__":
    unittest.main()
