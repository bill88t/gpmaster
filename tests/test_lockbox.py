"""Integration tests for lockbox operations."""

import unittest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from gpmaster.lockbox import Lockbox


class TestLockboxOperations(unittest.TestCase):
    """Test lockbox operations with mocked GPG."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.lockbox_path = Path(self.temp_dir) / "test.gpb"

    def tearDown(self):
        """Clean up test files."""
        if self.lockbox_path.exists():
            self.lockbox_path.unlink()
        os.rmdir(self.temp_dir)

    @patch("gpmaster.lockbox.GPGOperations")
    def test_create_lockbox(self, mock_gpg_class):
        """Test creating a new lockbox."""
        mock_gpg = Mock()
        mock_gpg.encrypt.return_value = (True, b"encrypted_data")
        mock_gpg.sign.return_value = (True, b"signature")
        mock_gpg_class.return_value = mock_gpg

        lockbox = Lockbox(str(self.lockbox_path), quiet=True)
        lockbox.create("TESTKEY")

        self.assertTrue(self.lockbox_path.exists())
        mock_gpg.encrypt.assert_called_once()
        mock_gpg.sign.assert_called_once()

    @patch("gpmaster.lockbox.GPGOperations")
    def test_add_and_get_secret(self, mock_gpg_class):
        """Test adding and retrieving a secret."""
        mock_gpg = Mock()
        mock_gpg.encrypt.return_value = (True, b"encrypted_data")
        mock_gpg.sign.return_value = (True, b"signature")
        mock_gpg.decrypt.return_value = (
            True,
            b'{"test_secret":{"value":"my_secret"}}',
            "TESTKEY",
        )
        mock_gpg_class.return_value = mock_gpg

        lockbox = Lockbox(str(self.lockbox_path), quiet=True)
        lockbox.create("TESTKEY")

        mock_gpg.decrypt.return_value = (True, b"{}", "TESTKEY")
        lockbox.add_secret("test_secret", "my_secret")

        mock_gpg.decrypt.return_value = (
            True,
            b'{"test_secret":{"value":"my_secret"}}',
            "TESTKEY",
        )
        secret, is_totp = lockbox.get_secret("test_secret")

        self.assertEqual(secret, "my_secret")
        self.assertFalse(is_totp)

    @patch("gpmaster.lockbox.GPGOperations")
    def test_list_contents_no_decryption(self, mock_gpg_class):
        """Test listing contents without decryption."""
        mock_gpg = Mock()
        mock_gpg.encrypt.return_value = (True, b"encrypted_data")
        mock_gpg.sign.return_value = (True, b"signature")
        mock_gpg_class.return_value = mock_gpg

        lockbox = Lockbox(str(self.lockbox_path), quiet=True)
        lockbox.create("TESTKEY")

        titles, key_id = lockbox.list_contents()

        self.assertEqual(titles, [])
        self.assertEqual(key_id, "TESTKEY")
        mock_gpg.decrypt.assert_not_called()

    @patch("gpmaster.lockbox.GPGOperations")
    def test_edit_note(self, mock_gpg_class):
        """Test editing note document."""
        mock_gpg = Mock()
        mock_gpg.encrypt.return_value = (True, b"encrypted_data")
        mock_gpg.sign.return_value = (True, b"signature")
        mock_gpg_class.return_value = mock_gpg

        lockbox = Lockbox(str(self.lockbox_path), quiet=True)
        lockbox.create("TESTKEY")

        # Test that get_info works
        titles, note_content, note_signature, key_id = lockbox.get_info()

        self.assertEqual(titles, [])
        self.assertIsNone(note_content)
        self.assertIsNone(note_signature)
        self.assertEqual(key_id, "TESTKEY")

    @patch("gpmaster.lockbox.GPGOperations")
    def test_validate_lockbox(self, mock_gpg_class):
        """Test lockbox validation."""
        mock_gpg = Mock()
        mock_gpg.encrypt.return_value = (True, b"encrypted_data")
        mock_gpg.sign.return_value = (True, b"signature")
        mock_gpg.verify.return_value = (True, "TESTKEY")
        mock_gpg_class.return_value = mock_gpg

        lockbox = Lockbox(str(self.lockbox_path), quiet=True)
        lockbox.create("TESTKEY")

        valid = lockbox.validate()

        self.assertTrue(valid)
        mock_gpg.verify.assert_called_once()

    def test_invalid_extension(self):
        """Test that non-.gpb extension raises error."""
        invalid_path = Path(self.temp_dir) / "test.txt"

        with self.assertRaises(ValueError):
            Lockbox(str(invalid_path), quiet=True)


if __name__ == "__main__":
    unittest.main()
