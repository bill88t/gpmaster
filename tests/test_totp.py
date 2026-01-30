"""Tests for TOTP functionality."""

import unittest
from unittest.mock import Mock, patch

try:
    import pyotp

    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False


@unittest.skipIf(not TOTP_AVAILABLE, "pyotp not available")
class TestTOTPFunctionality(unittest.TestCase):
    """Test TOTP secret handling."""

    def test_totp_secret_validation(self):
        """Test TOTP secret validation."""
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        code = totp.now()

        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())

    def test_totp_verification(self):
        """Test TOTP code verification."""
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        code = totp.now()

        self.assertTrue(totp.verify(code, valid_window=1))


if __name__ == "__main__":
    unittest.main()
