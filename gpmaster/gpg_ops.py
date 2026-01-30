"""GPG operations wrapper with retry logic."""

import gnupg
import sys
import tempfile
import os
from typing import Optional, Tuple


class GPGOperations:
    """Handle GPG encryption, decryption, and signing with retry logic."""

    def __init__(self, quiet: bool = False):
        self.gpg = gnupg.GPG()
        self.quiet = quiet

    def encrypt(self, data: bytes, key_id: str) -> Tuple[bool, Optional[bytes]]:
        """Encrypt data for the specified key."""
        result = self.gpg.encrypt(data, key_id, always_trust=False, armor=False)
        if result.ok:
            return True, bytes(result.data)
        return False, None

    def decrypt(self, data: bytes) -> Tuple[bool, Optional[bytes], Optional[str]]:
        """Decrypt data and return key ID used."""
        result = self.gpg.decrypt(data)
        if result.ok:
            return True, bytes(result.data), result.key_id
        return False, None, None

    def sign(
        self, data: bytes, key_id: str, retry: bool = True
    ) -> Tuple[bool, Optional[bytes]]:
        """Sign data with retry logic."""
        while True:
            result = self.gpg.sign(data, keyid=key_id, detach=True, binary=True)

            if result.data:
                return True, bytes(result.data)

            if not retry:
                return False, None

            if not self.quiet:
                print(f"Signing failed: {result.status}", file=sys.stderr)
                response = input("Retry signing? [Y/n]: ").strip().lower()
                if response and response != "y":
                    return False, None
            else:
                return False, None

    def verify(self, data: bytes, signature: bytes) -> Tuple[bool, Optional[str]]:
        """Verify signature and return key ID."""
        # Write signature to temp file since verify_data expects a filename
        with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as sig_file:
            sig_file.write(signature)
            sig_filename = sig_file.name

        try:
            result = self.gpg.verify_data(sig_filename, data)
            if result.valid:
                return True, result.key_id
            return False, None
        finally:
            os.unlink(sig_filename)
