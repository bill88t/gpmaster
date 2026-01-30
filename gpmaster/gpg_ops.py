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

    def encrypt(
        self, data: bytes, key_id: str, retry: bool = True
    ) -> Tuple[bool, Optional[bytes]]:
        """Encrypt data for the specified key."""
        while True:
            result = self.gpg.encrypt(data, key_id, always_trust=False, armor=False)
            if result.ok:
                return True, bytes(result.data)

            if not retry or self.quiet:
                return False, None

            print(f"Encryption failed: {result.status}", file=sys.stderr)
            try:
                response = input(
                    "Retry encryption? (Enter to retry, Ctrl+C to abort): "
                ).strip()
                continue
            except KeyboardInterrupt:
                print("\nAborted", file=sys.stderr)
                return False, None

    def decrypt(
        self, data: bytes, retry: bool = True
    ) -> Tuple[bool, Optional[bytes], Optional[str]]:
        """Decrypt data and return key ID used."""
        while True:
            result = self.gpg.decrypt(data)
            if result.ok:
                return True, bytes(result.data), result.key_id

            if not retry or self.quiet:
                return False, None, None

            print(f"Decryption failed: {result.status}", file=sys.stderr)
            try:
                response = input(
                    "Retry decryption? (Enter to retry, Ctrl+C to abort): "
                ).strip()
                continue
            except KeyboardInterrupt:
                print("\nAborted", file=sys.stderr)
                return False, None, None

    def sign(
        self, data: bytes, key_id: str, retry: bool = True
    ) -> Tuple[bool, Optional[bytes]]:
        """Sign data with retry logic."""
        while True:
            result = self.gpg.sign(data, keyid=key_id, detach=True, binary=True)

            if result.data:
                return True, bytes(result.data)

            if not retry or self.quiet:
                return False, None

            print(f"Signing failed: {result.status}", file=sys.stderr)
            try:
                response = input(
                    "Retry signing? (Enter to retry, Ctrl+C to abort): "
                ).strip()
                continue
            except KeyboardInterrupt:
                print("\nAborted", file=sys.stderr)
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
