"""GPG operations wrapper with retry logic."""

import gnupg
import sys
import tempfile
import os
import shutil
from typing import Optional, Tuple


class GPGOperations:
    """Handle GPG encryption, decryption, and signing with retry logic."""

    def __init__(self, quiet: bool = False):
        # Determine gpg binary: env override > packaged wrapper > default
        gpg_binary = (
            os.environ.get("GPMASTER_GPG_BINARY")
            or os.environ.get("GPG_BINARY")
            or os.environ.get("GPG")
        )
        if not gpg_binary:
            wrap_path = shutil.which("gpg-wrap")
            okc_path = shutil.which("okc-gpg")
            if okc_path and wrap_path:
                gpg_binary = wrap_path

        agent_socket = os.environ.get("GPMASTER_AGENT_SOCKET") or os.environ.get(
            "OKC_AGENT_SOCKET"
        )

        if agent_socket and "GPG_AGENT_INFO" not in os.environ:
            os.environ["GPG_AGENT_INFO"] = agent_socket
        self.quiet = quiet
        if gpg_binary:
            if not self.quiet:
                print(f'[GPMASTER:] Using GPG binary: "{gpg_binary}"')
            self.gpg = gnupg.GPG(gpgbinary=gpg_binary)
        else:
            if not self.quiet:
                print("[GPMASTER:] Using system GPG for all operations.")
            self.gpg = gnupg.GPG()

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

            print(f"[GPMASTER:] Encryption failed: {result.status}", file=sys.stderr)
            try:
                response = input(
                    "[GPMASTER:] Retry encryption? (Enter to retry, Ctrl+C to abort): "
                ).strip()
                continue
            except KeyboardInterrupt:
                print("\n[GPMASTER:] Aborted", file=sys.stderr)
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

            print(f"[GPMASTER:] Decryption failed: {result.status}", file=sys.stderr)
            try:
                response = input(
                    "[GPMASTER:] Retry decryption? (Enter to retry, Ctrl+C to abort): "
                ).strip()
                continue
            except KeyboardInterrupt:
                print("\n[GPMASTER:] Aborted", file=sys.stderr)
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

            print(f"[GPMASTER:] Signing failed: {result.status}", file=sys.stderr)
            try:
                response = input(
                    "[GPMASTER:] Retry signing? (Enter to retry, Ctrl+C to abort): "
                ).strip()
                continue
            except KeyboardInterrupt:
                print("\n[GPMASTER:] Aborted", file=sys.stderr)
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
