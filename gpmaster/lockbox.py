import json
import os
import sys
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .format import LockboxFormat
from .gpg_ops import GPGOperations


class Lockbox:
    """Manage GPG-encrypted lockbox with secrets."""

    def __init__(self, path: str, quiet: bool = False):
        self.path = Path(path)
        self.quiet = quiet
        self.gpg = GPGOperations(quiet=quiet)
        self._ensure_extension()

    def _ensure_extension(self):
        """Ensure lockbox file has .gpb extension."""
        if self.path.suffix != ".gpb":
            raise ValueError("Lockbox file must have .gpb extension")

    def _load_format(self) -> LockboxFormat:
        """Load and validate lockbox format."""
        if not self.path.exists():
            raise FileNotFoundError(f"Lockbox not found: {self.path}")

        with open(self.path, "rb") as f:
            data = f.read()

        return LockboxFormat.unpack(data)

    def _decrypt_data(
        self, fmt: LockboxFormat, retry: bool = True
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Decrypt lockbox data."""
        success, decrypted, key_id = self.gpg.decrypt(fmt.encrypted_data, retry=retry)
        if not success:
            return False, None, None

        try:
            secrets = json.loads(decrypted.decode("utf-8"))
            return True, secrets, key_id
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False, None, None

    def _save_lockbox(self, fmt: LockboxFormat):
        """Save lockbox to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)

        data = fmt.pack()
        with open(self.path, "wb") as f:
            f.write(data)

    def create(self, key_id: str):
        """Create a new lockbox."""
        if self.path.exists():
            raise FileExistsError(f"Lockbox already exists: {self.path}")

        secrets = {}
        secrets_json = json.dumps(secrets, separators=(",", ":")).encode("utf-8")

        success, encrypted = self.gpg.encrypt(secrets_json, key_id, retry=False)
        if not success:
            raise RuntimeError("Failed to encrypt lockbox")

        fmt = LockboxFormat()
        fmt.key_id = key_id
        fmt.encrypted_data = encrypted
        fmt.titles = []
        fmt.note_content = None
        fmt.note_signature = None

        data_to_sign = fmt.key_id.encode("utf-8") + encrypted
        success, signature = self.gpg.sign(data_to_sign, key_id, retry=True)
        if success:
            fmt.signature = signature

        self._save_lockbox(fmt)

        if not self.quiet:
            print(f"Created lockbox encrypted with key: {key_id}")

    def validate(self) -> bool:
        """Validate lockbox integrity and signature."""
        try:
            fmt = self._load_format()

            if not self.quiet:
                print(f"Lockbox encrypted with key: {fmt.key_id}")

            if fmt.signature:
                data_to_verify = fmt.key_id.encode("utf-8") + fmt.encrypted_data
                valid, signer_key = self.gpg.verify(data_to_verify, fmt.signature)

                if valid:
                    if not self.quiet:
                        print(f"Signature valid (signed by: {signer_key})")
                    return True
                else:
                    if not self.quiet:
                        print("Signature validation failed")
                    return False
            else:
                if not self.quiet:
                    print("No signature present")
                return True

        except Exception as e:
            if not self.quiet:
                print(f"Validation failed: {e}")
            return False

    def list_contents(self) -> Tuple[List[str], str]:
        """List lockbox contents without decryption (kept for compatibility)."""
        fmt = self._load_format()
        return fmt.titles, fmt.key_id

    def get_info(self) -> Tuple[List[str], Optional[str], Optional[bytes], str]:
        """Get lockbox info including note content and signature."""
        fmt = self._load_format()
        return fmt.titles, fmt.note_content, fmt.note_signature, fmt.key_id

    def add_secret(
        self,
        name: str,
        secret: str,
        is_totp: bool = False,
        auto_create_key: Optional[str] = None,
    ):
        """Add or update a secret in the lockbox."""
        if self.path.exists():
            fmt = self._load_format()
            success, secrets, dec_key = self._decrypt_data(fmt, retry=not self.quiet)
            if not success:
                raise RuntimeError("Failed to decrypt lockbox")

            if not self.quiet:
                print(f"Decrypted with key: {dec_key}")
        else:
            if not auto_create_key:
                raise FileNotFoundError(
                    "Lockbox does not exist. Create it first with 'gpmaster create <key-id>' or set GPMASTER_KEY_ID environment variable."
                )

            if not self.quiet:
                print(f"Creating new lockbox with key: {auto_create_key}")
            self.create(auto_create_key)

            fmt = self._load_format()
            secrets = {}

        entry = {"value": secret}
        if is_totp:
            entry["type"] = "totp"

        secrets[name] = entry

        if name not in fmt.titles:
            fmt.titles.append(name)

        secrets_json = json.dumps(secrets, separators=(",", ":")).encode("utf-8")
        success, encrypted = self.gpg.encrypt(
            secrets_json, fmt.key_id, retry=not self.quiet
        )
        if not success:
            raise RuntimeError("Failed to encrypt lockbox")

        fmt.encrypted_data = encrypted

        data_to_sign = fmt.key_id.encode("utf-8") + encrypted
        success, signature = self.gpg.sign(data_to_sign, fmt.key_id, retry=True)
        if success:
            fmt.signature = signature

        self._save_lockbox(fmt)

        if not self.quiet:
            print(f"Added secret: {name}")

    def get_secret(self, name: str) -> Tuple[Optional[str], bool]:
        """Retrieve a secret from the lockbox."""
        fmt = self._load_format()

        if not self.quiet:
            print(f"Encrypted with key: {fmt.key_id}")

        success, secrets, dec_key = self._decrypt_data(fmt, retry=not self.quiet)
        if not success:
            raise RuntimeError("Failed to decrypt lockbox")

        if not self.quiet:
            print(f"Decrypted with key: {dec_key}")

        if name not in secrets:
            return None, False

        entry = secrets[name]
        is_totp = entry.get("type") == "totp"
        return entry["value"], is_totp

    def rename_secret(self, old_name: str, new_name: str):
        """Rename a secret."""
        fmt = self._load_format()
        success, secrets, dec_key = self._decrypt_data(fmt, retry=not self.quiet)
        if not success:
            raise RuntimeError("Failed to decrypt lockbox")

        if not self.quiet:
            print(f"Decrypted with key: {dec_key}")

        if old_name not in secrets:
            raise KeyError(f"Secret not found: {old_name}")

        if new_name in secrets:
            raise KeyError(f"Secret already exists: {new_name}")

        secrets[new_name] = secrets.pop(old_name)

        if old_name in fmt.titles:
            idx = fmt.titles.index(old_name)
            fmt.titles[idx] = new_name

        secrets_json = json.dumps(secrets, separators=(",", ":")).encode("utf-8")
        success, encrypted = self.gpg.encrypt(
            secrets_json, fmt.key_id, retry=not self.quiet
        )
        if not success:
            raise RuntimeError("Failed to encrypt lockbox")

        fmt.encrypted_data = encrypted

        data_to_sign = fmt.key_id.encode("utf-8") + encrypted
        success, signature = self.gpg.sign(data_to_sign, fmt.key_id, retry=True)
        if success:
            fmt.signature = signature

        self._save_lockbox(fmt)

        if not self.quiet:
            print(f"Renamed: {old_name} -> {new_name}")

    def delete_secret(self, name: str):
        """Delete a secret."""
        fmt = self._load_format()
        success, secrets, dec_key = self._decrypt_data(fmt, retry=not self.quiet)
        if not success:
            raise RuntimeError("Failed to decrypt lockbox")

        if not self.quiet:
            print(f"Decrypted with key: {dec_key}")

        if name not in secrets:
            raise KeyError(f"Secret not found: {name}")

        del secrets[name]

        if name in fmt.titles:
            fmt.titles.remove(name)

        secrets_json = json.dumps(secrets, separators=(",", ":")).encode("utf-8")
        success, encrypted = self.gpg.encrypt(
            secrets_json, fmt.key_id, retry=not self.quiet
        )
        if not success:
            raise RuntimeError("Failed to encrypt lockbox")

        fmt.encrypted_data = encrypted

        data_to_sign = fmt.key_id.encode("utf-8") + encrypted
        success, signature = self.gpg.sign(data_to_sign, fmt.key_id, retry=True)
        if success:
            fmt.signature = signature

        self._save_lockbox(fmt)

        if not self.quiet:
            print(f"Deleted secret: {name}")

    def edit_note(self):
        """Edit notes document with $EDITOR and sign it."""
        fmt = self._load_format()

        current_content = fmt.note_content if fmt.note_content else ""

        editor = os.environ.get("EDITOR", "vi")

        with tempfile.NamedTemporaryFile(mode="w+", suffix=".txt", delete=False) as tf:
            tf.write(current_content)
            tf.flush()
            temp_path = tf.name

        try:
            result = subprocess.run([editor, temp_path])

            if result.returncode != 0:
                if not self.quiet:
                    print("Editor exited with error, not saving", file=sys.stderr)
                os.unlink(temp_path)
                return

            with open(temp_path, "r") as f:
                new_content = f.read()

            if new_content == current_content:
                if not self.quiet:
                    print("No changes made")
                os.unlink(temp_path)
                return

            data_to_sign = new_content.encode("utf-8")
            success, signature = self.gpg.sign(data_to_sign, fmt.key_id, retry=True)

            if not success:
                if not self.quiet:
                    print("Failed to sign note, not saving changes", file=sys.stderr)
                os.unlink(temp_path)
                return

            fmt.note_content = new_content
            fmt.note_signature = signature

            self._save_lockbox(fmt)

            if not self.quiet:
                print("Note saved and signed")

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def rekey(self, new_key_id: str):
        """Change encryption key."""
        fmt = self._load_format()

        if not self.quiet:
            print(f"Current key: {fmt.key_id}")

        success, secrets, dec_key = self._decrypt_data(fmt, retry=not self.quiet)
        if not success:
            raise RuntimeError("Failed to decrypt lockbox")

        if not self.quiet:
            print(f"Decrypted with key: {dec_key}")
            print(f"Re-encrypting with key: {new_key_id}")

        secrets_json = json.dumps(secrets, separators=(",", ":")).encode("utf-8")
        success, encrypted = self.gpg.encrypt(
            secrets_json, new_key_id, retry=not self.quiet
        )
        if not success:
            raise RuntimeError("Failed to encrypt with new key")

        fmt.key_id = new_key_id
        fmt.encrypted_data = encrypted

        data_to_sign = fmt.key_id.encode("utf-8") + encrypted
        success, signature = self.gpg.sign(data_to_sign, new_key_id, retry=True)
        if success:
            fmt.signature = signature
        else:
            fmt.signature = None

        self._save_lockbox(fmt)

        if not self.quiet:
            print(f"Lockbox re-keyed to: {new_key_id}")

    def dump_secrets(self, format: str = "list") -> Dict:
        """Dump all secrets (non-TOTP form)."""
        fmt = self._load_format()

        if not self.quiet:
            print(f"Encrypted with key: {fmt.key_id}", file=sys.stderr)

        success, secrets, dec_key = self._decrypt_data(fmt, retry=not self.quiet)
        if not success:
            raise RuntimeError("Failed to decrypt lockbox")

        if not self.quiet:
            print(f"Decrypted with key: {dec_key}", file=sys.stderr)

        result = {}
        for name, entry in secrets.items():
            result[name] = entry["value"]

        return result
