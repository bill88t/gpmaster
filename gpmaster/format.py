import json
import struct
import hashlib
from typing import Dict, List, Optional, Tuple

MAGIC = b"GPMASTER"
VERSION = 1


class LockboxFormat:
    """Handle .gpb binary format with metadata and encrypted data."""

    def __init__(self):
        self.key_id: Optional[str] = None
        self.titles: List[str] = []
        self.note_content: Optional[str] = None
        self.note_signature: Optional[bytes] = None
        self.signature: Optional[bytes] = None
        self.encrypted_data: Optional[bytes] = None

    def pack(self) -> bytes:
        """Pack lockbox data into binary format."""
        if not self.key_id or self.encrypted_data is None:
            raise ValueError("key_id and encrypted_data are required")

        metadata = {"titles": self.titles, "note_content": self.note_content}
        metadata_json = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
        key_id_bytes = self.key_id.encode("utf-8")

        parts = [
            MAGIC,
            struct.pack("B", VERSION),
            struct.pack("H", len(key_id_bytes)),
            key_id_bytes,
            struct.pack("I", len(metadata_json)),
            metadata_json,
        ]

        if self.signature:
            parts.append(struct.pack("I", len(self.signature)))
            parts.append(self.signature)
        else:
            parts.append(struct.pack("I", 0))

        if self.note_signature:
            parts.append(struct.pack("I", len(self.note_signature)))
            parts.append(self.note_signature)
        else:
            parts.append(struct.pack("I", 0))

        data_before_checksum = b"".join(parts)
        checksum = hashlib.sha256(data_before_checksum + self.encrypted_data).digest()

        parts.append(checksum)
        parts.append(struct.pack("I", len(self.encrypted_data)))
        parts.append(self.encrypted_data)

        return b"".join(parts)

    @classmethod
    def unpack(cls, data: bytes) -> "LockboxFormat":
        """Unpack binary data into LockboxFormat."""
        lockbox = cls()

        if not data.startswith(MAGIC):
            raise ValueError("Invalid lockbox file: wrong magic header")

        offset = len(MAGIC)

        version = struct.unpack("B", data[offset : offset + 1])[0]
        offset += 1

        if version != VERSION:
            raise ValueError(f"Unsupported lockbox version: {version}")

        key_id_len = struct.unpack("H", data[offset : offset + 2])[0]
        offset += 2

        lockbox.key_id = data[offset : offset + key_id_len].decode("utf-8")
        offset += key_id_len

        metadata_len = struct.unpack("I", data[offset : offset + 4])[0]
        offset += 4

        metadata_json = data[offset : offset + metadata_len].decode("utf-8")
        offset += metadata_len
        metadata = json.loads(metadata_json)
        lockbox.titles = metadata.get("titles", [])
        lockbox.note_content = metadata.get("note_content")

        sig_len = struct.unpack("I", data[offset : offset + 4])[0]
        offset += 4

        if sig_len > 0:
            lockbox.signature = data[offset : offset + sig_len]
            offset += sig_len

        note_sig_len = struct.unpack("I", data[offset : offset + 4])[0]
        offset += 4

        if note_sig_len > 0:
            lockbox.note_signature = data[offset : offset + note_sig_len]
            offset += note_sig_len

        stored_checksum = data[offset : offset + 32]
        offset += 32

        encrypted_len = struct.unpack("I", data[offset : offset + 4])[0]
        offset += 4

        lockbox.encrypted_data = data[offset : offset + encrypted_len]

        data_to_hash = data[: offset - 36]
        calculated_checksum = hashlib.sha256(
            data_to_hash + lockbox.encrypted_data
        ).digest()

        if stored_checksum != calculated_checksum:
            raise ValueError("Checksum validation failed: lockbox may be corrupted")

        return lockbox

    def get_metadata(self) -> Dict:
        """Get unencrypted metadata."""
        return {
            "key_id": self.key_id,
            "titles": self.titles,
            "note_content": self.note_content,
        }
