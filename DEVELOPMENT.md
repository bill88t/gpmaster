# GPMaster Development Guide

## Project Structure

```
gpmaster2/
├── gpmaster/              # Main package
│   ├── __init__.py       # Package init
│   ├── cli.py            # CLI interface
│   ├── format.py         # Binary format handler
│   ├── gpg_ops.py        # GPG operations wrapper
│   └── lockbox.py        # Core lockbox operations
├── tests/                 # Test suite
│   ├── __init__.py
│   ├── test_format.py    # Format tests
│   ├── test_lockbox.py   # Lockbox integration tests
│   └── test_totp.py      # TOTP tests
├── debian/                # Debian packaging
│   ├── changelog
│   ├── compat
│   ├── control
│   ├── copyright
│   ├── rules
│   └── source/format
├── PKGBUILD              # Arch Linux packaging
├── pyproject.toml        # Modern Python packaging
├── setup.py              # Legacy Python packaging
├── requirements.txt      # Dependencies
├── LICENSE               # MIT License
└── README.md             # User documentation
```

## Running Tests

```bash
# Run with pytest
python -m pytest tests/ -v

# Run with unittest
python -m unittest discover -s tests -v

# Run specific test file
python -m pytest tests/test_format.py -v
```

## Building Packages

### Arch Linux

```bash
makepkg -si
```

The PKGBUILD uses `$srcdir/..` to build from the local git tree instead of downloading from upstream.

### Debian/Ubuntu

```bash
dpkg-buildpackage -b -uc -us
sudo dpkg -i ../gpmaster_1.0.0-1_all.deb
```

### Python Wheel

```bash
python -m build --wheel --no-isolation
pip install dist/gpmaster-1.0.0-py3-none-any.whl
```

## Environment Variables

The application supports the following environment variables:

- **GPMASTER_LOCKBOX_PATH**: Default lockbox file path
  - Default: `~/.local/state/gpmaster.gpb`
  
- **GPMASTER_KEY_ID**: Default GPG key ID for auto-creating lockboxes
  - Used when adding secrets to non-existent lockboxes
  
- **GPMASTER_QUIET**: Enable quiet mode globally
  - Set to any non-empty value to enable

## Binary Format Specification

### Header Structure

```
Offset  Size    Description
------  ----    -----------
0       8       Magic: "GPMASTER"
8       1       Version (currently 1)
9       2       Key ID length (uint16, big-endian)
11      N       Key ID (UTF-8 string)
N+11    4       Metadata length (uint32, big-endian)
N+15    M       Metadata JSON (UTF-8)
M+15    4       Signature length (uint32, big-endian)
M+19    S       Signature (0 if no signature)
S+19    32      SHA256 checksum
S+51    4       Encrypted data length (uint32, big-endian)
S+55    E       Encrypted data (GPG encrypted)
```

### Metadata JSON Format

```json
{
  "titles": ["secret1", "secret2", "..."],
  "notes": ["note1", "note2", "..."]
}
```

### Encrypted Data Format

The encrypted data contains a JSON object with secrets:

```json
{
  "secret_name": {
    "value": "secret_value",
    "type": "totp"  // optional, only for TOTP secrets
  }
}
```

## Development Workflow

1. Make changes to Python code
2. Run tests: `python -m pytest tests/ -v`
3. Test CLI manually: `python -m gpmaster.cli --help`
4. Build package: `python -m build --wheel`
5. Test installation: `pip install --force-reinstall dist/*.whl`

## Code Style

- Follow PEP 8
- Use type hints where appropriate
- Keep functions focused and small
- Minimal dependencies policy
- Prefer clarity over cleverness

## Security Notes

- Titles and notes are stored UNENCRYPTED in the lockbox
- Only secret values are encrypted
- Always verify signatures when present
- Checksums prevent tampering and corruption
- GPG operations may fail on some hardware tokens (hence retry logic)

## Contributing

When contributing:

1. Maintain backward compatibility with existing lockbox files
2. Add tests for new features
3. Update README.md with new commands/features
4. Keep dependencies minimal
5. Ensure packaging still works (Arch, Debian, pip)
