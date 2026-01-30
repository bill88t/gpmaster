# GPMaster

A GPG-backed lockbox for secure secrets management with a custom binary format.

## Features

- **Custom Binary Format (.gpb)**: Efficient storage with unencrypted metadata for fast operations
- **GPG Encryption & Signing**: All secrets encrypted with GPG, with optional signature verification
- **TOTP Support**: Store and generate TOTP codes for two-factor authentication
- **Interactive TOTP Viewer**: Real-time TOTP code viewer with countdown timer
- **Multiple Export Formats**: Dump secrets as list, JSON, or POSIX shell variables
- **Minimal Dependencies**: Only requires `python-gnupg` and `pyotp`
- **Environment Configuration**: Customize default paths via environment variables
- **Retry Logic**: Smart retry for GPG operations when hardware tokens are unreliable
- **Quiet Mode**: Minimal output for scripting

## Installation

### Arch Linux

```bash
makepkg -si
```

### Debian/Ubuntu

```bash
dpkg-buildpackage -b -uc -us
sudo dpkg -i ../gpmaster_1.0.0-1_all.deb
```

### From Source

```bash
pip install .
```

## Quick Start

### Create a Lockbox

```bash
# Create a new lockbox with your GPG key
gpmaster create YOUR_GPG_KEY_ID

# Or set default key and auto-create on first use
export GPMASTER_KEY_ID=YOUR_GPG_KEY_ID
gpmaster add mypassword --key-id YOUR_GPG_KEY_ID
```

### Add Secrets

```bash
# Add a regular secret
gpmaster add github_token
# Enter secret: [type your secret]

# Add a TOTP secret
gpmaster add google_2fa --totp
# Enter secret: [paste your TOTP base32 secret]
```

### Retrieve Secrets

```bash
# Get a secret
gpmaster get github_token

# Generate TOTP code
gpmaster get google_2fa --totp-code

# Monitor a TOTP code
gpmaster get -i google_2fa --totp-code

```

### Dump Secrets

```bash
# Dump all secrets in list format
gpmaster dump

# Dump as JSON
gpmaster dump --format json

# Dump as POSIX shell variables (for eval)
gpmaster dump --format sh
```

### Show Lockbox Info

```bash
# List all secrets and verify note signature
gpmaster info
```

### Other Operations

```bash
# Rename a secret
gpmaster rename old_name new_name

# Delete a secret
gpmaster delete secret_name

# Edit notes document (opens $EDITOR and signs)
gpmaster note

# Validate lockbox integrity
gpmaster validate

# Change encryption key
gpmaster rekey NEW_KEY_ID
```

## Environment Variables

- `GPMASTER_LOCKBOX_PATH`: Default lockbox file path (default: `~/.local/state/gpmaster.gpb`)
- `GPMASTER_KEY_ID`: Default GPG key ID for auto-creating lockboxes
- `GPMASTER_QUIET`: Enable quiet mode globally

## Command Reference

### Global Options

- `-l, --lockbox PATH`: Specify lockbox file path
- `-q, --quiet`: Minimal output mode

### Commands

- `create KEY_ID`: Create a new lockbox
- `add NAME [--totp] [--key-id KEY]`: Add a secret
- `get NAME [--totp-code] [-i]`: Retrieve a secret
- `rename OLD NEW`: Rename a secret
- `delete NAME`: Delete a secret
- `info`: Show lockbox info and verify note signature
- `note`: Edit notes document with $EDITOR (signed)
- `validate`: Validate lockbox integrity and signature
- `rekey NEW_KEY_ID`: Change encryption key
- `dump [--format {list,json,sh}]`: Dump all secrets in various formats

## Binary Format

The `.gpb` lockbox format contains:

- Magic header: "GPMASTER"
- Version number
- GPG key ID (unencrypted)
- Metadata JSON with titles and note content (unencrypted)
- Signature (optional)
- Note signature (for signed note content)
- SHA256 checksum for integrity
- Encrypted secrets data

This design allows listing contents and viewing metadata without decryption.

## Security Considerations

- The lockbox format stores secret **titles** and **note content** unencrypted
- Note content is **signed** by the lockbox owner to ensure authenticity
- Secret **values** are always encrypted with GPG
- Signatures are verified on every access when present
- Checksums prevent corruption and tampering
- Always validate your lockbox with `gpmaster validate`

## Dependencies

- Python 3.8+
- python-gnupg
- pyotp
- GnuPG
