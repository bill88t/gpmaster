# GPMaster Installation Guide

Complete installation instructions for all supported platforms.

## Prerequisites

### All Platforms
- Python 3.8 or higher
- GnuPG (gpg) installed on your system

### Verify Prerequisites
```bash
# Check Python version
python --version  # Should be 3.8+

# Check GnuPG installation
gpg --version

# Check you have a GPG key
gpg --list-secret-keys
```

If you don't have a GPG key:
```bash
gpg --full-generate-key
```

## Installation Methods

### Method 1: Arch Linux (Recommended for Arch)

From the project directory:

```bash
# Build and install
makepkg -si

# Verify installation
gpmaster --help
```

The PKGBUILD automatically:
- Installs Python dependencies (python-gnupg, python-pyotp)
- Installs the gpmaster command
- Installs the license file
- Uses the local git tree (no upstream download needed)

### Method 2: Debian/Ubuntu

From the project directory:

```bash
# Install build dependencies
sudo apt-get install debhelper dh-python python3-all python3-setuptools \
                     python3-build python3-installer python3-wheel \
                     python3-gnupg python3-pyotp gnupg

# Build the package
dpkg-buildpackage -b -uc -us

# Install the package
sudo dpkg -i ../gpmaster_1.0.0-1_all.deb

# Verify installation
gpmaster --help
```

### Method 3: pip (Universal)

From the project directory:

```bash
# Install with pip
pip install .

# Or in development mode
pip install -e .

# Verify installation
gpmaster --help
```

### Method 4: pip with virtualenv (Isolated)

```bash
# Create virtual environment
python -m venv gpmaster-env

# Activate it
source gpmaster-env/bin/activate  # Linux/Mac
# or
gpmaster-env\Scripts\activate  # Windows

# Install
pip install .

# Verify
gpmaster --help
```

## Post-Installation Setup

### 1. Configure Environment (Optional)

Add to your `~/.bashrc`, `~/.zshrc`, or shell config:

```bash
# Default lockbox location
export GPMASTER_LOCKBOX_PATH="$HOME/.local/state/gpmaster.gpb"

# Default GPG key for auto-creation
export GPMASTER_KEY_ID="YOUR_GPG_KEY_ID"

# Enable quiet mode by default (optional)
# export GPMASTER_QUIET=1
```

Get your GPG key ID:
```bash
gpg --list-secret-keys --keyid-format LONG
# Look for the line like: sec   rsa4096/ABCD1234EFGH5678
# The key ID is: ABCD1234EFGH5678
```

### 2. Create Your First Lockbox

```bash
# Create lockbox
gpmaster create YOUR_GPG_KEY_ID

# Add your first secret
gpmaster add test_secret

# Verify it works
gpmaster get test_secret
gpmaster list
gpmaster validate
```

### 3. Set Permissions (Important!)

```bash
# Make sure only you can read the lockbox
chmod 600 ~/.local/state/gpmaster.gpb

# Or wherever your lockbox is located
chmod 600 "$GPMASTER_LOCKBOX_PATH"
```

## Verification

### Check Installation

```bash
# Command should be available
which gpmaster

# Help should work
gpmaster --help

# Version info
python -c "import gpmaster; print(gpmaster.__version__)"
```

### Run Tests

```bash
# From project directory
cd /path/to/gpmaster2

# Run tests
python -m pytest tests/ -v

# Or with unittest
python -m unittest discover -s tests -v
```

Expected output:
```
===== 12 passed, 3 skipped in 0.05s =====
```

## Troubleshooting

### "gpmaster: command not found"

**Issue**: Command not in PATH

**Solution**:
```bash
# For pip user install
export PATH="$HOME/.local/bin:$PATH"

# Add to ~/.bashrc permanently
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### "ModuleNotFoundError: No module named 'gnupg'"

**Issue**: python-gnupg not installed

**Solution**:
```bash
pip install python-gnupg pyotp
```

### "gpg: signing failed: No secret key"

**Issue**: GPG key ID not found

**Solution**:
```bash
# List your keys
gpg --list-secret-keys --keyid-format LONG

# Use the correct key ID
gpmaster create CORRECT_KEY_ID
```

### "ValueError: Lockbox file must have .gpb extension"

**Issue**: Wrong file extension

**Solution**:
```bash
# Always use .gpb extension
gpmaster -l /path/to/secrets.gpb create KEY_ID
```

### Hardware Token Failures

**Issue**: GPG signing fails intermittently

**Solution**: gpmaster has built-in retry logic. When prompted:
```
Signing failed: [error message]
Retry signing? [Y/n]: y
```

Just press 'y' to retry. This is normal with some GPG hardware tokens.

## Updating

### Arch Linux
```bash
cd /path/to/gpmaster2
git pull  # if using git
makepkg -si --noconfirm
```

### Debian/Ubuntu
```bash
cd /path/to/gpmaster2
git pull  # if using git
dpkg-buildpackage -b -uc -us
sudo dpkg -i ../gpmaster_1.0.0-1_all.deb
```

### pip
```bash
cd /path/to/gpmaster2
git pull  # if using git
pip install --upgrade --force-reinstall .
```

## Uninstallation

### Arch Linux
```bash
sudo pacman -R gpmaster
```

### Debian/Ubuntu
```bash
sudo apt remove gpmaster
```

### pip
```bash
pip uninstall gpmaster
```

### Clean Up Data
```bash
# Remove lockbox (WARNING: deletes all secrets!)
rm ~/.local/state/gpmaster.gpb

# Or backup first
mv ~/.local/state/gpmaster.gpb ~/gpmaster-backup.gpb
```

## Next Steps

After installation:

1. **Read the README**: `cat /path/to/gpmaster2/README.md`
2. **Check Examples**: `cat /path/to/gpmaster2/EXAMPLES.md`
3. **Create your lockbox**: `gpmaster create YOUR_KEY_ID`
4. **Add some secrets**: `gpmaster add my_first_secret`
5. **Explore commands**: `gpmaster --help`

## Support

For issues:
- Check the EXAMPLES.md file for usage patterns
- Check the DEVELOPMENT.md file for technical details
- Verify your GPG setup: `gpg --list-secret-keys`
- Run tests to verify installation: `python -m pytest tests/`
