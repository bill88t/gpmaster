#!/bin/bash
# Quick test script for GPMaster functionality
# This demonstrates basic usage without installing

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║           GPMaster Quick Test Script                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if we're in the right directory
if [ ! -f "gpmaster/cli.py" ]; then
    echo "Error: Please run this script from the gpmaster2 directory"
    exit 1
fi

# Check Python version
echo "Checking Python version..."
python --version
echo ""

# Run tests
echo "Running test suite..."
python -m pytest tests/ -v || python -m unittest discover -s tests -v
echo ""

# Show CLI help
echo "Showing CLI help..."
python -m gpmaster.cli --help
echo ""

# Show example commands
echo "╔════════════════════════════════════════════════════════════╗"
echo "║           Example Usage                                    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "To use gpmaster, first get your GPG key ID:"
echo "  $ gpg --list-secret-keys --keyid-format LONG"
echo ""
echo "Then create a lockbox:"
echo "  $ gpmaster create YOUR_GPG_KEY_ID"
echo ""
echo "Add secrets:"
echo "  $ gpmaster add github_token"
echo "  $ gpmaster add google_2fa --totp"
echo ""
echo "Retrieve secrets:"
echo "  $ gpmaster get github_token"
echo "  $ gpmaster get google_2fa --totp-code"
echo ""
echo "Show lockbox info:"
echo "  $ gpmaster info"
echo ""
echo "Validate lockbox:"
echo "  $ gpmaster validate"
echo ""
echo "For more examples, see EXAMPLES.md"
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║           Installation                                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Arch Linux:"
echo "  $ makepkg -si"
echo ""
echo "Debian/Ubuntu:"
echo "  $ dpkg-buildpackage -b -uc -us"
echo "  $ sudo dpkg -i ../gpmaster_1.0.0-1_all.deb"
echo ""
echo "From Source:"
echo "  $ pip install ."
echo ""
echo "For detailed installation instructions, see INSTALL.md"
echo ""
