# GPMaster Usage Examples

## Basic Workflow

### 1. First Time Setup

```bash
# Set your default GPG key ID
export GPMASTER_KEY_ID="YOUR_KEY_ID"

# Optional: Use a custom lockbox location
export GPMASTER_LOCKBOX_PATH="~/Documents/secrets.gpb"

# Create the lockbox
gpmaster create $GPMASTER_KEY_ID
```

### 2. Adding Secrets

```bash
# Add a simple password
gpmaster add github_password
# Enter secret: MySecurePassword123

# Add an API token
gpmaster add stripe_api_key
# Enter secret: sk_live_1234567890abcdef

# Add a TOTP secret for 2FA
gpmaster add google_2fa --totp
# Enter secret: JBSWY3DPEHPK3PXP

# Auto-create lockbox if it doesn't exist
gpmaster add first_secret --key-id YOUR_KEY_ID
```

### 3. Retrieving Secrets

```bash
# Get a password (outputs to stdout)
gpmaster get github_password

# Get and copy to clipboard (Linux with xclip)
gpmaster get github_password | xclip -selection clipboard

# Get and use in a script
TOKEN=$(gpmaster get stripe_api_key)
curl -H "Authorization: Bearer $TOKEN" https://api.stripe.com/v1/charges

# Generate TOTP code
gpmaster get google_2fa --totp-code
# Output: 123456

# Use TOTP in automation
CODE=$(gpmaster get google_2fa --totp-code)
./login_script.sh "$CODE"
```

### 4. Managing Secrets

```bash
# Show lockbox info
gpmaster info

# Rename a secret
gpmaster rename old_github_token new_github_token

# Delete a secret
gpmaster delete obsolete_password

# Edit notes document (opens $EDITOR and signs)
gpmaster note

# Validate lockbox integrity
gpmaster validate
```

## Advanced Usage

### Multiple Lockboxes

```bash
# Work lockbox
gpmaster -l ~/work/secrets.gpb create WORK_KEY_ID
gpmaster -l ~/work/secrets.gpb add aws_access_key

# Personal lockbox
gpmaster -l ~/personal/secrets.gpb create PERSONAL_KEY_ID
gpmaster -l ~/personal/secrets.gpb add email_password

# Query different lockboxes
gpmaster -l ~/work/secrets.gpb info
gpmaster -l ~/personal/secrets.gpb info
```

### Quiet Mode for Scripts

```bash
# Quiet mode with -q flag
gpmaster -q get api_key

# Or with environment variable
export GPMASTER_QUIET=1
gpmaster get api_key

# Perfect for automation
#!/bin/bash
export GPMASTER_QUIET=1
API_KEY=$(gpmaster get production_api)
curl -H "Authorization: Bearer $API_KEY" https://api.example.com/data
```

### Re-keying a Lockbox

```bash
# Change to a new GPG key
gpmaster rekey NEW_KEY_ID

# Useful when:
# - Rotating keys for security
# - Moving to a hardware token
# - Sharing with different team members
```

### TOTP Workflow

```bash
# Add TOTP secrets from various services
gpmaster add github_2fa --totp
# Enter secret: [base32 secret from GitHub]

gpmaster add aws_mfa --totp
# Enter secret: [base32 secret from AWS]

gpmaster add discord_2fa --totp
# Enter secret: [base32 secret from Discord]

# Generate codes on demand
gpmaster get github_2fa --totp-code

# Interactive TOTP viewer (shows all TOTP codes with timer)
gpmaster get -i github_2fa

# Login automation example
#!/bin/bash
USERNAME="myuser"
PASSWORD=$(gpmaster get github_password)
TOTP=$(gpmaster get github_2fa --totp-code)

echo "Logging in..."
# Use these credentials with your automation tool
```

### Dumping Secrets

```bash
# List all secrets (default format)
gpmaster dump
# Output:
# github_password: MySecurePassword123
# api_key: sk_live_1234567890abcdef

# Export as JSON
gpmaster dump --format json
# Output:
# {
#   "github_password": "MySecurePassword123",
#   "api_key": "sk_live_1234567890abcdef"
# }

# Export as shell variables
gpmaster dump --format sh
# Output:
# GITHUB_PASSWORD='MySecurePassword123'
# API_KEY='sk_live_1234567890abcdef'

# Eval into shell (be careful!)
eval $(gpmaster -q dump --format sh)
echo $API_KEY  # Now available as shell variable
```

## Integration Examples

### SSH Key Passphrase

```bash
# Store SSH key passphrase
gpmaster add ssh_key_passphrase

# Use with ssh-add
eval $(ssh-agent)
gpmaster get ssh_key_passphrase | ssh-add ~/.ssh/id_rsa
```

### Database Connections

```bash
# Store database credentials
gpmaster add postgres_password
gpmaster add mysql_root_password

# Use in connection strings
DB_PASS=$(gpmaster -q get postgres_password)
psql "postgresql://user:$DB_PASS@localhost/mydb"

# Or in config files (be careful!)
DB_PASS=$(gpmaster -q get mysql_root_password)
echo "password=$DB_PASS" >> ~/.my.cnf
chmod 600 ~/.my.cnf
```

### API Development

```bash
# Store development API keys
gpmaster add stripe_test_key
gpmaster add twilio_sid
gpmaster add twilio_auth_token

# Use in .env file generation
cat > .env <<EOF
STRIPE_KEY=$(gpmaster -q get stripe_test_key)
TWILIO_SID=$(gpmaster -q get twilio_sid)
TWILIO_AUTH=$(gpmaster -q get twilio_auth_token)
EOF

# Or use dump to generate .env file
gpmaster -q dump --format sh > .env

# Load into current shell
eval $(gpmaster -q dump --format sh)
```

### Backup and Restore

```bash
# Backup your lockbox
cp ~/.local/state/gpmaster.gpb ~/backups/gpmaster-$(date +%Y%m%d).gpb

# Restore from backup
cp ~/backups/gpmaster-20260130.gpb ~/.local/state/gpmaster.gpb

# Verify after restore
gpmaster validate
```

## Security Best Practices

```bash
# Always validate after any operation
gpmaster validate

# Use hardware tokens when possible
# (gpmaster handles token failures with retry logic)

# Don't expose secrets in logs
gpmaster -q get secret >/dev/null  # Check if secret exists
if [ $? -eq 0 ]; then
    SECRET=$(gpmaster -q get secret)
    # Use $SECRET without logging it
fi

# Secure your lockbox file permissions
chmod 600 ~/.local/state/gpmaster.gpb

# Regular audits
gpmaster info  # Review what secrets you have
gpmaster note  # Edit notes to add audit information
```

## Troubleshooting

```bash
# GPG card/token failures
# gpmaster will automatically prompt to retry on failures
# Press Enter to retry, or Ctrl+C to abort

# Force validation
gpmaster validate

# Check what key is used
gpmaster info  # Shows "Encrypted with key: KEY_ID"

# Recreate corrupted lockbox (LOSES ALL SECRETS!)
# Make sure you have a backup first!
rm ~/.local/state/gpmaster.gpb
gpmaster create YOUR_KEY_ID
# Re-add all secrets manually
```

## Shell Aliases

Add to your `.bashrc` or `.zshrc`:

```bash
# Quick aliases
alias gpm='gpmaster'
alias gpget='gpmaster get'
alias gpadd='gpmaster add'
alias gpinfo='gpmaster info'
alias gpval='gpmaster validate'
alias gpdump='gpmaster dump'

# Get and copy to clipboard
alias gpc='gpmaster get "$1" | xclip -selection clipboard'

# TOTP shortcut
alias gpotp='gpmaster get "$1" --totp-code'

# Load all secrets into shell
alias gpload='eval $(gpmaster -q dump --format sh)'
```
