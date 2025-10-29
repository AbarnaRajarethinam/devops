# SSH Key Generator - Alternative to ssh-keygen

Since `ssh-keygen` command is not available on this system, I've created a Python-based alternative that provides the same functionality.

## Usage

### Basic Usage
```bash
python ssh_keygen.py
```
This creates an RSA 2048-bit key pair named `id_rsa` and `id_rsa.pub`

### Advanced Usage
```bash
# Generate RSA key with custom name and comment
python ssh_keygen.py -t rsa -b 2048 -f my_key -C "user@example.com"

# Generate Ed25519 key (more secure, recommended)
python ssh_keygen.py -t ed25519 -f my_ed25519_key -C "user@example.com"

# Generate ECDSA key
python ssh_keygen.py -t ecdsa -f my_ecdsa_key -C "user@example.com"

# Generate key with passphrase protection
python ssh_keygen.py -t rsa -f secure_key -N "my_passphrase" -C "user@example.com"

# Show key fingerprint after generation
python ssh_keygen.py -t rsa -f test_key --show-fingerprint
```

### Available Options
- `-t, --type`: Key type (rsa, ecdsa, ed25519) - default: rsa
- `-b, --bits`: Key size in bits (for RSA keys) - default: 2048
- `-f, --file`: Output filename - default: id_rsa
- `-C, --comment`: Comment for the key (usually email)
- `-N, --passphrase`: Passphrase for private key protection
- `--show-fingerprint`: Display key fingerprint after generation

### Key Types Supported
1. **RSA**: Traditional and widely supported (2048, 3072, 4096 bits)
2. **Ed25519**: Modern, fast, and secure (recommended for new keys)
3. **ECDSA**: Elliptic curve-based (good balance of security and performance)

### Generated Files
- **Private key** (e.g., `id_rsa`): Keep this secure, never share it
- **Public key** (e.g., `id_rsa.pub`): Safe to share, add to servers/services

### Security Notes
- Private keys are automatically set with 600 permissions (owner read/write only)
- Public keys are set with 644 permissions (owner read/write, others read)
- Use strong passphrases for additional security
- Ed25519 keys are recommended for new deployments

### Example Output
```
Generating RSA key pair...
Your identification has been saved in test_key
Your public key has been saved in test_key.pub
The key fingerprint is:
SHA256:DrCkFrwlBqQR5ue32z5trkF3L8aOzdhuw6xYsFN3AoU
```

## Requirements
- Python 3.6+
- cryptography library (automatically installed)

This tool generates keys compatible with standard SSH implementations and can be used anywhere ssh-keygen would be used.
