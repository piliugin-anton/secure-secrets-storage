# Secure Secrets Storage (AI vibe-coding demo)
## ⚠️⚠️⚠️ DO NOT USE IT IN PRODUCTION ⚠️⚠️⚠️

A cryptographically secure, file-based secrets manager with comprehensive security features including rollback attack protection, encrypted audit logging, and key rotation capabilities.

## Features

### 🔐 Strong Cryptography
- **XChaCha20-Poly1305** authenticated encryption (256-bit keys)
- **Argon2id** password-based key derivation (256MB memory, GPU-resistant)
- **HMAC-SHA256** for authentication and integrity verification
- **HKDF** for secure key derivation with domain separation

### 🛡️ Security Hardening
- **Rollback attack protection** via monotonic counter with HMAC authentication
- **Memory security**: automatic zeroization of sensitive data, memory locking (Unix)
- **Secure file permissions**: owner-only read/write (0600 on Unix, ACL on Windows)
- **Core dump prevention** (Unix systems)
- **Atomic file operations** with exclusive locking to prevent corruption

### 📊 Audit & Compliance
- **Encrypted audit log** with tamper detection
- Comprehensive operation tracking (reads, writes, deletes, key rotations)
- Timestamped entries with success/failure status
- Audit log encryption tied to vault passphrase

### 🔄 Key Management
- **Key rotation** without passphrase change (re-encrypts with new salt)
- **Emergency rotation** with automatic verification
- **Passphrase change** with secure rekeying of all components
- Automatic backup creation before critical operations

### 💾 Backup & Recovery
- **Encrypted backups** with HMAC verification
- **Export/Import** functionality (plaintext JSON for migration)
- **Vault verification** command for integrity checks
- Atomic restore with pre-restore backup

## Installation

### Prerequisites
- Rust 1.70 or later
- Cargo

### Build from Source

```bash
git clone https://github.com/piliugin-anton/secure-secrets-storage.git
cd secure-secrets-storage
cargo build --release
```

The binary will be at `target/release/secure-secrets-storage`

### Install Globally

```bash
cargo install --path .
```

## Usage

### Basic Operations

```bash
# Add a secret
secure-secrets-storage add api_key
Enter passphrase: ****
Enter secret value for 'api_key': ****

# Retrieve a secret
secure-secrets-storage get api_key
Enter passphrase: ****
your-secret-value

# List all keys
secure-secrets-storage list
Enter passphrase: ****
Stored keys:
  - api_key
  - database_password
  - github_token

# Delete a secret
secure-secrets-storage delete api_key
Enter passphrase: ****
Secret deleted successfully.
```

### Security Operations

```bash
# Change passphrase
secure-secrets-storage change-passphrase
Enter passphrase: ****
Enter new passphrase: ****
Confirm new passphrase: ****
Passphrase changed successfully.

# Rotate encryption keys (same passphrase, new encryption)
secure-secrets-storage rotate-keys
Enter passphrase: ****
🔄 Re-encrypting with new keys...
✅ Keys rotated successfully

# Emergency key rotation (for suspected compromise)
secure-secrets-storage emergency-rotate
Enter passphrase: ****
Type 'ROTATE' to confirm: ROTATE
🚨 EMERGENCY KEY ROTATION
✅ Emergency rotation complete and verified

# Verify vault integrity
secure-secrets-storage verify
Enter passphrase: ****
✓ File format valid
✓ HMAC verified (no tampering detected)
✓ Decryption successful
✓ Counter verified (no rollback detected)
✓ 5 secrets stored
✓ Current counter: 42
```

### Backup & Restore

```bash
# Create encrypted backup
secure-secrets-storage backup /path/to/backup.bak
Enter passphrase: ****
Backup created successfully at: /path/to/backup.bak

# Restore from backup
secure-secrets-storage restore /path/to/backup.bak
Enter passphrase: ****
⚠️  WARNING: This will REPLACE your current vault!
Type 'yes' to confirm: yes
Vault restored successfully from: /path/to/backup.bak
```

### Import/Export

```bash
# Export to plaintext JSON (⚠️ INSECURE - for migration only)
secure-secrets-storage export secrets.json
Enter passphrase: ****
Type 'EXPORT' to confirm: EXPORT
⚠️  WARNING: Secrets exported in PLAINTEXT to: secrets.json
    Delete this file securely after use!

# Import from plaintext JSON
secure-secrets-storage import secrets.json
Enter passphrase: ****
Secrets imported successfully
```

### Audit Logging

```bash
# View audit log
secure-secrets-storage audit
Enter passphrase: ****

=== Audit Log ===
2024-01-15 14:30:22 [✓] VAULT_CREATED
2024-01-15 14:30:45 [✓] SECRET_WRITE
2024-01-15 14:31:12 [✓] SECRET_READ
2024-01-15 14:35:00 [✓] KEY_ROTATION
2024-01-15 14:40:33 [✗] SECRET_READ
=================
```

### Permission Management

```bash
# Check and fix file permissions
secure-secrets-storage check-permissions
Enter passphrase: ****
🔒 Checking file permissions...
   Vault file ... ✅ OK
   Counter file ... ⚠️  INSECURE
      → Fixed
   Audit log ... ✅ OK
```

## File Structure

```
vault.enc           # Encrypted secrets storage
vault.counter       # Monotonic counter for rollback protection
vault_audit.log     # Encrypted audit log
```

## Security Best Practices

### ✅ DO
- Use a **strong, unique passphrase** (12+ characters, mixed case, numbers, symbols)
- Keep **regular encrypted backups** in a secure location
- **Verify vault integrity** periodically with `verify` command
- **Rotate keys** annually or after suspected compromise
- **Check file permissions** regularly with `check-permissions`
- Store vault files on **encrypted storage** (full disk encryption)

### ❌ DON'T
- Share your passphrase or store it in plaintext
- Store vault files on networked/cloud storage without additional encryption
- Use the `export` command unless absolutely necessary (creates plaintext file)
- Run the application with elevated privileges unless required for memory locking
- Modify vault files directly (always use the application)

## Architecture

### Cryptographic Design

```
Passphrase (user input)
    ↓
Argon2id (256MB memory, 3 iterations)
    ↓
Master Key (64 bytes)
    ↓
HKDF-SHA256 (domain separation)
    ↓
├─ Encryption Key (32 bytes) → XChaCha20-Poly1305
└─ Authentication Key (32 bytes) → HMAC-SHA256
```

### File Format

**Vault File** (`vault.enc`):
```
[1 byte: version]
[8 bytes: counter (little-endian)]
[32 bytes: random salt]
[24 bytes: XChaCha20 nonce]
[32 bytes: HMAC-SHA256]
[variable: ciphertext]
```

**Counter File** (`vault.counter`):
```
[8 bytes: counter (little-endian)]
[32 bytes: HMAC-SHA256(counter)]
```

### Rollback Protection

1. Counter incremented **before** vault write
2. If vault write fails, next read detects counter > vault_counter
3. Attacker replacing vault with old version triggers: stored_counter > vault_counter
4. System rejects operation and alerts user

### Concurrency Model

- **Exclusive locks** for write operations (one writer at a time)
- **Shared locks** for read operations (multiple concurrent readers)
- **File-based locking** (flock on Unix, LockFileEx on Windows)
- Atomic operations with temp files + rename

## Testing

```bash
# Run all tests (sequential to avoid OOM)
cargo test -- --test-threads=1

# Run specific test module
cargo test concurrency_tests -- --test-threads=1

# Run with verbose output
cargo test -- --test-threads=1 --nocapture

# Check code coverage (requires cargo-tarpaulin)
cargo tarpaulin --out Html
```

### Test Coverage

- ✅ Cryptographic operations (encryption, decryption, key derivation)
- ✅ Rollback attack detection
- ✅ Tampering detection
- ✅ Concurrent access (multiple readers, write contention)
- ✅ Crash recovery scenarios
- ✅ Backup and restore
- ✅ Import/export functionality
- ✅ Permission handling (Unix and Windows)
- ✅ Audit log encryption and rekeying

## Performance

- **Key derivation**: ~1-2 seconds per operation (intentionally slow, GPU-resistant)
- **Encryption/Decryption**: Sub-millisecond for typical vault sizes (<1MB)
- **File I/O**: Optimized with buffered readers/writers
- **Memory**: ~256MB during key derivation, minimal during normal operations

## Platform Support

| Platform | Encryption | Rollback Protection | File Locking | Secure Permissions | Memory Locking |
|----------|-----------|---------------------|--------------|-------------------|----------------|
| Linux    | ✅        | ✅                  | ✅ (flock)   | ✅ (chmod 0600)   | ✅            |
| macOS    | ✅        | ✅                  | ✅ (flock)   | ✅ (chmod 0600)   | ✅            |
| Windows  | ✅        | ✅                  | ✅ (LockFileEx) | ✅ (ACL)       | ⚠️ (limited)  |
| BSD      | ✅        | ✅                  | ✅ (flock)   | ✅ (chmod 0600)   | ✅            |

## Limitations

- **Single vault per directory**: The application uses fixed filenames (`vault.enc`, etc.)
- **No network sync**: Designed for local storage only
- **No sharing**: One passphrase = one user (no multi-user access control)
- **Performance**: Argon2id is intentionally slow (security vs. convenience trade-off)

## Troubleshooting

### "Failed to acquire exclusive lock"
Multiple processes are accessing the vault. Wait for other operations to complete.

### "Rollback attack detected"
The vault file is older than the counter file. This could indicate:
- Restored from old backup without restoring counter
- Attempted rollback attack
- File system corruption

**Solution**: Use the most recent backup or verify vault integrity.

### "Authentication failed - wrong passphrase or tampered data"
Either:
- Incorrect passphrase entered
- Vault file has been modified/corrupted
- Wrong vault file being accessed

### "Insecure file permissions"
Vault files are readable by other users.

**Solution**: Run `check-permissions` command to fix automatically.

## Contributing

Contributions are welcome! Please see [SECURITY.md](SECURITY.md) for security-related contributions.

### Development Setup

```bash
# Clone repository
git clone https://github.com/piliugin-anton/secure-secrets-storage.git
cd secure-secrets-storage

# Run tests
cargo test -- --test-threads=1

# Check formatting
cargo fmt --check

# Run clippy
cargo clippy -- -D warnings

# Build documentation
cargo doc --open
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

For security-related issues, please see [SECURITY.md](SECURITY.md) for reporting guidelines.

**⚠️ SECURITY NOTICE**: This is cryptographic software. While it has been designed with security best practices, it has not undergone a formal security audit. Use at your own risk for non-critical applications.

## Acknowledgments

- **Argon2** - Password Hashing Competition winner
- **XChaCha20-Poly1305** - Modern authenticated encryption
- **RustCrypto** - Cryptographic implementations for Rust