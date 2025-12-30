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

## Multi-User API Server (WIP)

The vault now supports multi-user access via a secure REST API with role-based permissions.

### Initial Setup

#### 1. Initialize user database with admin account
```bash
secure-secrets-storage init-users admin
Enter users database passphrase: ****
Repeat users database passphrase: ****
Enter admin password: ****
Repeat admin passphrase: ****
```

Output:
```bash
✓ User database initialized
  Admin user created
```

### CLI User Management

#### List all users (requires master passphrase)
```bash
secure-secrets-storage list-users
Enter users database passphrase: ****
```

Output:
```bash
=== Users ===
  • admin (Admin)
    ID: 550e8400-e29b-41d4-a716-446655440000
    Created: 2025-12-29 10:00:00 UTC
    Last login: 2025-12-29 14:30:00 UTC
    Login count: 5

  • alice (ReadWrite)
    ID: 7c9e6679-7425-40de-944b-e07fc1f90ae7
    Created: 2025-12-29 14:45:00 UTC
    Last login: 2025-12-29 15:20:00 UTC
    Login count: 3

  • bob (ReadOnly) [LOCKED]
    ID: 9b2d5e8a-3c4f-4a5b-8d6e-1f2a3b4c5d6e
    Created: 2025-12-29 16:00:00 UTC
    Last login: None
    Login count: 0
```

#### Add new user (requires master passphrase and vault passphrase)
```bash
secure-secrets-storage add-user alice
Enter users database passphrase: ****
Enter user password: ****
Repeat user password: ****
Enter vault passphrase: ****
Repeat vault passphrase: ****
Select user role:
  1. Admin
  2. Read-only
  3. Read + Write
> 3
✓ User 'alice' created with role ReadWrite
```
### User Roles

| Role | Read Secrets | Write Secrets | Delete Secrets | Manage Users |
|------|--------------|---------------|----------------|--------------|
| **Admin** | ✅ | ✅ | ✅ | ✅ |
| **ReadWrite** | ✅ | ✅ | ✅ | ❌ |
| **ReadOnly** | ✅ | ❌ | ❌ | ❌ |

#### 2. Start API server
```bash
secure-secrets-storage api
Enter users database passphrase: ****

Output:
🔐 Starting Secure Vault API Server
   Vault: vault.enc
   User DB: users.db
   Listening on: 127.0.0.1:6666

# Custom address
secure-secrets-storage api 0.0.0.0:6666
```

### API Endpoints

#### Authentication
```bash
# Login
curl -X POST http://localhost:6666/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your_password"}'

Response:
{
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "expires_at": "2025-12-29 15:30:00 UTC",
  "username": "admin",
  "role": "Admin"
}

# Get current user info
curl -H "Authorization: Bearer <token>" \
  http://localhost:6666/api/v1/auth/whoami

# Change password
curl -X POST http://localhost:6666/api/v1/auth/change-password \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "old_password": "current_pass",
    "new_password": "new_pass"
  }'

# Logout
curl -X POST http://localhost:6666/api/v1/auth/logout \
  -H "Authorization: Bearer <token>"
```

#### Secret Management
```bash
# List all secrets
curl -H "Authorization: Bearer <token>" \
  http://localhost:6666/api/v1/secrets

# Get specific secret
curl -H "Authorization: Bearer <token>" \
  http://localhost:6666/api/v1/secrets/api_key

# Create/update secret
curl -X POST http://localhost:6666/api/v1/secrets \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"key": "api_key", "value": "secret123"}'

# Delete secret
curl -X DELETE http://localhost:6666/api/v1/secrets/api_key \
  -H "Authorization: Bearer <token>"
```

#### User Management (Admin Only)
```bash
# Create new user
curl -X POST http://localhost:6666/api/v1/admin/users \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "secure_password",
    "role": "ReadWrite"
  }'

# List all users
curl -H "Authorization: Bearer <token>" \
  http://localhost:6666/api/v1/admin/users

Response:
[
  {
    "username": "admin",
    "role": "Admin",
    "created_at": "2025-12-29 10:00:00 UTC",
    "last_login": "2025-12-29 14:30:00 UTC",
    "login_count": 5
  },
  {
    "username": "alice",
    "role": "ReadWrite",
    "created_at": "2025-12-29 14:45:00 UTC",
    "last_login": null,
    "login_count": 0
  }
]
```

#### Health Check
```bash
# No authentication required
curl http://localhost:6666/health

Response:
{
  "status": "healthy",
  "version": "1.0",
  "uptime_seconds": 3600
}
```

### Security Features

- ✅ **Argon2id password hashing** - GPU-resistant, 64MB memory per hash
- ✅ **Per-user vault passphrase encryption** - Each user's password encrypts vault access
- ✅ **Session management** - 30-minute token expiration with auto-refresh
- ✅ **Account lockout** - 5 failed attempts = 15-minute lock
- ✅ **Role-based access control** - Granular permissions per user
- ✅ **Encrypted user database** - Protected by master passphrase
- ✅ **Audit logging** - All authentication events tracked

### Architecture
```
User Login
    ↓
Password → Argon2id hash verification
    ↓
Decrypt vault passphrase (unique per user)
    ↓
Create session token (UUID, 30min expiration)
    ↓
All API requests: Authorization: Bearer <token>
    ↓
Role-based permission check
    ↓
Access vault with decrypted passphrase
```

### Shared Vault Model

All users share the same vault but authenticate separately:
- One encrypted vault containing all secrets
- Each user has the vault passphrase encrypted with their own password
- Role-based permissions control read/write/delete access
- Ideal for team secrets: API keys, DB passwords, shared credentials

### Files Created
```
vault.enc           # Encrypted secrets (shared by all users)
vault.counter       # Rollback protection
vault_audit.log     # Encrypted audit log
users.db            # Encrypted user database
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
- **No network sync**: Designed for local storage only (API provides network access)
- **Shared vault model**: All authenticated users access the same vault (role-controlled)
- **Performance**: Argon2id is intentionally slow (security vs. convenience trade-off)
- **Session storage**: Sessions stored in memory only (restart clears all sessions)

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

### "Maximum concurrent sessions exceeded"
User has reached the session limit (default: 5 per user).

**Solution**: Logout from unused sessions or wait for sessions to expire (30 minutes).

### "Account locked due to failed login attempts"
Too many failed login attempts (5+ failures).

**Solution**: Wait 15 minutes for automatic unlock, or contact admin to manually unlock.

### "Invalid or expired session"
Session token has expired or is invalid.

**Solution**: Login again to get a new session token.

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