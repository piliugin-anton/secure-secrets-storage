# Security Policy

## Overview

This document outlines the security model, threat analysis, and vulnerability reporting procedures for Secure Secrets Storage.

## Security Model

### Design Principles

1. **Defense in Depth**: Multiple layers of security (encryption, authentication, integrity checks)
2. **Fail Securely**: Errors result in denial of access, never in exposure of secrets
3. **Least Privilege**: Files use strictest possible permissions (owner-only)
4. **Memory Safety**: Rust's memory safety + explicit zeroization of sensitive data
5. **Cryptographic Agility**: Versioned format allows algorithm upgrades

### Threat Model

#### ✅ Protected Against

| Threat | Protection Mechanism | Details |
|--------|---------------------|---------|
| **Offline Password Guessing** | Argon2id (256MB, 3 iter) | GPU/ASIC-resistant, ~1-2 sec/attempt |
| **Rollback Attacks** | Monotonic counter + HMAC | Detects restored old vault versions |
| **Tampering Detection** | HMAC-SHA256 | Any modification detected before decryption |
| **Replay Attacks** | Counter verification | Each save increments counter atomically |
| **Data Corruption** | Authenticated encryption | Poly1305 MAC detects bit flips |
| **Memory Dumps** | Zeroization + mlockall | Secrets cleared from RAM, pages locked |
| **Core Dumps** | rlimit RLIMIT_CORE=0 | Core dumps disabled (Unix) |
| **Concurrent Access** | File locking | Prevents race conditions and corruption |
| **Information Leakage** | Constant-time operations | Cryptographic libraries use constant-time crypto |
| **Unauthorized File Access** | 0600 permissions (Unix), ACL (Windows) | Only owner can read/write |

#### ⚠️ Partially Protected Against

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| **Side-Channel Attacks** | Constant-time crypto | Local timing attacks still possible |
| **Memory Extraction (Cold Boot)** | Memory locking | Physical access can bypass |
| **Keyloggers** | None | Passphrase entered via terminal is vulnerable |
| **Screen Capture** | None | Displayed secrets can be captured |
| **Malicious Terminal** | None | Trust in terminal emulator required |

#### ❌ NOT Protected Against

| Threat | Why Not Protected | Recommended Mitigation |
|--------|------------------|----------------------|
| **Root/Admin Access** | Root can bypass all protections | Use hardware security modules (HSM), secure boot |
| **Kernel Exploits** | Kernel has full memory access | Keep OS updated, use security modules (SELinux, AppArmor) |
| **Physical Access** | Attacker can copy files, extract RAM | Full disk encryption, physical security |
| **Compromised System** | Malware can capture passphrase | Use dedicated, hardened system for secrets |
| **Social Engineering** | User reveals passphrase | User training, 2FA for access to system |
| **Supply Chain Attacks** | Compiler/dependency compromise | Verify checksums, use reproducible builds |

### Cryptographic Specifications

#### Algorithms

| Component | Algorithm | Key Size | Notes |
|-----------|-----------|----------|-------|
| **Encryption** | XChaCha20-Poly1305 | 256-bit | Authenticated encryption, extended nonce |
| **KDF** | Argon2id v1.3 | 256-bit output | Memory: 256MB, Iterations: 3, Parallelism: 4 |
| **HMAC** | HMAC-SHA256 | 256-bit | For authentication and counter integrity |
| **Key Derivation** | HKDF-SHA256 | 256-bit | Domain separation for enc/auth keys |

#### Security Parameters

```rust
// Password-based key derivation (production)
Argon2id {
    memory: 256 MB,      // 262,144 KB
    iterations: 3,       // Time cost
    parallelism: 4,      // Number of threads
    output_len: 64 bytes // Master key size
}

// Key derivation from master key
HKDF-SHA256 {
    salt: random_salt,         // 32 bytes per vault
    info: "vault-encryption-key-v2" | "vault-authentication-key-v2"
    output_len: 32 bytes       // Per derived key
}

// Encryption
XChaCha20-Poly1305 {
    key: 256 bits,
    nonce: 192 bits,     // Extended nonce prevents reuse
    tag: 128 bits        // Authentication tag
}
```

#### Security Margins

- **Argon2id Memory**: 256MB provides strong GPU resistance
  - GPU attack: ~1000x slower than CPU
  - ASIC attack: Still expensive due to memory bandwidth
  
- **XChaCha20 Nonce**: 192 bits eliminates birthday bound concerns
  - Can safely generate 2^96 random nonces (vs. 2^64 for ChaCha20)
  
- **HMAC-SHA256**: 256-bit output provides 128-bit security
  - Collision resistance: 2^128 operations
  - Preimage resistance: 2^256 operations

### Known Limitations

#### 1. **Single Point of Failure: Passphrase**
The passphrase is the sole authentication factor. Compromise = total breach.

**Mitigations:**
- Use strong, unique passphrase (12+ characters)
- Consider key derivation from hardware token (future enhancement)
- Regular key rotation

#### 2. **No Forward Secrecy**
Compromised passphrase allows decryption of all historical backups.

**Mitigations:**
- Regular key rotation creates temporal boundaries
- Delete old backups after verification
- Consider separate backup encryption keys

#### 3. **Metadata Leakage**
File sizes reveal approximate number/size of secrets.

**Impact:** Low - attacker learns vault contains "~10 secrets of ~500 bytes total"

#### 4. **Timing Side Channels**
Argon2id duration may vary slightly based on CPU load.

**Impact:** Very low - ~50ms variance in 1-2 second operation

#### 5. **Test Mode Uses Weaker Parameters**
Test builds use 8MB Argon2 (vs. 256MB production) to prevent OOM.

**Mitigation:** Never use test builds for production data

### Compliance & Standards

#### Aligned With:

- ✅ **OWASP Password Storage Cheat Sheet** - Argon2id recommended KDF
- ✅ **NIST SP 800-63B** - Password-based authentication guidelines
- ✅ **NIST SP 800-132** - Password-based key derivation
- ✅ **FIPS 140-2** - Algorithms (not certified, but compatible)

#### Cryptographic Libraries:

All cryptographic implementations from **RustCrypto** project:
- `argon2` - Memory-hard password hashing
- `chacha20poly1305` - Authenticated encryption
- `hmac` - Message authentication
- `hkdf` - Key derivation
- `sha2` - Hash functions

These are **pure Rust** implementations (no C dependencies), reducing supply chain risk.

## Vulnerability Reporting

### Reporting a Vulnerability

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report via:

1. **Email**: security@yourdomain.com (preferred)
2. **PGP Key**: [Key fingerprint if available]

### What to Include

Please provide:

1. **Description** of the vulnerability
2. **Steps to reproduce** (proof of concept)
3. **Impact assessment** (what can an attacker do?)
4. **Affected versions** (if known)
5. **Suggested fix** (if you have one)

### Response Timeline

| Stage | Timeline | Action |
|-------|----------|--------|
| **Acknowledgment** | 48 hours | Confirm receipt of report |
| **Initial Assessment** | 7 days | Severity evaluation, reproduction |
| **Fix Development** | 30 days | Develop, test, review fix |
| **Disclosure** | 90 days | Public disclosure (coordinated) |

### Severity Classification

#### Critical (CVSS 9.0-10.0)
- Remote code execution
- Authentication bypass
- Cryptographic break (full plaintext recovery)

#### High (CVSS 7.0-8.9)
- Partial cryptographic weakness
- Rollback protection bypass
- Memory disclosure of secrets

#### Medium (CVSS 4.0-6.9)
- Side-channel attacks requiring local access
- Denial of service (crash)
- Information leakage (metadata)

#### Low (CVSS 0.1-3.9)
- Minor information disclosure
- Theoretical attacks requiring impractical resources

### Bug Bounty

Currently, this project does **not** have a bug bounty program. However, we greatly appreciate responsible disclosure and will publicly acknowledge your contribution (with your permission).

## Security Audits

### Status

⚠️ **This software has NOT undergone a formal security audit.**

### Recommended Audit Scope

If you are considering using this for critical applications, we recommend auditing:

1. **Cryptographic Implementation**
   - Key derivation (Argon2id parameters)
   - Encryption/decryption (XChaCha20-Poly1305)
   - HMAC verification
   - Random number generation

2. **Rollback Protection**
   - Counter increment ordering
   - HMAC verification of counter
   - Lock acquisition order

3. **File Handling**
   - Atomic operations (temp + rename)
   - Lock ordering (preventing deadlocks)
   - Permission setting (cross-platform)

4. **Memory Safety**
   - Zeroization of sensitive data
   - Memory locking effectiveness
   - Buffer handling in crypto operations

5. **Concurrency**
   - Race conditions in file operations
   - Lock contention handling
   - State consistency

## Security Updates

### Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |

### Update Policy

- **Critical vulnerabilities**: Patch within 7 days, immediate notification
- **High vulnerabilities**: Patch within 30 days
- **Medium/Low**: Addressed in next regular release

### Notification Channels

Security advisories published via:
- GitHub Security Advisories
- Release notes (tagged `[SECURITY]`)
- Mailing list (if established)

## Secure Development Practices

### Code Review

All changes undergo:
- Automated testing (100+ test cases)
- Clippy lints (`cargo clippy -- -D warnings`)
- Manual review for security-sensitive code

### Testing

```bash
# Run full test suite
cargo test -- --test-threads=1

# Security-specific tests
cargo test rollback_protection
cargo test tampering_detection
cargo test concurrency_tests
```

### Dependencies

Security-critical dependencies are:
- Pinned to specific versions
- Reviewed before updates
- Monitored via `cargo audit`

```bash
# Check for known vulnerabilities
cargo install cargo-audit
cargo audit
```

## Operational Security Recommendations

### Deployment

1. **Use dedicated user account** for vault access
2. **Enable full disk encryption** (LUKS, BitLocker, FileVault)
3. **Restrict file access** to vault directory
4. **Disable swap** or use encrypted swap
5. **Run on hardened OS** with security modules (SELinux, AppArmor)

### Passphrase Management

1. **Minimum 12 characters**, mixed case, numbers, symbols
2. **Use passphrase generator** (diceware, password manager)
3. **Never reuse** across different vaults or systems
4. **Change regularly** (annually or after suspected compromise)
5. **Don't store in plaintext** anywhere

### Backup Strategy

1. **Encrypt backups** before cloud storage (additional layer)
2. **Test restores** periodically
3. **Store offline copies** on separate media
4. **Version backups** to maintain history
5. **Delete old backups** after verification (reduce exposure window)

### Access Control

```bash
# Linux/macOS: Restrict vault directory
chmod 700 vault_directory
chown user:user vault_directory

# Create dedicated user for vault access
sudo useradd -r -s /bin/false vault-user
sudo chown vault-user:vault-user /path/to/vault/

# Use sudo to access vault
sudo -u vault-user secure-secrets-storage list
```

### Monitoring

Monitor for:
- Unexpected vault file modifications
- Failed authentication attempts (in audit log)
- Permission changes on vault files
- Unusual process access patterns

## Incident Response

### If You Suspect Compromise

1. **Immediately change passphrase**
   ```bash
   secure-secrets-storage change-passphrase
   ```

2. **Rotate encryption keys**
   ```bash
   secure-secrets-storage emergency-rotate
   ```

3. **Review audit log** for suspicious activity
   ```bash
   secure-secrets-storage audit
   ```

4. **Verify vault integrity**
   ```bash
   secure-secrets-storage verify
   ```

5. **Rotate all stored secrets** (API keys, passwords, etc.)

6. **Investigate** how compromise occurred

7. **Report** if vulnerability found in software

### If Passphrase Lost

⚠️ **There is NO recovery mechanism.** This is by design.

Options:
- Restore from backup (if passphrase known)
- Secrets are permanently inaccessible

### If Files Corrupted

```bash
# Try to verify what's wrong
secure-secrets-storage verify

# Restore from most recent backup
secure-secrets-storage restore /path/to/backup.bak

# If verification shows rollback attack, investigate:
# - Was old backup restored accidentally?
# - Is system time correct?
# - Has storage been tampered with?
```

## FAQ

**Q: Is this quantum-resistant?**  
A: No. XChaCha20 and SHA256 are vulnerable to quantum attacks. Post-quantum migration planned for future versions.

**Q: Can I use this for production systems?**  
A: Use with caution. This software has not been formally audited. Suitable for non-critical applications. For critical systems, consider professional solutions with security audits.

**Q: Why no multi-user support?**  
A: Single passphrase = single user keeps security model simple and auditable. Multi-user requires complex key management and access control.

**Q: Can I access vault from multiple machines?**  
A: Not recommended. Concurrent access across network can cause corruption. Use backup/restore for migration instead.

**Q: Is this FIPS 140-2 certified?**  
A: No. Uses compatible algorithms but not certified. Certification requires extensive testing and validation.

**Q: How do I verify the binary isn't backdoored?**  
A: Build from source yourself, verify checksums, or use reproducible builds (future feature).

---

**Last Updated**: 2025-12-28  
**Version**: 1.0.0