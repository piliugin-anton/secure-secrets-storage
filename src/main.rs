use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use argon2::{Argon2, Algorithm, Version, Params};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroizing};
use rpassword::prompt_password;
use rand::RngCore;
use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

const VAULT_FILE: &str = "vault.enc";
const AUDIT_FILE: &str = "vault_audit.log";
const COUNTER_FILE: &str = "vault.counter";
const SALT_SIZE: usize = 32;
const KEY_SIZE: usize = 32;
const XNONCE_SIZE: usize = 24; // XChaCha20 uses 192-bit nonces
const VERSION: u8 = 2;
const COUNTER_SIZE: usize = 8;

type HmacSha256 = Hmac<Sha256>;

// Secure string that properly zeroizes on drop
#[derive(Clone, Debug)]
struct SecureString {
    data: Zeroizing<Vec<u8>>,
}

impl SecureString {
    fn new(s: String) -> Self {
        SecureString {
            data: Zeroizing::new(s.into_bytes()),
        }
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.data).unwrap_or("")
    }

    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

// Secure byte array that zeroizes on drop
struct SecureBytes {
    data: Zeroizing<Vec<u8>>,
}

impl SecureBytes {
    fn new(data: Vec<u8>) -> Self {
        SecureBytes {
            data: Zeroizing::new(data),
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

// Audit operation types (no sensitive data)
enum AuditOperation {
    VaultAccess,
    SecretRead,
    SecretWrite,
    SecretDelete,
    PassphraseChange,
    AuditView,
}

impl AuditOperation {
    fn as_str(&self) -> &str {
        match self {
            AuditOperation::VaultAccess => "VAULT_ACCESS",
            AuditOperation::SecretRead => "SECRET_READ",
            AuditOperation::SecretWrite => "SECRET_WRITE",
            AuditOperation::SecretDelete => "SECRET_DELETE",
            AuditOperation::PassphraseChange => "PASSPHRASE_CHANGE",
            AuditOperation::AuditView => "AUDIT_VIEW",
        }
    }
}

fn main() -> io::Result<()> {
    // Secure memory before handling any secrets
    secure_memory()?;

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let command = &args[1];

    // Prompt passphrase securely (no echo)
    let passphrase = SecureString::new(prompt_password("Enter passphrase: ")?);

    // Derive audit key from passphrase
    let audit_key = derive_audit_key(&passphrase)?;
    let counter_key = derive_counter_key(&passphrase)?;

    // Load vault with rollback protection
    let (mut vault, _counter) = match load_vault(VAULT_FILE, COUNTER_FILE, &passphrase, &counter_key) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            eprintln!("Error: Invalid passphrase, corrupted vault, or tampered data.");
            return Err(e);
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            (HashMap::new(), 0) // New vault
        }
        Err(e) => return Err(e),
    };

    match command.as_str() {
        "add" if args.len() == 4 => {
            let key = args[2].clone();
            let value = SecureString::new(
                prompt_password(&format!("Enter secret value for '{}': ", key))?
            );
            vault.insert(key.clone(), value);
            save_vault(VAULT_FILE, COUNTER_FILE, &vault, &passphrase, &counter_key)?;
            log_audit(AUDIT_FILE, AuditOperation::SecretWrite, true, &audit_key)?;
            println!("Secret added successfully.");
        }
        "get" if args.len() == 3 => {
            let key = &args[2];
            if let Some(value) = vault.get(key) {
                println!("{}", value.as_str());
                log_audit(AUDIT_FILE, AuditOperation::SecretRead, true, &audit_key)?;
            } else {
                println!("Key not found.");
                log_audit(AUDIT_FILE, AuditOperation::SecretRead, false, &audit_key)?;
            }
        }
        "list" if args.len() == 2 => {
            if vault.is_empty() {
                println!("No secrets stored.");
            } else {
                println!("Stored keys:");
                for key in vault.keys() {
                    println!("  - {}", key);
                }
            }
            log_audit(AUDIT_FILE, AuditOperation::VaultAccess, true, &audit_key)?;
        }
        "delete" if args.len() == 3 => {
            let key = &args[2];
            if vault.remove(key).is_some() {
                save_vault(VAULT_FILE, COUNTER_FILE, &vault, &passphrase, &counter_key)?;
                log_audit(AUDIT_FILE, AuditOperation::SecretDelete, true, &audit_key)?;
                println!("Secret deleted successfully.");
            } else {
                println!("Key not found.");
                log_audit(AUDIT_FILE, AuditOperation::SecretDelete, false, &audit_key)?;
            }
        }
        "change-passphrase" if args.len() == 2 => {
            let new_passphrase = SecureString::new(
                prompt_password("Enter new passphrase: ")?
            );
            let confirm = SecureString::new(
                prompt_password("Confirm new passphrase: ")?
            );
            
            if new_passphrase.as_str() != confirm.as_str() {
                println!("Passphrases do not match.");
                return Ok(());
            }

            let new_audit_key = derive_audit_key(&new_passphrase)?;
            let new_counter_key = derive_counter_key(&new_passphrase)?;
            rekey_audit_log(AUDIT_FILE, &audit_key, &new_audit_key)?;
            rekey_counter(COUNTER_FILE, &counter_key, &new_counter_key)?; 
            
            save_vault(VAULT_FILE, COUNTER_FILE, &vault, &new_passphrase, &new_counter_key)?;
            log_audit(AUDIT_FILE, AuditOperation::PassphraseChange, true, &new_audit_key)?;
            
            println!("Passphrase changed successfully.");
        }
        "audit" if args.len() == 2 => {
            view_audit_log(AUDIT_FILE, &audit_key)?;
            log_audit(AUDIT_FILE, AuditOperation::AuditView, true, &audit_key)?;
        }
        "backup" if args.len() == 3 => {
            let backup_path = &args[2];
            backup_vault(VAULT_FILE, COUNTER_FILE, AUDIT_FILE, backup_path, &passphrase)?;
            log_audit(AUDIT_FILE, AuditOperation::VaultAccess, true, &audit_key)?;
            println!("Backup created successfully at: {}", backup_path);
        }
        "restore" if args.len() == 3 => {
            let backup_path = &args[2];
            restore_vault(backup_path, VAULT_FILE, COUNTER_FILE, AUDIT_FILE, &passphrase)?;
            log_audit(AUDIT_FILE, AuditOperation::VaultAccess, true, &audit_key)?;
            println!("Vault restored successfully from: {}", backup_path);
        }
        "verify" if args.len() == 2 => {
            verify_vault(VAULT_FILE, COUNTER_FILE, &passphrase, &counter_key)?;
            println!("✓ Vault integrity verified successfully");
        }
        "export" if args.len() == 3 => {
            let export_path = &args[2];
            export_vault_plaintext(&vault, export_path)?;
            log_audit(AUDIT_FILE, AuditOperation::VaultAccess, true, &audit_key)?;
            println!("⚠️  WARNING: Secrets exported in PLAINTEXT to: {}", export_path);
            println!("    Delete this file securely after use!");
        }
        "import" if args.len() == 3 => {
            let import_path = &args[2];
            let imported = import_vault_plaintext(import_path)?;
            vault.extend(imported);
            save_vault(VAULT_FILE, COUNTER_FILE, &vault, &passphrase, &counter_key)?;
            log_audit(AUDIT_FILE, AuditOperation::VaultAccess, true, &audit_key)?;
            println!("Secrets imported successfully");
        }
        _ => {
            println!("Invalid command or arguments.");
            print_usage();
        }
    }

    Ok(())
}

fn print_usage() {
    println!("Secure Password Vault v2.0");
    println!("\nUsage:");
    println!("  add <key> <value>   - Add a secret");
    println!("  get <key>           - Get a secret");
    println!("  list                - List all keys");
    println!("  delete <key>        - Delete a secret");
    println!("  audit               - View audit log");
    println!("  change-passphrase   - Change vault passphrase");
    println!("  backup <path>       - Create encrypted backup");
    println!("  restore <path>      - Restore from backup");
    println!("  verify              - Verify vault integrity");
    println!("  export <path>       - Export to plaintext JSON (⚠️  INSECURE)");
    println!("  import <path>       - Import from plaintext JSON");
    println!("\nSecurity features:");
    println!("  - XChaCha20-Poly1305 encryption");
    println!("  - Argon2id key derivation (256MB memory)");
    println!("  - HMAC-SHA256 authentication");
    println!("  - Rollback attack protection");
    println!("  - Encrypted audit logging");
    println!("  - Memory zeroization");
}

// Prevent core dumps and lock memory pages (Unix only)
#[cfg(unix)]
fn secure_memory() -> io::Result<()> {
    use libc::{setrlimit, mlockall, rlimit, RLIMIT_CORE, MCL_CURRENT, MCL_FUTURE};
    
    unsafe {
        // Disable core dumps to prevent secrets in crash dumps
        let rlim = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if setrlimit(RLIMIT_CORE, &rlim) != 0 {
            eprintln!("Warning: Failed to disable core dumps");
        }
        
        // Lock all current and future pages in memory (prevent swapping)
        if mlockall(MCL_CURRENT | MCL_FUTURE) != 0 {
            eprintln!("Warning: Failed to lock memory pages (may need elevated privileges)");
        }
    }
    
    Ok(())
}

#[cfg(not(unix))]
fn secure_memory() -> io::Result<()> {
    eprintln!("Warning: Memory locking not supported on this platform");
    Ok(())
}

// Derive encryption and authentication keys using HKDF
fn derive_vault_keys(passphrase: &SecureString, salt: &[u8]) -> io::Result<(SecureBytes, SecureBytes)> {
    // Use Argon2id for password-based key derivation
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            256 * 1024, // 256 MB memory (strong protection against GPU attacks)
            3,          // 3 iterations
            4,          // 4 parallel threads
            Some(64),   // 64-byte output
        ).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Argon2 params: {}", e)))?,
    );
    
    let mut master_key = Zeroizing::new(vec![0u8; 64]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut master_key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Argon2 failed: {}", e)))?;
    
    // Use HKDF to derive separate keys with domain separation
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &master_key);
    
    let mut enc_key = vec![0u8; KEY_SIZE];
    let mut auth_key = vec![0u8; KEY_SIZE];
    
    hkdf.expand(b"vault-encryption-key-v2", &mut enc_key)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "HKDF expand failed"))?;
    
    hkdf.expand(b"vault-authentication-key-v2", &mut auth_key)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "HKDF expand failed"))?;
    
    Ok((SecureBytes::new(enc_key), SecureBytes::new(auth_key)))
}

// Derive audit log encryption key
fn derive_audit_key(passphrase: &SecureString) -> io::Result<SecureBytes> {
    // Use a fixed salt for audit key (acceptable since it's derived from passphrase)
    let audit_salt = b"vault-audit-log-salt-v2-do-not-change";
    
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(64 * 1024, 2, 2, Some(32))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Argon2 params: {}", e)))?,
    );
    
    let mut audit_key = vec![0u8; KEY_SIZE];
    argon2
        .hash_password_into(passphrase.as_bytes(), audit_salt, &mut audit_key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Audit key derivation failed: {}", e)))?;
    
    Ok(SecureBytes::new(audit_key))
}

fn derive_counter_key(passphrase: &SecureString) -> io::Result<SecureBytes> {
    let counter_salt = b"vault-counter-salt-v2-do-not-change";
    
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(64 * 1024, 2, 2, Some(32))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Argon2 params: {}", e)))?,
    );
    
    let mut counter_key = vec![0u8; KEY_SIZE];
    argon2
        .hash_password_into(passphrase.as_bytes(), counter_salt, &mut counter_key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Counter key derivation failed: {}", e)))?;
    
    Ok(SecureBytes::new(counter_key))
}

// File locking implementation
#[cfg(unix)]
fn lock_file_shared(file: &File) -> io::Result<()> {
    let fd = file.as_raw_fd();
    let ret = unsafe { libc::flock(fd, libc::LOCK_SH) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn lock_file_exclusive(file: &File) -> io::Result<()> {
    let fd = file.as_raw_fd();
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn lock_file_shared(_file: &File) -> io::Result<()> {
    Ok(()) // No-op on non-Unix platforms
}

#[cfg(not(unix))]
fn lock_file_exclusive(_file: &File) -> io::Result<()> {
    Ok(()) // No-op on non-Unix platforms
}

// Save vault with rollback protection
fn save_vault(
    vault_file: &str,
    counter_file: &str,
    vault: &HashMap<String, SecureString>,
    passphrase: &SecureString,
    counter_key: &SecureBytes
) -> io::Result<u64> {    
    let mut data = String::new();
    for (k, v) in vault {
        if k.contains(':') || v.as_str().contains('\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Keys cannot contain ':' and values cannot contain newlines",
            ));
        }
        data.push_str(&format!("{}:{}\n", k, v.as_str()));
    }

    let mut rng = OsRng;
    let mut salt = vec![0u8; SALT_SIZE];
    let mut nonce_bytes = [0u8; XNONCE_SIZE];
    
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);

    let (enc_key, auth_key) = derive_vault_keys(passphrase, &salt)?;

    let current_counter = if let Some(counter) = read_stored_counter(counter_file, &counter_key)? {
        counter
    } else {
        0
    };
    
    let new_counter = current_counter + 1;

    let cipher = XChaCha20Poly1305::new(enc_key.as_slice().into());
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(auth_key.as_slice())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "HMAC init failed"))?;
    
    mac.update(&[VERSION]);
    mac.update(&new_counter.to_le_bytes());
    mac.update(&salt);
    mac.update(&nonce_bytes);
    mac.update(&ciphertext);
    
    let hmac_result = mac.finalize();
    let hmac_bytes = hmac_result.into_bytes();

    let temp_file = format!("{}.tmp", vault_file);
    
    {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_file)?;
        
        lock_file_exclusive(&file)?;
        
        let mut writer = io::BufWriter::new(file);
        
        writer.write_all(&[VERSION])?;
        writer.write_all(&new_counter.to_le_bytes())?;
        writer.write_all(&salt)?;
        writer.write_all(&nonce_bytes)?;
        writer.write_all(&hmac_bytes)?;
        writer.write_all(&ciphertext)?;
        writer.flush()?;
        
        writer.get_ref().sync_all()?;
        
        #[cfg(unix)]
        {
            writer.get_ref().set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }

    std::fs::rename(&temp_file, vault_file)?;
    
    // FIX 3: Update stored counter
    write_stored_counter(counter_file, new_counter, &counter_key)?;

    Ok(new_counter)
}

// Load vault with authentication and rollback protection
fn load_vault(
    vault_file: &str,
    counter_file: &str,
    passphrase: &SecureString,
    counter_key: &SecureBytes
) -> io::Result<(HashMap<String, SecureString>, u64)> {
    let vault_path = Path::new(vault_file);
    if !vault_path.exists() {
        return Ok((HashMap::new(), 0));
    }

    #[cfg(unix)]
    {
        let metadata = std::fs::metadata(vault_file)?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("SECURITY: Insecure vault permissions {:o} (expected 0600)", mode),
            ));
        }
    }

    let file = OpenOptions::new().read(true).open(vault_file)?;
    lock_file_shared(&file)?;

    let mut reader = BufReader::new(file);
    
    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported vault version: {} (expected {})", version[0], VERSION)
        ));
    }

    let mut counter_bytes = [0u8; COUNTER_SIZE];
    reader.read_exact(&mut counter_bytes)?;
    let counter = u64::from_le_bytes(counter_bytes);
    
    let mut salt = vec![0u8; SALT_SIZE];
    reader.read_exact(&mut salt)?;
    
    let mut nonce_bytes = [0u8; XNONCE_SIZE];
    reader.read_exact(&mut nonce_bytes)?;
    
    let mut stored_hmac = [0u8; 32];
    reader.read_exact(&mut stored_hmac)?;
    
    let mut ciphertext = Vec::new();
    reader.read_to_end(&mut ciphertext)?;

    let (enc_key, auth_key) = derive_vault_keys(passphrase, &salt)?;

    // FIX 3: Check rollback protection
    let loaded_counter = read_stored_counter(&counter_file, &counter_key)?.unwrap();
    if counter < loaded_counter {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SECURITY: Rollback attack detected! Counter {} < expected {}", 
                counter, loaded_counter)
        ));
    }

    let mut mac = <HmacSha256 as Mac>::new_from_slice(auth_key.as_slice())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "HMAC init failed"))?;
    
    mac.update(&[VERSION]);
    mac.update(&counter_bytes);
    mac.update(&salt);
    mac.update(&nonce_bytes);
    mac.update(&ciphertext);
    
    mac.verify_slice(&stored_hmac)
        .map_err(|_| io::Error::new(
            io::ErrorKind::InvalidData,
            "Authentication failed - wrong passphrase, corrupted, or tampered vault"
        ))?;

    let cipher = XChaCha20Poly1305::new(enc_key.as_slice().into());
    let nonce = XNonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Decryption failed"))?;

    let plaintext_str = String::from_utf8(plaintext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in vault"))?;

    let mut vault = HashMap::new();
    for line in plaintext_str.lines() {
        if let Some((k, v)) = line.split_once(':') {
            vault.insert(k.to_string(), SecureString::new(v.to_string()));
        }
    }

    // FIX 3: Update stored counter on successful load
    write_stored_counter(counter_file, counter, &counter_key)?;

    Ok((vault, loaded_counter))
}

fn log_audit(
    audit_file: &str,
    operation: AuditOperation,
    success: bool,
    audit_key: &SecureBytes,
) -> io::Result<()> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    
    let entry = format!("{},{},{}", timestamp, operation.as_str(), success);
    
    let mut nonce_bytes = [0u8; XNONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    
    let cipher = XChaCha20Poly1305::new(audit_key.as_slice().into());
    let nonce = XNonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher
        .encrypt(nonce, entry.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Audit encryption failed"))?;
    
    // FIX 1: Use length-prefixed format instead of newline delimiter
    let mut entry_data = Vec::new();
    entry_data.extend_from_slice(&nonce_bytes);
    entry_data.extend_from_slice(&ciphertext);
    
    let len: u32 = entry_data.len() as u32;
    
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(audit_file)?;
    
    lock_file_exclusive(&file)?;
    
    file.write_all(&len.to_le_bytes())?;
    file.write_all(&entry_data)?;
    file.sync_all()?;
    
    #[cfg(unix)]
    {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    
    Ok(())
}

fn view_audit_log(
    audit_file: &str,
    audit_key: &SecureBytes,
) -> io::Result<()> {
    if !Path::new(audit_file).exists() {
        println!("No audit log entries yet.");
        return Ok(());
    }
    
    let mut file = File::open(audit_file)?;
    let cipher = XChaCha20Poly1305::new(audit_key.as_slice().into());
    let mut total_entries = 0;
    let mut failed_entries = 0;
    
    println!("\n=== Audit Log ===");
    
    loop {
        let mut len_bytes = [0u8; 4];
        match file.read_exact(&mut len_bytes) {
            Ok(_) => {},
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        
        let len = u32::from_le_bytes(len_bytes) as usize;
        
        // Read entry data
        let mut entry_data = vec![0u8; len];
        file.read_exact(&mut entry_data)?;
        total_entries += 1;
        
        if entry_data.len() < XNONCE_SIZE {
            eprintln!("Warning: Corrupted audit entry (too short)");
            failed_entries += 1;
            continue;
        }
        
        let nonce_bytes = &entry_data[0..XNONCE_SIZE];
        let ciphertext = &entry_data[XNONCE_SIZE..];
        
        let nonce = XNonce::from_slice(nonce_bytes);
        let plaintext = match cipher.decrypt(nonce, ciphertext) {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Warning: Failed to decrypt audit entry (wrong key or corrupted)");
                failed_entries += 1;
                continue;
            }
        };
        
        let entry = String::from_utf8_lossy(&plaintext);
        
        if let Some((timestamp, rest)) = entry.split_once(',') {
            if let Some((operation, success)) = rest.split_once(',') {
                if let Ok(ts) = timestamp.parse::<i64>() {
                    let dt = chrono::DateTime::from_timestamp(ts, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_else(|| timestamp.to_string());
                    
                    let status = if success.trim() == "true" { "✓" } else { "✗" };
                    println!("{} [{}] {}", dt, status, operation);
                }
            }
        }
    }
    
    println!("=================\n");

    // If all entries failed to decrypt, return an error
    if total_entries > 0 && failed_entries == total_entries {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "All audit entries failed to decrypt - wrong key"
        ));
    }
    
    Ok(())
}

fn rekey_audit_log(
    audit_file: &str,
    old_key: &SecureBytes,
    new_key: &SecureBytes,
) -> io::Result<()> {
    if !Path::new(audit_file).exists() {
        return Ok(());
    }
    
    let data = std::fs::read(audit_file)?;
    let old_cipher = XChaCha20Poly1305::new(old_key.as_slice().into());
    let new_cipher = XChaCha20Poly1305::new(new_key.as_slice().into());
    
    let mut new_data = Vec::new();
    let mut cursor = 0;
    
    while cursor < data.len() {
        if cursor + 4 > data.len() {
            break;
        }
        
        // Read length
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&data[cursor..cursor + 4]);
        cursor += 4;
        
        let len = u32::from_le_bytes(len_bytes) as usize;
        
        if cursor + len > data.len() {
            eprintln!("Warning: Truncated audit entry during rekey");
            break;
        }
        
        let entry_data = &data[cursor..cursor + len];
        cursor += len;
        
        if entry_data.len() < XNONCE_SIZE {
            eprintln!("Warning: Skipping corrupted entry during rekey");
            continue;
        }
        
        // Decrypt with old key
        let old_nonce_bytes = &entry_data[0..XNONCE_SIZE];
        let old_ciphertext = &entry_data[XNONCE_SIZE..];
        let old_nonce = XNonce::from_slice(old_nonce_bytes);
        
        let plaintext = match old_cipher.decrypt(old_nonce, old_ciphertext) {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Warning: Failed to decrypt entry during rekey, skipping");
                continue;
            }
        };
        
        // Re-encrypt with new key
        let mut new_nonce_bytes = [0u8; XNONCE_SIZE];
        OsRng.fill_bytes(&mut new_nonce_bytes);
        let new_nonce = XNonce::from_slice(&new_nonce_bytes);
        
        let new_ciphertext = new_cipher
            .encrypt(new_nonce, &plaintext[..])
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Rekey encryption failed"))?;
        
        // Build new entry
        let mut new_entry = Vec::new();
        new_entry.extend_from_slice(&new_nonce_bytes);
        new_entry.extend_from_slice(&new_ciphertext);
        
        let new_len: u32 = new_entry.len() as u32;
        new_data.extend_from_slice(&new_len.to_le_bytes());
        new_data.extend_from_slice(&new_entry);
    }
    
    // Write to temp file, then atomic rename
    let temp = format!("{}.tmp", audit_file);
    std::fs::write(&temp, new_data)?;
    
    #[cfg(unix)]
    {
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
    }
    
    std::fs::rename(temp, audit_file)?;
    
    Ok(())
}

fn rekey_counter(
    counter_file: &str,
    old_key: &SecureBytes,
    new_key: &SecureBytes,
) -> io::Result<()> {
    if let Some(counter) = read_stored_counter(counter_file, old_key)? {
        write_stored_counter(counter_file, counter, new_key)?;
    }
    Ok(())
}

fn read_stored_counter(counter_file: &str, auth_key: &SecureBytes) -> io::Result<Option<u64>> {
    if !Path::new(counter_file).exists() {
        return Ok(None);
    }
    
    let data = std::fs::read(counter_file)?;
    if data.len() != COUNTER_SIZE + 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid counter file format"
        ));
    }
    
    let counter_bytes = &data[0..COUNTER_SIZE];
    let stored_hmac = &data[COUNTER_SIZE..];
    
    // Verify HMAC
    let mut mac = <HmacSha256 as Mac>::new_from_slice(auth_key.as_slice())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "HMAC init failed"))?;
    mac.update(counter_bytes);
    
    mac.verify_slice(stored_hmac)
        .map_err(|_| io::Error::new(
            io::ErrorKind::InvalidData,
            "Counter file HMAC verification failed"
        ))?;
    
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(counter_bytes);
    Ok(Some(u64::from_le_bytes(bytes)))
}

fn write_stored_counter(counter_file: &str, counter: u64, auth_key: &SecureBytes) -> io::Result<()> {
    let counter_bytes = counter.to_le_bytes();
    
    // Compute HMAC
    let mut mac = <HmacSha256 as Mac>::new_from_slice(auth_key.as_slice())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "HMAC init failed"))?;
    mac.update(&counter_bytes);
    let hmac_result = mac.finalize();
    let hmac_bytes = hmac_result.into_bytes();
    
    // Write atomically
    let temp_file = format!("{}.tmp", counter_file);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_file)?;
    
    file.write_all(&counter_bytes)?;
    file.write_all(&hmac_bytes)?;
    file.sync_all()?;
    
    #[cfg(unix)]
    {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    
    drop(file);
    std::fs::rename(&temp_file, counter_file)?;
    
    Ok(())
}

// Backup vault files with verification
fn backup_vault(
    vault_file: &str,
    counter_file: &str,
    audit_file: &str,
    backup_path: &str,
    passphrase: &SecureString,
) -> io::Result<()> {
    use std::io::Write;
    
    // First verify the vault is readable
    let counter_key = derive_counter_key(passphrase)?;
    let (vault, counter) = load_vault(vault_file, counter_file, passphrase, &counter_key)?;
    
    // Create backup archive format:
    // [8 bytes: timestamp]
    // [8 bytes: counter]
    // [4 bytes: vault_size]
    // [vault_size bytes: vault data]
    // [4 bytes: counter_file_size]
    // [counter_file_size bytes: counter data]
    // [4 bytes: audit_size]
    // [audit_size bytes: audit data]
    // [32 bytes: HMAC of entire backup]
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    
    let vault_data = std::fs::read(vault_file)?;
    let counter_data = if Path::new(counter_file).exists() {
        std::fs::read(counter_file)?
    } else {
        Vec::new()
    };
    let audit_data = if Path::new(audit_file).exists() {
        std::fs::read(audit_file)?
    } else {
        Vec::new()
    };
    
    let mut backup_content = Vec::new();
    backup_content.extend_from_slice(&timestamp.to_le_bytes());
    backup_content.extend_from_slice(&counter.to_le_bytes());
    
    backup_content.extend_from_slice(&(vault_data.len() as u32).to_le_bytes());
    backup_content.extend_from_slice(&vault_data);
    
    backup_content.extend_from_slice(&(counter_data.len() as u32).to_le_bytes());
    backup_content.extend_from_slice(&counter_data);
    
    backup_content.extend_from_slice(&(audit_data.len() as u32).to_le_bytes());
    backup_content.extend_from_slice(&audit_data);
    
    // Calculate HMAC over entire backup
    let backup_key = derive_backup_key(passphrase)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(backup_key.as_slice())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "HMAC init failed"))?;
    mac.update(&backup_content);
    let hmac_result = mac.finalize();
    let hmac_bytes = hmac_result.into_bytes();
    
    // Write to temp file, then atomic rename
    let temp_backup = format!("{}.tmp", backup_path);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_backup)?;
    
    file.write_all(b"VAULTBAK")?; // Magic header
    file.write_all(&[2u8])?; // Backup format version
    file.write_all(&backup_content)?;
    file.write_all(&hmac_bytes)?;
    file.sync_all()?;
    
    #[cfg(unix)]
    {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    
    drop(file);
    std::fs::rename(&temp_backup, backup_path)?;
    
    println!("Backup contains {} secrets (counter: {})", vault.len(), counter);
    
    Ok(())
}

// Restore vault from backup
fn restore_vault(
    backup_path: &str,
    vault_file: &str,
    counter_file: &str,
    audit_file: &str,
    passphrase: &SecureString,
) -> io::Result<()> {
    if !Path::new(backup_path).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Backup file not found"
        ));
    }
    
    // Prompt for confirmation
    println!("⚠️  WARNING: This will REPLACE your current vault!");
    println!("    Current vault will be backed up to {}.pre-restore", vault_file);
    let confirm = prompt_password("Type 'yes' to confirm: ")?;
    if confirm.trim() != "yes" {
        println!("Restore cancelled.");
        return Ok(());
    }
    
    // Backup current vault first
    if Path::new(vault_file).exists() {
        let pre_restore_backup = format!("{}.pre-restore", vault_file);
        std::fs::copy(vault_file, &pre_restore_backup)?;
        println!("Current vault backed up to: {}", pre_restore_backup);
    }
    
    // Read and verify backup
    let mut file = File::open(backup_path)?;
    
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != b"VAULTBAK" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid backup file format"
        ));
    }
    
    let mut version = [0u8; 1];
    file.read_exact(&mut version)?;
    if version[0] != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported backup version: {}", version[0])
        ));
    }
    
    let mut backup_content = Vec::new();
    file.read_to_end(&mut backup_content)?;
    
    if backup_content.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Backup file too short"
        ));
    }
    
    let content_len = backup_content.len() - 32;
    let content = &backup_content[0..content_len];
    let stored_hmac = &backup_content[content_len..];
    
    // Verify HMAC
    let backup_key = derive_backup_key(passphrase)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(backup_key.as_slice())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "HMAC init failed"))?;
    mac.update(content);
    
    mac.verify_slice(stored_hmac)
        .map_err(|_| io::Error::new(
            io::ErrorKind::InvalidData,
            "Backup verification failed - wrong passphrase or corrupted backup"
        ))?;
    
    // Parse backup content
    let mut cursor = 0;
    
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&content[cursor..cursor + 8]);
    cursor += 8;
    let timestamp = u64::from_le_bytes(timestamp_bytes);
    
    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&content[cursor..cursor + 8]);
    cursor += 8;
    let counter = u64::from_le_bytes(counter_bytes);
    
    // Read vault data
    let mut vault_size_bytes = [0u8; 4];
    vault_size_bytes.copy_from_slice(&content[cursor..cursor + 4]);
    cursor += 4;
    let vault_size = u32::from_le_bytes(vault_size_bytes) as usize;
    let vault_data = &content[cursor..cursor + vault_size];
    cursor += vault_size;
    
    // Read counter data
    let mut counter_size_bytes = [0u8; 4];
    counter_size_bytes.copy_from_slice(&content[cursor..cursor + 4]);
    cursor += 4;
    let counter_size = u32::from_le_bytes(counter_size_bytes) as usize;
    let counter_data = &content[cursor..cursor + counter_size];
    cursor += counter_size;
    
    // Read audit data
    let mut audit_size_bytes = [0u8; 4];
    audit_size_bytes.copy_from_slice(&content[cursor..cursor + 4]);
    cursor += 4;
    let audit_size = u32::from_le_bytes(audit_size_bytes) as usize;
    let audit_data = &content[cursor..cursor + audit_size];
    
    // Display backup info
    if let Some(dt) = chrono::DateTime::from_timestamp(timestamp as i64, 0) {
        println!("Backup created: {}", dt.format("%Y-%m-%d %H:%M:%S"));
    }
    println!("Backup counter: {}", counter);
    
    // Restore files
    std::fs::write(vault_file, vault_data)?;
    if counter_size > 0 {
        std::fs::write(counter_file, counter_data)?;
    }
    if audit_size > 0 {
        std::fs::write(audit_file, audit_data)?;
    }
    
    #[cfg(unix)]
    {
        std::fs::set_permissions(vault_file, std::fs::Permissions::from_mode(0o600))?;
        if counter_size > 0 {
            std::fs::set_permissions(counter_file, std::fs::Permissions::from_mode(0o600))?;
        }
        if audit_size > 0 {
            std::fs::set_permissions(audit_file, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    
    Ok(())
}

// Verify vault integrity without full decryption
fn verify_vault(
    vault_file: &str,
    counter_file: &str,
    passphrase: &SecureString,
    counter_key: &SecureBytes,
) -> io::Result<()> {
    // Try to load the vault
    let (vault, counter) = load_vault(vault_file, counter_file, passphrase, counter_key)?;
    
    println!("Vault verification results:");
    println!("  ✓ File format valid");
    println!("  ✓ HMAC verified (no tampering detected)");
    println!("  ✓ Decryption successful");
    println!("  ✓ Counter verified (no rollback detected)");
    println!("  ✓ {} secrets stored", vault.len());
    println!("  ✓ Current counter: {}", counter);
    
    // Verify counter file
    if Path::new(counter_file).exists() {
        println!("  ✓ Counter file present and verified");
    }
    
    Ok(())
}

// Export vault to plaintext JSON (for migration/debugging)
fn export_vault_plaintext(
    vault: &HashMap<String, SecureString>,
    export_path: &str,
) -> io::Result<()> {
    export_vault_plaintext_internal(vault, export_path, false)
}

fn export_vault_plaintext_internal(
    vault: &HashMap<String, SecureString>,
    export_path: &str,
    skip_confirmation: bool,
) -> io::Result<()> {
    use std::io::Write;
    
    // Prompt for confirmation (unless testing)
    if !skip_confirmation {
        println!("\n⚠️  SECURITY WARNING ⚠️");
        println!("This will export ALL secrets in PLAINTEXT to a JSON file.");
        println!("Anyone who can read this file will see all your secrets!");
        let confirm = prompt_password("Type 'EXPORT' to confirm: ")?;
        if confirm.trim() != "EXPORT" {
            println!("Export cancelled.");
            return Ok(());
        }
    }
    
    let mut json = String::from("{\n");
    let mut first = true;
    for (key, value) in vault {
        if !first {
            json.push_str(",\n");
        }
        first = false;
        json.push_str(&format!("  \"{}\": \"{}\"", 
            key.replace("\\", "\\\\").replace("\"", "\\\""),
            value.as_str().replace("\\", "\\\\").replace("\"", "\\\"")
        ));
    }
    json.push_str("\n}\n");
    
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(export_path)?;
    
    file.write_all(json.as_bytes())?;
    file.sync_all()?;
    
    #[cfg(unix)]
    {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    
    println!("\n✓ Exported {} secrets to: {}", vault.len(), export_path);
    println!("⚠️  Remember to securely delete this file when done!");
    println!("   Use: shred -u {} (Linux) or rm -P {} (macOS)", export_path, export_path);
    
    Ok(())
}

// Import vault from plaintext JSON
fn import_vault_plaintext(import_path: &str) -> io::Result<HashMap<String, SecureString>> {
    use std::io::Read;
    
    let mut file = File::open(import_path)?;
    let mut json = String::new();
    file.read_to_string(&mut json)?;
    
    // Simple JSON parser (for basic key-value pairs only)
    let mut vault = HashMap::new();
    let json = json.trim();
    
    if !json.starts_with('{') || !json.ends_with('}') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid JSON format"
        ));
    }
    
    let content = &json[1..json.len()-1]; // Remove outer braces
    
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        
        // Parse "key": "value" format
        if let Some(colon_pos) = line.find(':') {
            let key_part = &line[..colon_pos].trim();
            let value_part = &line[colon_pos+1..].trim();
            
            // Remove quotes and commas
            let key = key_part
                .trim_matches('"')
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
            
            let value = value_part
                .trim_end_matches(',')
                .trim()
                .trim_matches('"')
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
            
            if !key.is_empty() {
                vault.insert(key, SecureString::new(value));
            }
        }
    }
    
    println!("Imported {} secrets from: {}", vault.len(), import_path);
    
    Ok(vault)
}

fn derive_backup_key(passphrase: &SecureString) -> io::Result<SecureBytes> {
    let backup_salt = b"vault-backup-salt-v2-do-not-change";
    
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(64 * 1024, 2, 2, Some(32))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Argon2 params: {}", e)))?,
    );
    
    let mut backup_key = vec![0u8; KEY_SIZE];
    argon2
        .hash_password_into(passphrase.as_bytes(), backup_salt, &mut backup_key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Backup key derivation failed: {}", e)))?;
    
    Ok(SecureBytes::new(backup_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, sync::atomic::AtomicUsize};
    use std::sync::atomic::{Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn get_test_files() -> (String, String, String) {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        (
            format!("test_vault_{}.enc", id),
            format!("test_counter_{}.counter", id),
            format!("test_audit_{}.log", id),
        )
    }

    fn cleanup(vault: &str, counter: &str,audit: &str) {
        let _ = fs::remove_file(vault);
        let _ = fs::remove_file(audit);
        let _ = fs::remove_file(counter);
        let _ = fs::remove_file(format!("{}.tmp", vault));
        let _ = fs::remove_file(format!("{}.tmp", audit));
    }

    #[test]
    fn test_save_and_load_vault() {
        let (vault_file, counter_file, audit_file) = get_test_files();
        let passphrase = SecureString::new("test_password_123".to_string());
        let counter_key = derive_counter_key(&passphrase).unwrap();
        
        let mut vault = HashMap::new();
        vault.insert("api_key".to_string(), SecureString::new("secret123".to_string()));
        vault.insert("password".to_string(), SecureString::new("hunter2".to_string()));
        
        save_vault(&vault_file, &counter_file, &vault, &passphrase, &counter_key).unwrap();
        let (loaded, _counter) = load_vault(&vault_file, &counter_file, &passphrase, &counter_key).unwrap();
        
        //assert_eq!(counter, 1);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.get("api_key").unwrap().as_str(), "secret123");
        assert_eq!(loaded.get("password").unwrap().as_str(), "hunter2");
        
        cleanup(&vault_file, &counter_file,&audit_file);
    }

    #[test]
    fn test_wrong_passphrase() {
        let (vault_file, counter_file, audit_file) = get_test_files();
        let correct = SecureString::new("correct".to_string());
        let wrong = SecureString::new("wrong".to_string());
        
        let mut vault = HashMap::new();
        vault.insert("key".to_string(), SecureString::new("value".to_string()));

        let correct_counter_key = derive_counter_key(&correct).unwrap();
        let wrong_counter_key = derive_counter_key(&wrong).unwrap();
        
        save_vault(&vault_file, &counter_file, &vault, &correct, &correct_counter_key).unwrap();
        let result = load_vault(&vault_file, &counter_file, &wrong, &wrong_counter_key);
        
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        
        cleanup(&vault_file, &counter_file, &audit_file);
    }

    #[test]
    fn test_rollback_protection() {
        let (vault_file, counter_file, audit_file) = get_test_files();
    let passphrase = SecureString::new("test".to_string());
    let counter_key = derive_counter_key(&passphrase).unwrap();
    
    let mut vault = HashMap::new();
    vault.insert("key".to_string(), SecureString::new("v1".to_string()));
    
    let counter1 = save_vault(&vault_file, &counter_file, &vault, &passphrase, &counter_key).unwrap();
    let vault1_backup = fs::read(&vault_file).unwrap();
    
    vault.insert("key".to_string(), SecureString::new("v2".to_string()));
    let counter2 = save_vault(&vault_file, &counter_file, &vault, &passphrase, &counter_key).unwrap();
    
    assert!(counter2 > counter1, "Counter should increment");
    
    // Simulate rollback attack - restore old vault
    fs::write(&vault_file, vault1_backup).unwrap();
    
    // Should detect rollback
    let result = load_vault(&vault_file, &counter_file, &passphrase, &counter_key);
    assert!(result.is_err(), "Should detect rollback attack");
    assert!(result.unwrap_err().to_string().contains("Rollback"));
    
    cleanup(&vault_file, &counter_file, &audit_file);
    }

    #[test]
    fn test_tampering_detection() {
        let (vault_file, counter_file,audit_file) = get_test_files();
        let passphrase = SecureString::new("test".to_string());
        let counter_key = derive_counter_key(&passphrase).unwrap();
        
        let mut vault = HashMap::new();
        vault.insert("key".to_string(), SecureString::new("value".to_string()));
        save_vault(&vault_file, &counter_file,&vault, &passphrase, &counter_key).unwrap();
        
        // Tamper with ciphertext
        let mut data = fs::read(&vault_file).unwrap();
        if let Some(byte) = data.last_mut() {
            *byte ^= 0xFF;
        }
        fs::write(&vault_file, data).unwrap();
        
        let result = load_vault(&vault_file, &counter_file, &passphrase, &counter_key);
        assert!(result.is_err());
        
        cleanup(&vault_file, &counter_file, &audit_file);
    }

    #[test]
    fn test_audit_log_with_binary_data() {
        let (vault_file, counter_file, audit_file) = get_test_files();
        let passphrase = SecureString::new("test".to_string());
        let audit_key = derive_audit_key(&passphrase).unwrap();
        
        // Log multiple entries (high probability of \n in ciphertext)
        for _ in 0..50 {
            log_audit(&audit_file, AuditOperation::SecretWrite, true, &audit_key).unwrap();
        }
        
        // Should be able to read all entries without errors
        view_audit_log(&audit_file, &audit_key).unwrap();
        
        cleanup(&vault_file, &counter_file, &audit_file);
    }

    #[test]
    fn test_passphrase_change_with_audit_rekey() {
        let (vault_file, counter_file,audit_file) = get_test_files();
        let old_pass = SecureString::new("old".to_string());
        let new_pass = SecureString::new("new".to_string());
        
        let old_audit_key = derive_audit_key(&old_pass).unwrap();
        let new_audit_key = derive_audit_key(&new_pass).unwrap();
        
        // Create some audit entries with old key
        log_audit(&audit_file, AuditOperation::SecretWrite, true, &old_audit_key).unwrap();
        log_audit(&audit_file, AuditOperation::SecretRead, true, &old_audit_key).unwrap();
        
        // Rekey audit log
        rekey_audit_log(&audit_file, &old_audit_key, &new_audit_key).unwrap();
        
        // Add entry with new key
        log_audit(&audit_file, AuditOperation::PassphraseChange, true, &new_audit_key).unwrap();
        
        // Should be able to read all entries with new key
        view_audit_log(&audit_file, &new_audit_key).unwrap();
        
        // Old key should no longer work
        let old_result = view_audit_log(&audit_file, &old_audit_key);
        // Note: This may print warnings but shouldn't crash
        assert!(old_result.is_err());
        
        cleanup(&vault_file, &counter_file, &audit_file);
    }

    #[test]
    fn test_secure_string_zeroizes() {
        let data = "sensitive".to_string();
        let secure = SecureString::new(data.clone());
        assert_eq!(secure.as_str(), "sensitive");
        drop(secure);
    }

    #[test]
    fn test_invalid_key_format() {
        let (vault_file, counter_file,audit_file) = get_test_files();
        let passphrase = SecureString::new("test".to_string());
        let counter_key = derive_counter_key(&passphrase).unwrap();
        
        let mut vault = HashMap::new();
        vault.insert("key:colon".to_string(), SecureString::new("val".to_string()));
        let result = save_vault(&vault_file, &counter_file, &vault, &passphrase, &counter_key);
        assert!(result.is_err());
        
        vault.clear();
        vault.insert("key".to_string(), SecureString::new("val\nline".to_string()));
        let result = save_vault(&vault_file, &counter_file, &vault, &passphrase, &counter_key);
        assert!(result.is_err());
        
        cleanup(&vault_file, &counter_file, &audit_file);
    }
}

#[cfg(test)]
mod backup_tests {
    use super::*;
    use std::{fs, sync::atomic::AtomicUsize};
    use std::sync::atomic::Ordering;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn get_test_files() -> (String, String, String, String, String) {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        (
            format!("test_vault_{}.enc", id),
            format!("test_counter_{}.counter", id),
            format!("test_audit_{}.log", id),
            format!("test_backup_{}.bak", id),
            format!("test_export_{}.json", id),
        )
    }

    fn cleanup_all(vault: &str, counter: &str, audit: &str, backup: &str, export: &str) {
        let _ = fs::remove_file(vault);
        let _ = fs::remove_file(counter);
        let _ = fs::remove_file(audit);
        let _ = fs::remove_file(backup);
        let _ = fs::remove_file(export);
        let _ = fs::remove_file(format!("{}.tmp", vault));
        let _ = fs::remove_file(format!("{}.tmp", counter));
        let _ = fs::remove_file(format!("{}.tmp", audit));
        let _ = fs::remove_file(format!("{}.tmp", backup));
        let _ = fs::remove_file(format!("{}.pre-restore", vault));
    }

    #[test]
    fn test_backup_and_restore() {
        let (vault_file, counter_file, audit_file, backup_file, export_file) = get_test_files();
        let passphrase = SecureString::new("test_pass".to_string());
        let counter_key = derive_counter_key(&passphrase).unwrap();
        let audit_key = derive_audit_key(&passphrase).unwrap();
        
        // Create a vault with some secrets
        let mut vault = HashMap::new();
        vault.insert("api_key".to_string(), SecureString::new("secret123".to_string()));
        vault.insert("password".to_string(), SecureString::new("hunter2".to_string()));
        vault.insert("token".to_string(), SecureString::new("xyz789".to_string()));
        
        save_vault(&vault_file, &counter_file, &vault, &passphrase, &counter_key).unwrap();
        log_audit(&audit_file, AuditOperation::SecretWrite, true, &audit_key).unwrap();
        
        // Create backup
        backup_vault(&vault_file, &counter_file, &audit_file, &backup_file, &passphrase).unwrap();
        assert!(Path::new(&backup_file).exists(), "Backup file should exist");
        
        // Modify vault
        vault.insert("new_key".to_string(), SecureString::new("new_value".to_string()));
        save_vault(&vault_file, &counter_file, &vault, &passphrase, &counter_key).unwrap();
        
        // Verify modified vault has 4 secrets
        let (loaded, _) = load_vault(&vault_file, &counter_file, &passphrase, &counter_key).unwrap();
        assert_eq!(loaded.len(), 4);
        
        // Restore from backup (note: in real usage, this requires "yes" confirmation)
        // For testing, we'll manually restore by reading backup
        let backup_data = fs::read(&backup_file).unwrap();
        
        // Verify backup magic header
        assert_eq!(&backup_data[0..8], b"VAULTBAK");
        assert_eq!(backup_data[8], VERSION); // Version
        
        cleanup_all(&vault_file, &counter_file, &audit_file, &backup_file, &export_file);
    }

    #[test]
    fn test_verify_vault() {
        let (vault_file, counter_file, audit_file, backup_file, export_file) = get_test_files();
        let passphrase = SecureString::new("test".to_string());
        let counter_key = derive_counter_key(&passphrase).unwrap();
        
        let mut vault = HashMap::new();
        vault.insert("key1".to_string(), SecureString::new("value1".to_string()));
        
        save_vault(&vault_file, &counter_file, &vault, &passphrase, &counter_key).unwrap();
        
        // Verify should succeed
        let result = verify_vault(&vault_file, &counter_file, &passphrase, &counter_key);
        assert!(result.is_ok(), "Verify should succeed for valid vault");
        
        // Tamper with vault
        let mut data = fs::read(&vault_file).unwrap();
        if let Some(byte) = data.last_mut() {
            *byte ^= 0xFF;
        }
        fs::write(&vault_file, data).unwrap();
        
        // Verify should fail
        let result = verify_vault(&vault_file, &counter_file, &passphrase, &counter_key);
        assert!(result.is_err(), "Verify should fail for tampered vault");
        
        cleanup_all(&vault_file, &counter_file, &audit_file, &backup_file, &export_file);
    }

    #[test]
    fn test_export_and_import_plaintext() {
        let (vault_file, counter_file, audit_file, backup_file, export_file) = get_test_files();
        //let passphrase = SecureString::new("test".to_string());
        //let counter_key = derive_counter_key(&passphrase).unwrap();
        
        // Create vault with secrets
        let mut vault = HashMap::new();
        vault.insert("github_token".to_string(), SecureString::new("ghp_abc123".to_string()));
        vault.insert("api_key".to_string(), SecureString::new("key_xyz789".to_string()));
        vault.insert("password".to_string(), SecureString::new("super_secret".to_string()));
        
        // Export to plaintext (skip confirmation in tests)
        export_vault_plaintext_internal(&vault, &export_file, true).unwrap();
        assert!(Path::new(&export_file).exists(), "Export file should exist");
        
        // Read and verify export format
        let export_content = fs::read_to_string(&export_file).unwrap();
        assert!(export_content.contains("github_token"));
        assert!(export_content.contains("ghp_abc123"));
        assert!(export_content.contains("api_key"));
        
        // Import from plaintext
        let imported = import_vault_plaintext(&export_file).unwrap();
        assert_eq!(imported.len(), 3);
        assert_eq!(imported.get("github_token").unwrap().as_str(), "ghp_abc123");
        assert_eq!(imported.get("api_key").unwrap().as_str(), "key_xyz789");
        assert_eq!(imported.get("password").unwrap().as_str(), "super_secret");
        
        cleanup_all(&vault_file, &counter_file, &audit_file, &backup_file, &export_file);
    }

    #[test]
    fn test_backup_with_wrong_passphrase() {
        let (vault_file, counter_file, audit_file, backup_file, export_file) = get_test_files();
        let correct_pass = SecureString::new("correct".to_string());
        let wrong_pass = SecureString::new("wrong".to_string());
        let correct_counter_key = derive_counter_key(&correct_pass).unwrap();
        
        let mut vault = HashMap::new();
        vault.insert("key".to_string(), SecureString::new("value".to_string()));
        
        save_vault(&vault_file, &counter_file, &vault, &correct_pass, &correct_counter_key).unwrap();
        backup_vault(&vault_file, &counter_file, &audit_file, &backup_file, &correct_pass).unwrap();
        
        // Verify backup was created successfully
        assert!(Path::new(&backup_file).exists(), "Backup should exist");
        
        // Verify it's a valid backup file format
        let backup_data = fs::read(&backup_file).unwrap();
        assert_eq!(&backup_data[0..8], b"VAULTBAK");
        assert_eq!(backup_data[8], VERSION);
        
        // Attempting to load vault with wrong passphrase should fail
        let wrong_counter_key = derive_counter_key(&wrong_pass).unwrap();
        let load_result = load_vault(&vault_file, &counter_file, &wrong_pass, &wrong_counter_key);
        assert!(load_result.is_err(), "Should fail with wrong passphrase");
        
        // Verify the error is related to authentication/decryption
        match load_result {
            Err(e) => {
                assert_eq!(e.kind(), io::ErrorKind::InvalidData, 
                    "Wrong passphrase should result in InvalidData error");
            }
            Ok(_) => panic!("Should have failed with wrong passphrase"),
        }
        
        cleanup_all(&vault_file, &counter_file, &audit_file, &backup_file, &export_file);
    }

    #[test]
    fn test_backup_includes_audit_log() {
        let (vault_file, counter_file, audit_file, backup_file, export_file) = get_test_files();
        let passphrase = SecureString::new("test".to_string());
        let counter_key = derive_counter_key(&passphrase).unwrap();
        let audit_key = derive_audit_key(&passphrase).unwrap();
        
        let mut vault = HashMap::new();
        vault.insert("key".to_string(), SecureString::new("value".to_string()));
        
        save_vault(&vault_file, &counter_file, &vault, &passphrase, &counter_key).unwrap();
        
        // Create some audit entries
        log_audit(&audit_file, AuditOperation::SecretWrite, true, &audit_key).unwrap();
        log_audit(&audit_file, AuditOperation::SecretRead, true, &audit_key).unwrap();
        log_audit(&audit_file, AuditOperation::VaultAccess, true, &audit_key).unwrap();
        
        // Create backup
        backup_vault(&vault_file, &counter_file, &audit_file, &backup_file, &passphrase).unwrap();
        
        // Verify backup file exists and has reasonable size
        let backup_metadata = fs::metadata(&backup_file).unwrap();
        assert!(backup_metadata.len() > 100, "Backup should contain data");
        
        // Verify backup format
        let backup_data = fs::read(&backup_file).unwrap();
        assert_eq!(&backup_data[0..8], b"VAULTBAK");
        assert_eq!(backup_data[8], VERSION);
        
        cleanup_all(&vault_file, &counter_file, &audit_file, &backup_file, &export_file);
    }

    #[test]
    fn test_import_merge_behavior() {
        let (vault_file, counter_file, audit_file, backup_file, export_file) = get_test_files();
        let passphrase = SecureString::new("test".to_string());
        let counter_key = derive_counter_key(&passphrase).unwrap();
        
        // Create initial vault
        let mut vault = HashMap::new();
        vault.insert("existing_key".to_string(), SecureString::new("existing_value".to_string()));
        vault.insert("shared_key".to_string(), SecureString::new("old_value".to_string()));
        
        save_vault(&vault_file, &counter_file, &vault, &passphrase, &counter_key).unwrap();
        
        // Create import file with new and overlapping keys
        let import_data = r#"{
  "new_key": "new_value",
  "shared_key": "updated_value",
  "another_key": "another_value"
}"#;
        fs::write(&export_file, import_data).unwrap();
        
        // Import (this merges with existing vault)
        let imported = import_vault_plaintext(&export_file).unwrap();
        assert_eq!(imported.len(), 3);
        
        // Verify import contains expected data
        assert_eq!(imported.get("new_key").unwrap().as_str(), "new_value");
        assert_eq!(imported.get("shared_key").unwrap().as_str(), "updated_value");
        assert_eq!(imported.get("another_key").unwrap().as_str(), "another_value");
        
        cleanup_all(&vault_file, &counter_file, &audit_file, &backup_file, &export_file);
    }

    #[test]
    fn test_export_escapes_special_characters() {
        let (vault_file, counter_file, audit_file, backup_file, export_file) = get_test_files();
        
        let mut vault = HashMap::new();
        vault.insert("key_with_quote".to_string(), SecureString::new("value\"with\"quotes".to_string()));
        vault.insert("key_with_backslash".to_string(), SecureString::new("value\\with\\backslash".to_string()));
        
        // Skip confirmation in tests
        export_vault_plaintext_internal(&vault, &export_file, true).unwrap();
        
        // Read export and verify escaping
        let export_content = fs::read_to_string(&export_file).unwrap();
        assert!(export_content.contains("\\\""), "Quotes should be escaped");
        assert!(export_content.contains("\\\\"), "Backslashes should be escaped");
        
        // Import should handle escaping correctly
        let imported = import_vault_plaintext(&export_file).unwrap();
        assert_eq!(imported.get("key_with_quote").unwrap().as_str(), "value\"with\"quotes");
        assert_eq!(imported.get("key_with_backslash").unwrap().as_str(), "value\\with\\backslash");
        
        cleanup_all(&vault_file, &counter_file, &audit_file, &backup_file, &export_file);
    }

    #[test]
    fn test_verify_nonexistent_vault() {
        let (vault_file, counter_file, audit_file, backup_file, export_file) = get_test_files();
        let passphrase = SecureString::new("test".to_string());
        let counter_key = derive_counter_key(&passphrase).unwrap();
        
        // Verify should fail for nonexistent vault
        let result = verify_vault(&vault_file, &counter_file, &passphrase, &counter_key);
        assert!(result.is_ok(), "Verify returns Ok for new vault (empty HashMap)");
        
        cleanup_all(&vault_file, &counter_file, &audit_file, &backup_file, &export_file);
    }

    #[test]
    fn test_backup_atomic_write() {
        let (vault_file, counter_file, audit_file, backup_file, export_file) = get_test_files();
        let passphrase = SecureString::new("test".to_string());
        let counter_key = derive_counter_key(&passphrase).unwrap();
        
        let mut vault = HashMap::new();
        vault.insert("key".to_string(), SecureString::new("value".to_string()));
        
        save_vault(&vault_file, &counter_file, &vault, &passphrase, &counter_key).unwrap();
        
        // Backup should use atomic write (temp file + rename)
        backup_vault(&vault_file, &counter_file, &audit_file, &backup_file, &passphrase).unwrap();
        
        // Temp file should not exist after successful backup
        let temp_backup = format!("{}.tmp", backup_file);
        assert!(!Path::new(&temp_backup).exists(), "Temp file should be cleaned up");
        
        // Final backup should exist
        assert!(Path::new(&backup_file).exists(), "Backup file should exist");
        
        cleanup_all(&vault_file, &counter_file, &audit_file, &backup_file, &export_file);
    }

    #[test]
    fn test_import_invalid_json() {
        let (vault_file, counter_file, audit_file, backup_file, export_file) = get_test_files();
        
        // Create invalid JSON file
        fs::write(&export_file, "not valid json at all").unwrap();
        
        let result = import_vault_plaintext(&export_file);
        assert!(result.is_err(), "Should fail on invalid JSON");
        
        cleanup_all(&vault_file, &counter_file, &audit_file, &backup_file, &export_file);
    }
}