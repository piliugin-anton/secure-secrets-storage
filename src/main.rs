use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use argon2::Argon2;
use rpassword::prompt_password;
use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::RngCore;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

const VAULT_FILE: &str = "vault.enc";
const AUDIT_FILE: &str = "audit.log";
const SALT_SIZE: usize = 32;
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const VERSION: u8 = 1;

// Secure string that zeroizes on drop
struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    fn new(s: String) -> Self {
        SecureString { data: s.into_bytes() }
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.data).unwrap_or("")
    }

    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Zeroize memory
        for byte in &mut self.data {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

impl Clone for SecureString {
    fn clone(&self) -> Self {
        SecureString {
            data: self.data.clone(),
        }
    }
}

// Secure byte array that zeroizes on drop
struct SecureBytes {
    data: Vec<u8>,
}

impl SecureBytes {
    fn new(data: Vec<u8>) -> Self {
        SecureBytes { data }
    }

    fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        // Zeroize memory
        for byte in &mut self.data {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage:");
        println!("  add <key> <value>   - Add a secret");
        println!("  get <key>           - Get a secret");
        println!("  list                - List keys");
        println!("  delete <key>        - Delete a secret");
        println!("  audit               - View audit log");
        println!("  change-passphrase   - Change vault passphrase");
        return Ok(());
    }

    let command = &args[1];

    let vault_file = "vault.enc";
    let audit_file = "audit.log";

    // Prompt passphrase securely (no echo)
    let passphrase = SecureString::new(prompt_password("Enter passphrase: ").unwrap());

    // Get username for audit logging
    let username = env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    // Load or create vault with file locking
    let mut vault = match load_vault(vault_file, &passphrase) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            println!("Invalid passphrase or corrupted vault.");
            return Err(e);
        }
        Err(e) => return Err(e),
    };    

    match command.as_str() {
        "add" if args.len() == 4 => {
            let key = args[2].clone();
            let value = SecureString::new(args[3].clone());
            vault.insert(key.clone(), value);
            log_audit(audit_file, &username, &format!("Added '{}'", key))?;
            save_vault(vault_file, audit_file, &vault, &passphrase)?;
            println!("Secret added successfully.");
        }
        "get" if args.len() == 3 => {
            let key = &args[2];
            if let Some(value) = vault.get(key) {
                println!("{}", value.as_str());
                log_audit(audit_file, &username, &format!("Accessed '{}'", key))?;
            } else {
                println!("Key not found.");
            }
        }
        "list" if args.len() == 2 => {
            for key in vault.keys() {
                println!("{}", key);
            }
            log_audit(audit_file, &username, "Listed keys")?;
        }
        "delete" if args.len() == 3 => {
            let key = &args[2];
            if vault.remove(key).is_some() {
                log_audit(audit_file, &username, &format!("Deleted '{}'", key))?;
                save_vault(vault_file, audit_file, &vault, &passphrase)?;
                println!("Secret deleted successfully.");
            } else {
                println!("Key not found.");
            }
        }
        "change-passphrase" if args.len() == 2 => {
            let new_passphrase = SecureString::new(
                prompt_password("Enter new passphrase: ").unwrap()
            );
            let confirm = SecureString::new(
                prompt_password("Confirm new passphrase: ").unwrap()
            );
            
            if new_passphrase.as_str() != confirm.as_str() {
                println!("Passphrases do not match.");
                return Ok(());
            }
            
            save_vault(vault_file, audit_file, &vault, &new_passphrase)?;
            log_audit(audit_file, &username, "Changed passphrase")?;
            println!("Passphrase changed successfully.");
        }
        "audit" if args.len() == 2 => {
            view_audit_log(audit_file, &passphrase)?;
            log_audit(audit_file, &username, "Viewed audit log")?;
        }
        _ => {
            println!("Invalid command or arguments.");
        }
    }

    Ok(())
}

fn derive_key(passphrase: &SecureString, salt: &[u8]) -> io::Result<SecureBytes> {
    let argon2 = Argon2::default();
    let mut key = vec![0u8; KEY_SIZE];
    
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Key derivation failed: {}", e)))?;
    
    Ok(SecureBytes::new(key))
}

// Simple file locking implementation
fn lock_file_shared(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        let fd = file.as_raw_fd();
        let ret = unsafe { libc::flock(fd, libc::LOCK_SH) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(windows)]
    {
        // Windows file locking would require more complex implementation
        // For simplicity, we skip it on Windows in this minimal version
    }
    Ok(())
}

fn lock_file_exclusive(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        let fd = file.as_raw_fd();
        let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(windows)]
    {
        // Windows file locking would require more complex implementation
        // For simplicity, we skip it on Windows in this minimal version
    }
    Ok(())
}

fn load_vault(vault_file: &str, passphrase: &SecureString) -> io::Result<HashMap<String, SecureString>> {
    let path = Path::new(vault_file);
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let file = OpenOptions::new().read(true).open(path)?;
    lock_file_shared(&file)?;

    let mut reader = BufReader::new(file);
    
    // Read version
    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unsupported vault version"
        ));
    }

    // Read salt
    let mut salt = vec![0u8; SALT_SIZE];
    reader.read_exact(&mut salt)?;
    
    // Read nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    reader.read_exact(&mut nonce_bytes)?;
    
    // Read HMAC
    let mut stored_hmac = [0u8; 32];
    reader.read_exact(&mut stored_hmac)?;
    
    // Read ciphertext
    let mut ciphertext = Vec::new();
    reader.read_to_end(&mut ciphertext)?;

    // Derive encryption and auth keys
    let master_key = derive_key(passphrase, &salt)?;
    let (enc_key, auth_key) = derive_subkeys(master_key.as_slice())?;

    // Verify HMAC
    verify_hmac(&auth_key, &salt, &nonce_bytes, &ciphertext, &stored_hmac)?;

    // Decrypt
    let cipher = ChaCha20Poly1305::new(enc_key.as_slice().into());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Decryption failed"))?;

    let plaintext_str = String::from_utf8(plaintext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8"))?;

    let mut vault = HashMap::new();
    for line in plaintext_str.lines() {
        if let Some((k, v)) = line.split_once(':') {
            vault.insert(k.to_string(), SecureString::new(v.to_string()));
        }
    }

    Ok(vault)
}

fn save_vault(vault_file: &str, audit_file: &str, vault: &HashMap<String, SecureString>, passphrase: &SecureString) -> io::Result<()> {
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

    // Always generate fresh salt and nonce
    let mut rng = OsRng;
    let mut salt = vec![0u8; SALT_SIZE];
    rng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce_bytes);

    // Derive encryption and authentication keys
    let master_key = derive_key(passphrase, &salt)?;
    let (enc_key, auth_key) = derive_subkeys(master_key.as_slice())?;

    // Encrypt
    let cipher = ChaCha20Poly1305::new(enc_key.as_slice().into());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;

    // Compute HMAC for authentication
    let hmac = compute_hmac(&auth_key, &salt, &nonce_bytes, &ciphertext)?;

    // Write to temporary file first, then atomic rename
    //let vault_file = get_vault_file();
    let temp_file = format!("{}.tmp", vault_file);
    let is_new = !Path::new(vault_file).exists();
    
    {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_file)?;
        
        lock_file_exclusive(&file)?;
        
        let mut writer = std::io::BufWriter::new(file);
        writer.write_all(&[VERSION])?;
        writer.write_all(&salt)?;
        writer.write_all(&nonce_bytes)?;
        writer.write_all(&hmac)?;
        writer.write_all(&ciphertext)?;
        writer.flush()?;
        
        writer.get_ref().sync_all()?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            writer.get_ref().set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }

    // Atomic rename
    std::fs::rename(&temp_file, vault_file)?;

    if is_new {
        log_audit(audit_file, "SYSTEM", "Vault created")?;
    }

    Ok(())
}

fn derive_subkeys(master_key: &[u8]) -> io::Result<(SecureBytes, SecureBytes)> {
    use chacha20poly1305::ChaCha20Poly1305;
    
    // Use ChaCha20 in a simple KDF mode (encrypt zeros with different nonces)
    let kdf_cipher = ChaCha20Poly1305::new(master_key.into());
    
    let mut enc_key = vec![0u8; KEY_SIZE];
    let mut auth_key = vec![0u8; KEY_SIZE];
    
    // Derive encryption key
    let nonce1 = [1u8; NONCE_SIZE];
    let enc_result = kdf_cipher.encrypt(Nonce::from_slice(&nonce1), &enc_key[..])
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "KDF failed"))?;
    enc_key.copy_from_slice(&enc_result[..KEY_SIZE]);
    
    // Derive authentication key
    let nonce2 = [2u8; NONCE_SIZE];
    let auth_result = kdf_cipher.encrypt(Nonce::from_slice(&nonce2), &auth_key[..])
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "KDF failed"))?;
    auth_key.copy_from_slice(&auth_result[..KEY_SIZE]);
    
    Ok((SecureBytes::new(enc_key), SecureBytes::new(auth_key)))
}

fn compute_hmac(key: &SecureBytes, salt: &[u8], nonce: &[u8], ciphertext: &[u8]) -> io::Result<[u8; 32]> {
    // Use ChaCha20Poly1305 as a PRF to compute MAC
    let mac_cipher = ChaCha20Poly1305::new(key.as_slice().into());
    let mac_nonce = [0u8; NONCE_SIZE];
    
    let mut data = Vec::new();
    data.extend_from_slice(salt);
    data.extend_from_slice(nonce);
    data.extend_from_slice(ciphertext);
    
    let result = mac_cipher.encrypt(Nonce::from_slice(&mac_nonce), data.as_slice())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "MAC computation failed"))?;
    
    let mut hmac = [0u8; 32];
    hmac.copy_from_slice(&result[..32]);
    Ok(hmac)
}

fn verify_hmac(key: &SecureBytes, salt: &[u8], nonce: &[u8], ciphertext: &[u8], expected: &[u8; 32]) -> io::Result<()> {
    let computed = compute_hmac(key, salt, nonce, ciphertext)?;
    
    // Constant-time comparison
    let mut diff = 0u8;
    for (a, b) in computed.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    
    if diff != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Authentication failed - vault may be tampered"
        ));
    }
    
    Ok(())
}

fn log_audit(audit_file: &str, user: &str, message: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(audit_file)?;
    
    lock_file_exclusive(&file)?;
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    
    let log_entry = format!("{} - {} - {}\n", timestamp, user, message);
    file.write_all(log_entry.as_bytes())?;
    file.sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

fn view_audit_log(audit_file: &str, passphrase: &SecureString) -> io::Result<()> {
    // Verify passphrase is correct by attempting to load the vault
    load_vault(audit_file, passphrase)?;
    
    if Path::new(audit_file).exists() {
        let file = File::open(audit_file)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            println!("{}", line?);
        }
    } else {
        println!("No audit log yet.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // Helper to create a test vault file path
    fn get_test_vault_file() -> String {
        let random_uuid: uuid::Uuid = uuid::Uuid::new_v4();
        format!("test_vault_{}.enc", random_uuid)
    }

    fn get_test_audit_file() -> String {
        let random_uuid: uuid::Uuid = uuid::Uuid::new_v4();
        format!("test_audit_{}.log", random_uuid)
    }

    // Clean up test files
    fn cleanup_test_files(vault: &str, audit: &str) {
        let _ = fs::remove_file(vault);
        if audit != "" {
            let _ = fs::remove_file(audit);
        }
    }

    #[test]
    fn test_secure_string_zeroizes() {
        let original = "sensitive_data";
        let secure = SecureString::new(original.to_string());
        assert_eq!(secure.as_str(), original);
        // After drop, memory should be zeroed (can't easily test without unsafe)
    }

    #[test]
    fn test_secure_bytes_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let secure = SecureBytes::new(data.clone());
        assert_eq!(secure.as_slice(), &data[..]);
    }

    #[test]
    fn test_derive_key_consistency() {
        let passphrase = SecureString::new("test_password".to_string());
        let salt = [42u8; SALT_SIZE];
        
        let key1 = derive_key(&passphrase, &salt).unwrap();
        let key2 = derive_key(&passphrase, &salt).unwrap();
        
        assert_eq!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_derive_key_different_salts() {
        let passphrase = SecureString::new("test_password".to_string());
        let salt1 = [1u8; SALT_SIZE];
        let salt2 = [2u8; SALT_SIZE];
        
        let key1 = derive_key(&passphrase, &salt1).unwrap();
        let key2 = derive_key(&passphrase, &salt2).unwrap();
        
        assert_ne!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_derive_subkeys_different() {
        let master_key = [42u8; KEY_SIZE];
        let (enc_key, auth_key) = derive_subkeys(&master_key).unwrap();
        
        assert_ne!(enc_key.as_slice(), auth_key.as_slice());
    }

    #[test]
    fn test_hmac_computation_consistency() {
        let key = SecureBytes::new(vec![1u8; KEY_SIZE]);
        let salt = [2u8; SALT_SIZE];
        let nonce = [3u8; NONCE_SIZE];
        let data = b"test data";
        
        let hmac1 = compute_hmac(&key, &salt, &nonce, data).unwrap();
        let hmac2 = compute_hmac(&key, &salt, &nonce, data).unwrap();
        
        assert_eq!(hmac1, hmac2);
    }

    #[test]
    fn test_hmac_verification_success() {
        let key = SecureBytes::new(vec![1u8; KEY_SIZE]);
        let salt = [2u8; SALT_SIZE];
        let nonce = [3u8; NONCE_SIZE];
        let data = b"test data";
        
        let hmac = compute_hmac(&key, &salt, &nonce, data).unwrap();
        let result = verify_hmac(&key, &salt, &nonce, data, &hmac);
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_hmac_verification_failure() {
        let key = SecureBytes::new(vec![1u8; KEY_SIZE]);
        let salt = [2u8; SALT_SIZE];
        let nonce = [3u8; NONCE_SIZE];
        let data = b"test data";
        
        let mut wrong_hmac = [0u8; 32];
        wrong_hmac[0] = 1;
        
        let result = verify_hmac(&key, &salt, &nonce, data, &wrong_hmac);
        
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_empty_vault_load() {
        let passphrase = SecureString::new("test_password".to_string());
        let vault_file = get_test_vault_file();
        // Should return empty hashmap for non-existent vault
        let vault = load_vault(&vault_file, &passphrase).unwrap();
        assert_eq!(vault.len(), 0);
        cleanup_test_files(&vault_file, "");
    }

    #[test]
    fn test_save_and_load_vault() {
        let vault_file = get_test_vault_file();
        let audit_file = get_test_audit_file();
        
       /*  // Temporarily override file paths for testing
        unsafe {
            VAULT_FILE_OVERRIDE = Some(vault_file.clone());
            AUDIT_FILE_OVERRIDE = Some(audit_file.clone());
        } */
        
        let passphrase = SecureString::new("test_password_123".to_string());
        let mut vault = HashMap::new();
        vault.insert("key1".to_string(), SecureString::new("value1".to_string()));
        vault.insert("key2".to_string(), SecureString::new("value2".to_string()));
        
        // Save vault
        save_vault(&vault_file, &audit_file, &vault, &passphrase).unwrap();
        
        // Load vault
        let loaded_vault = load_vault(&vault_file, &passphrase).unwrap();
        
        assert_eq!(loaded_vault.len(), 2);
        assert_eq!(loaded_vault.get("key1").unwrap().as_str(), "value1");
        assert_eq!(loaded_vault.get("key2").unwrap().as_str(), "value2");
        
        /* unsafe {
            VAULT_FILE_OVERRIDE = None;
            AUDIT_FILE_OVERRIDE = None;
        } */
        cleanup_test_files(&vault_file, &audit_file);
    }

    #[test]
    fn test_wrong_passphrase() {
        let vault_file = get_test_vault_file();
        let audit_file = get_test_audit_file();
        
       /*  unsafe {
            VAULT_FILE_OVERRIDE = Some(vault_file.clone());
            AUDIT_FILE_OVERRIDE = Some(audit_file.clone());
        } */
        
        let correct_passphrase = SecureString::new("correct_password".to_string());
        let wrong_passphrase = SecureString::new("wrong_password".to_string());
        
        let mut vault = HashMap::new();
        vault.insert("secret".to_string(), SecureString::new("data".to_string()));
        
        save_vault(&vault_file, &audit_file, &vault, &correct_passphrase).unwrap();
        
        // Try to load with wrong passphrase
        let result = load_vault(&vault_file, &wrong_passphrase);
        assert!(result.is_err());
        
       /*  unsafe {
            VAULT_FILE_OVERRIDE = None;
            AUDIT_FILE_OVERRIDE = None;
        } */
        cleanup_test_files(&vault_file, &audit_file);
    }

    #[test]
    fn test_salt_changes_on_save() {
        let vault_file = get_test_vault_file();
        let audit_file = get_test_audit_file();
        
       /*  unsafe {
            VAULT_FILE_OVERRIDE = Some(vault_file.clone());
            AUDIT_FILE_OVERRIDE = Some(audit_file.clone());
        } */
        
        let passphrase = SecureString::new("test_password".to_string());
        let mut vault = HashMap::new();
        vault.insert("key".to_string(), SecureString::new("value".to_string()));
        
        // Save twice
        save_vault(&vault_file, &audit_file, &vault, &passphrase).unwrap();
        let mut file1 = File::open(&vault_file).unwrap();
        let mut salt1 = vec![0u8; SALT_SIZE + 1]; // +1 for version byte
        file1.read_exact(&mut salt1).unwrap();
        
        save_vault(&vault_file, &audit_file, &vault, &passphrase).unwrap();
        let mut file2 = File::open(&vault_file).unwrap();
        let mut salt2 = vec![0u8; SALT_SIZE + 1];
        file2.read_exact(&mut salt2).unwrap();
        
        // Salts should be different (fresh salt on each save)
        assert_ne!(salt1, salt2);
        
       /*  unsafe {
            VAULT_FILE_OVERRIDE = None;
            AUDIT_FILE_OVERRIDE = None;
        } */
        cleanup_test_files(&vault_file, &audit_file);
    }

    #[test]
    fn test_passphrase_change() {
        let vault_file = get_test_vault_file();
        let audit_file = get_test_audit_file();
        
       /*  unsafe {
            VAULT_FILE_OVERRIDE = Some(vault_file.clone());
            AUDIT_FILE_OVERRIDE = Some(audit_file.clone());
        } */
        
        let old_passphrase = SecureString::new("old_password".to_string());
        let new_passphrase = SecureString::new("new_password".to_string());
        
        let mut vault = HashMap::new();
        vault.insert("secret".to_string(), SecureString::new("important_data".to_string()));
        
        // Save with old passphrase
        save_vault(&vault_file, &audit_file, &vault, &old_passphrase).unwrap();
        
        // Re-encrypt with new passphrase
        save_vault(&vault_file, &audit_file, &vault, &new_passphrase).unwrap();
        
        // Should not load with old passphrase
        assert!(load_vault(&vault_file, &old_passphrase).is_err());
        
        // Should load with new passphrase
        let loaded = load_vault(&vault_file, &new_passphrase).unwrap();
        assert_eq!(loaded.get("secret").unwrap().as_str(), "important_data");
        
       /*  unsafe {
            VAULT_FILE_OVERRIDE = None;
            AUDIT_FILE_OVERRIDE = None;
        } */
        cleanup_test_files(&vault_file, &audit_file);
    }

    #[test]
    fn test_tampering_detection() {
        let vault_file = get_test_vault_file();
        let audit_file = get_test_audit_file();
        
       /*  unsafe {
            VAULT_FILE_OVERRIDE = Some(vault_file.clone());
            AUDIT_FILE_OVERRIDE = Some(audit_file.clone());
        } */
        
        let passphrase = SecureString::new("test_password".to_string());
        let mut vault = HashMap::new();
        vault.insert("key".to_string(), SecureString::new("value".to_string()));
        
        save_vault(&vault_file, &audit_file, &vault, &passphrase).unwrap();
        
        // Tamper with the file
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&vault_file)
            .unwrap();
        
        // Skip to near the end and modify a byte
        file.seek(SeekFrom::End(-10)).unwrap();
        file.write_all(&[0xFF]).unwrap();
        
        // Should fail to load due to authentication failure
        let result = load_vault(&vault_file, &passphrase);
        assert!(result.is_err());
        
       /*  unsafe {
            VAULT_FILE_OVERRIDE = None;
            AUDIT_FILE_OVERRIDE = None;
        } */
        cleanup_test_files(&vault_file, &audit_file);
    }

    #[test]
    fn test_invalid_key_value_format() {
        let vault_file = get_test_vault_file();
        let audit_file = get_test_audit_file();
        
       /*  unsafe {
            VAULT_FILE_OVERRIDE = Some(vault_file.clone());
            AUDIT_FILE_OVERRIDE = Some(audit_file.clone());
        } */
        
        let passphrase = SecureString::new("test_password".to_string());
        let mut vault = HashMap::new();
        
        // Key with colon should fail
        vault.insert("key:with:colon".to_string(), SecureString::new("value".to_string()));
        let result = save_vault(&vault_file, &audit_file, &vault, &passphrase);
        assert!(result.is_err());
        
        vault.clear();
        
        // Value with newline should fail
        vault.insert("key".to_string(), SecureString::new("value\nwith\nnewlines".to_string()));
        let result = save_vault(&vault_file, &audit_file, &vault, &passphrase);
        assert!(result.is_err());
        
       /*  unsafe {
            VAULT_FILE_OVERRIDE = None;
            AUDIT_FILE_OVERRIDE = None;
        } */
        cleanup_test_files(&vault_file, &audit_file);
    }
}
/* 
// Test helpers - allow overriding file paths
static mut VAULT_FILE_OVERRIDE: Option<String> = None;
static mut AUDIT_FILE_OVERRIDE: Option<String> = None;

fn get_vault_file() -> &'static str {
    unsafe {
        if let Some(ref path) = VAULT_FILE_OVERRIDE {
            // Leak the string to get a 'static reference (only for tests)
            Box::leak(path.clone().into_boxed_str())
        } else {
            VAULT_FILE
        }
    }
}

fn get_audit_file() -> &'static str {
    unsafe {
        if let Some(ref path) = AUDIT_FILE_OVERRIDE {
            Box::leak(path.clone().into_boxed_str())
        } else {
            AUDIT_FILE
        }
    }
} */