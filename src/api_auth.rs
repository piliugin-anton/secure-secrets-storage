use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Algorithm, Params, Version,
};
use chacha20poly1305::{aead::Aead, XChaCha20Poly1305, XNonce, KeyInit};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::vault::{
    SecureBytes, SecureString, VaultError, Result,
    set_secure_permissions,
    lock_file_exclusive, lock_file_shared, unlock_file,
};

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// User Roles and Permissions
// ============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum UserRole {
    Admin,      // Full access: manage users, read/write secrets
    ReadWrite,  // Can read and write secrets
    ReadOnly,   // Can only read secrets
}

impl UserRole {
    pub fn can_read(&self) -> bool {
        matches!(self, UserRole::Admin | UserRole::ReadWrite | UserRole::ReadOnly)
    }

    pub fn can_write(&self) -> bool {
        matches!(self, UserRole::Admin | UserRole::ReadWrite)
    }

    pub fn can_delete(&self) -> bool {
        matches!(self, UserRole::Admin | UserRole::ReadWrite)
    }

    pub fn can_manage_users(&self) -> bool {
        matches!(self, UserRole::Admin)
    }

    pub fn can_rotate_keys(&self) -> bool {
        matches!(self, UserRole::Admin)
    }
}

// ============================================================================
// User Account Structure
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub role: UserRole,
    pub created_at: u64,
    pub last_login: Option<u64>,
    pub login_count: u64,
    pub failed_attempts: u32,
    pub locked_until: Option<u64>,
    pub must_change_password: bool,
    
    // Password hash (Argon2id PHC format)
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub password_hash: String,
    
    // Per-user vault passphrase (encrypted with user's password)
    #[serde(with = "serde_bytes")]
    pub encrypted_vault_passphrase: Vec<u8>,
    
    // Nonce for passphrase encryption
    #[serde(with = "serde_bytes")]
    pub passphrase_nonce: Vec<u8>,
}

impl User {
    /// Create new user with encrypted vault passphrase
    pub fn new(
        username: String,
        password: &str,
        vault_passphrase: &SecureString,
        role: UserRole,
    ) -> Result<Self> {
        let id = Uuid::new_v4();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Hash password with Argon2id
        let password_hash = Self::hash_password(password)?;

        // Derive encryption key from password
        let encryption_key = Self::derive_key_from_password(password)?;

        // Encrypt vault passphrase
        let mut passphrase_nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut OsRng, &mut passphrase_nonce);

        let cipher = XChaCha20Poly1305::new(encryption_key.as_slice().into());
        let nonce = XNonce::from_slice(&passphrase_nonce);

        let encrypted_vault_passphrase = cipher
            .encrypt(nonce, vault_passphrase.as_bytes())
            .map_err(|_| VaultError::CryptoError("Failed to encrypt vault passphrase".into()))?;

        Ok(User {
            id,
            username,
            role,
            created_at: now,
            last_login: None,
            login_count: 0,
            failed_attempts: 0,
            locked_until: None,
            must_change_password: false,
            password_hash,
            encrypted_vault_passphrase,
            passphrase_nonce: passphrase_nonce.to_vec(),
        })
    }

    /// Hash password using Argon2id (PHC format)
    fn hash_password(password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(
                64 * 1024,  // 64 MB memory (reasonable for auth)
                3,          // 3 iterations
                4,          // 4 parallel threads
                None,
            ).map_err(|e| VaultError::Argon2(format!("Argon2 params: {}", e)))?,
        );

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| VaultError::Argon2(format!("Password hashing failed: {}", e)))
    }

    /// Verify password against stored hash
    pub fn verify_password(&self, password: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(&self.password_hash)
            .map_err(|e| VaultError::InvalidKeyFormat(format!("Invalid hash: {}", e)))?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Derive encryption key from password (for vault passphrase encryption)
    fn derive_key_from_password(password: &str) -> Result<SecureBytes> {
        let salt = b"vault-user-passphrase-encryption-v1";
        
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(64 * 1024, 3, 4, Some(32))
                .map_err(|e| VaultError::Argon2(format!("Argon2 params: {}", e)))?,
        );

        let mut key = vec![0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| VaultError::Argon2(format!("Key derivation failed: {}", e)))?;

        Ok(SecureBytes::new(key))
    }

    /// Decrypt vault passphrase using user's password
    pub fn decrypt_vault_passphrase(&self, password: &str) -> Result<SecureString> {
        let encryption_key = Self::derive_key_from_password(password)?;

        let cipher = XChaCha20Poly1305::new(encryption_key.as_slice().into());
        let nonce = XNonce::from_slice(&self.passphrase_nonce);

        let plaintext = cipher
            .decrypt(nonce, self.encrypted_vault_passphrase.as_ref())
            .map_err(|_| VaultError::AuthenticationFailed)?;

        let passphrase = String::from_utf8(plaintext)
            .map_err(|_| VaultError::InvalidDataFormat("Invalid UTF-8 in passphrase".into()))?;

        Ok(SecureString::new(passphrase))
    }

    /// Check if account is locked due to failed attempts
    pub fn is_locked(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now < locked_until
        } else {
            false
        }
    }

    /// Record failed login attempt
    pub fn record_failed_attempt(&mut self) {
        self.failed_attempts += 1;
        
        // Lock account after 5 failed attempts for 15 minutes
        if self.failed_attempts >= 5 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            self.locked_until = Some(now + 15 * 60); // 15 minutes
        }
    }

    /// Record successful login
    pub fn record_successful_login(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        self.last_login = Some(now);
        self.login_count += 1;
        self.failed_attempts = 0;
        self.locked_until = None;
    }

    /// Change user password and re-encrypt vault passphrase
    pub fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        // Verify old password
        if !self.verify_password(old_password)? {
            return Err(VaultError::AuthenticationFailed);
        }

        // Decrypt vault passphrase with old password
        let vault_passphrase = self.decrypt_vault_passphrase(old_password)?;

        // Generate new password hash
        self.password_hash = Self::hash_password(new_password)?;

        // Re-encrypt vault passphrase with new password
        let new_encryption_key = Self::derive_key_from_password(new_password)?;
        
        let mut new_nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut OsRng, &mut new_nonce);

        let cipher = XChaCha20Poly1305::new(new_encryption_key.as_slice().into());
        let nonce = XNonce::from_slice(&new_nonce);

        self.encrypted_vault_passphrase = cipher
            .encrypt(nonce, vault_passphrase.as_bytes())
            .map_err(|_| VaultError::CryptoError("Failed to re-encrypt vault passphrase".into()))?;

        self.passphrase_nonce = new_nonce.to_vec();
        self.must_change_password = false;

        Ok(())
    }
}

// ============================================================================
// User Database (Encrypted Storage)
// ============================================================================

const USER_DB_VERSION: u8 = 1;
pub const USER_DB_FILE: &str = "users.enc";

#[derive(Debug, Serialize, Deserialize)]
struct UserDatabase {
    version: u8,
    users: HashMap<String, User>, // username -> User
}

impl UserDatabase {
    fn new() -> Self {
        UserDatabase {
            version: USER_DB_VERSION,
            users: HashMap::new(),
        }
    }

    fn add_user(&mut self, user: User) -> Result<()> {
        if self.users.contains_key(&user.username) {
            return Err(VaultError::InvalidKeyFormat(
                format!("User '{}' already exists", user.username)
            ));
        }
        self.users.insert(user.username.clone(), user);
        Ok(())
    }

    fn get_user(&self, username: &str) -> Option<&User> {
        self.users.get(username)
    }

    fn get_user_mut(&mut self, username: &str) -> Option<&mut User> {
        self.users.get_mut(username)
    }

    fn remove_user(&mut self, username: &str) -> Option<User> {
        self.users.remove(username)
    }

    fn list_users(&self) -> Vec<&User> {
        self.users.values().collect()
    }
}

// ============================================================================
// User Manager (Handles encrypted user database)
// ============================================================================

pub struct UserManager {
    db_file: String,
    master_key: SecureBytes,
}

impl UserManager {
    /// Create new UserManager with a master key
    /// This key should be derived from a secure admin passphrase or HSM
    pub fn new(db_file: String, master_passphrase: &SecureString) -> Result<Self> {
        let master_key = Self::derive_master_key(master_passphrase)?;
        
        Ok(UserManager {
            db_file,
            master_key,
        })
    }

    /// Derive master key for database encryption
    fn derive_master_key(passphrase: &SecureString) -> Result<SecureBytes> {
        let salt = b"vault-user-database-master-key-v1-do-not-change";
        
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(256 * 1024, 3, 4, Some(32))
                .map_err(|e| VaultError::Argon2(format!("Argon2 params: {}", e)))?,
        );

        let mut key = vec![0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| VaultError::Argon2(format!("Master key derivation failed: {}", e)))?;

        Ok(SecureBytes::new(key))
    }

    /// Initialize user database with first admin user
    pub fn initialize(&self, admin_username: String, admin_password: &str) -> Result<()> {
        if Path::new(&self.db_file).exists() {
            return Err(VaultError::InvalidDataFormat(
                "User database already initialized".into()
            ));
        }

        // Create master vault passphrase (shared by all users)
        let vault_passphrase = Self::generate_secure_passphrase();

        // Create admin user
        let admin = User::new(
            admin_username,
            admin_password,
            &vault_passphrase,
            UserRole::Admin,
        )?;

        let mut db = UserDatabase::new();
        db.add_user(admin)?;

        self.save_database(&db)?;

        println!("✓ User database initialized");
        println!("  Admin user created");
        println!("  Master vault passphrase: {}", vault_passphrase.as_str());
        println!("  ⚠️  SAVE THIS PASSPHRASE - needed for vault operations!");

        Ok(())
    }

    /// Generate cryptographically secure random passphrase
    fn generate_secure_passphrase() -> SecureString {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        let mut rng = rand::thread_rng();
        
        let passphrase: String = (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();

        SecureString::new(passphrase)
    }

    /// Load and decrypt user database
    fn load_database(&self) -> Result<UserDatabase> {
        if !Path::new(&self.db_file).exists() {
            return Ok(UserDatabase::new());
        }

        let file = File::open(&self.db_file)?;
        lock_file_shared(&file)?;

        let mut reader = BufReader::new(&file);

        // Read version
        let mut version = [0u8; 1];
        reader.read_exact(&mut version)?;

        if version[0] != USER_DB_VERSION {
            return Err(VaultError::UnsupportedVersion {
                found: version[0],
                expected: USER_DB_VERSION,
            });
        }

        // Read nonce
        let mut nonce_bytes = [0u8; 24];
        reader.read_exact(&mut nonce_bytes)?;

        // Read HMAC
        let mut stored_hmac = [0u8; 32];
        reader.read_exact(&mut stored_hmac)?;

        // Read ciphertext
        let mut ciphertext = Vec::new();
        reader.read_to_end(&mut ciphertext)?;

        drop(reader);
        unlock_file(&file)?;

        // Verify HMAC
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.master_key.as_slice())
            .map_err(|_| VaultError::Hmac("HMAC init failed".into()))?;
        mac.update(&version);
        mac.update(&nonce_bytes);
        mac.update(&ciphertext);

        mac.verify_slice(&stored_hmac)
            .map_err(|_| VaultError::AuthenticationFailed)?;

        // Decrypt
        let cipher = XChaCha20Poly1305::new(self.master_key.as_slice().into());
        let nonce = XNonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| VaultError::CryptoError("Failed to decrypt user database".into()))?;

        // Deserialize
        let db: UserDatabase = serde_json::from_slice(&plaintext)
            .map_err(|e| VaultError::InvalidDataFormat(format!("JSON parse error: {}", e)))?;

        Ok(db)
    }

    /// Encrypt and save user database
    fn save_database(&self, db: &UserDatabase) -> Result<()> {
        // Serialize
        let plaintext = serde_json::to_vec_pretty(db)
            .map_err(|e| VaultError::InvalidDataFormat(format!("JSON error: {}", e)))?;

        // Generate nonce
        let mut nonce_bytes = [0u8; 24];
        rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);

        // Encrypt
        let cipher = XChaCha20Poly1305::new(self.master_key.as_slice().into());
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| VaultError::CryptoError("Failed to encrypt user database".into()))?;

        // Calculate HMAC
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.master_key.as_slice())
            .map_err(|_| VaultError::Hmac("HMAC init failed".into()))?;
        mac.update(&[USER_DB_VERSION]);
        mac.update(&nonce_bytes);
        mac.update(&ciphertext);
        let hmac_bytes = mac.finalize().into_bytes();

        // Write to temp file
        let temp_file = format!("{}.tmp", self.db_file);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_file)?;

        lock_file_exclusive(&file)?;

        let mut writer = BufWriter::new(&file);
        writer.write_all(&[USER_DB_VERSION])?;
        writer.write_all(&nonce_bytes)?;
        writer.write_all(&hmac_bytes)?;
        writer.write_all(&ciphertext)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;

        drop(writer);
        unlock_file(&file)?;

        // Set secure permissions
        set_secure_permissions(Path::new(&temp_file))?;

        // Atomic rename
        std::fs::rename(&temp_file, &self.db_file)?;

        Ok(())
    }

    /// Authenticate user and return vault passphrase
    pub fn authenticate(&mut self, username: &str, password: &str) -> Result<(User, SecureString)> {
        let mut db = self.load_database()?;

        let user = db.get_user_mut(username)
            .ok_or(VaultError::AuthenticationFailed)?;

        // Check if account is locked
        if user.is_locked() {
            return Err(VaultError::InvalidDataFormat(
                "Account locked due to failed login attempts".into()
            ));
        }

        // Verify password
        if !user.verify_password(password)? {
            user.record_failed_attempt();
            self.save_database(&db)?;
            return Err(VaultError::AuthenticationFailed);
        }

        // Decrypt vault passphrase
        let vault_passphrase = user.decrypt_vault_passphrase(password)?;

        // Record successful login
        user.record_successful_login();
        
        let user_clone = user.clone();
        self.save_database(&db)?;

        Ok((user_clone, vault_passphrase))
    }

    /// Add new user (admin only)
    pub fn add_user(
        &self,
        username: String,
        password: &str,
        role: UserRole,
        vault_passphrase: &SecureString,
    ) -> Result<()> {
        let mut db = self.load_database()?;

        let user = User::new(username, password, vault_passphrase, role)?;
        db.add_user(user)?;

        self.save_database(&db)?;

        Ok(())
    }

    /// Remove user (admin only)
    pub fn remove_user(&self, username: &str) -> Result<()> {
        let mut db = self.load_database()?;

        db.remove_user(username)
            .ok_or(VaultError::InvalidKeyFormat(format!("User '{}' not found", username)))?;

        self.save_database(&db)?;

        Ok(())
    }

    /// List all users
    pub fn list_users(&self) -> Result<Vec<User>> {
        let db = self.load_database()?;
        Ok(db.list_users().into_iter().cloned().collect())
    }

    /// Change user password
    pub fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        let mut db = self.load_database()?;

        let user = db.get_user_mut(username)
            .ok_or(VaultError::InvalidKeyFormat(format!("User '{}' not found", username)))?;

        user.change_password(old_password, new_password)?;

        self.save_database(&db)?;

        Ok(())
    }

    /// Update user role (admin only)
    pub fn update_user_role(&self, username: &str, new_role: UserRole) -> Result<()> {
        let mut db = self.load_database()?;

        let user = db.get_user_mut(username)
            .ok_or(VaultError::InvalidKeyFormat(format!("User '{}' not found", username)))?;

        user.role = new_role;

        self.save_database(&db)?;

        Ok(())
    }
}

// ============================================================================
// CLI Commands for User Management
// ============================================================================

pub fn init_user_database(
    db_file: &str,
    master_passphrase: &SecureString,
    admin_username: String,
    admin_password: &str,
) -> Result<()> {
    let manager = UserManager::new(db_file.to_string(), master_passphrase)?;
    manager.initialize(admin_username, admin_password)?;
    Ok(())
}

pub fn add_user_cli(
    db_file: &str,
    master_passphrase: &SecureString,
    username: String,
    password: &str,
    role: UserRole,
    vault_passphrase: &SecureString,
) -> Result<()> {
    let manager = UserManager::new(db_file.to_string(), master_passphrase)?;
    manager.add_user(username.clone(), password, role, vault_passphrase)?;
    println!("✓ User '{}' created with role {:?}", username, role);
    Ok(())
}

pub fn list_users_cli(
    db_file: &str,
    master_passphrase: &SecureString,
) -> Result<()> {
    let manager = UserManager::new(db_file.to_string(), master_passphrase)?;
    let users = manager.list_users()?;

    if users.is_empty() {
        println!("No users found.");
        return Ok(());
    }

    println!("\n=== Users ===");
    for user in users {
        let locked = if user.is_locked() { " [LOCKED]" } else { "" };
        let must_change = if user.must_change_password { " [MUST CHANGE PASSWORD]" } else { "" };
        
        println!("  • {} ({:?}){}{}", user.username, user.role, locked, must_change);
        println!("    ID: {}", user.id);
        println!("    Created: {}", format_timestamp(user.created_at));
        if let Some(last_login) = user.last_login {
            println!("    Last login: {}", format_timestamp(last_login));
        }
        println!("    Login count: {}", user.login_count);
        println!();
    }

    Ok(())
}

fn format_timestamp(timestamp: u64) -> String {
    use chrono::{DateTime, Utc};
    DateTime::<Utc>::from(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp))
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_user_creation_and_password_verification() {
        let vault_pass = SecureString::new("vault_passphrase_123".to_string());
        
        let user = User::new(
            "testuser".to_string(),
            "password123",
            &vault_pass,
            UserRole::ReadWrite,
        ).unwrap();

        assert_eq!(user.username, "testuser");
        assert_eq!(user.role, UserRole::ReadWrite);
        assert!(user.verify_password("password123").unwrap());
        assert!(!user.verify_password("wrongpassword").unwrap());
    }

    #[test]
    fn test_vault_passphrase_encryption_decryption() {
        let vault_pass = SecureString::new("my_vault_passphrase".to_string());
        
        let user = User::new(
            "testuser".to_string(),
            "userpassword",
            &vault_pass,
            UserRole::Admin,
        ).unwrap();

        let decrypted = user.decrypt_vault_passphrase("userpassword").unwrap();
        assert_eq!(decrypted.as_str(), vault_pass.as_str());

        // Wrong password should fail
        assert!(user.decrypt_vault_passphrase("wrongpassword").is_err());
    }

    #[test]
    fn test_password_change() {
        let vault_pass = SecureString::new("vault_pass".to_string());
        
        let mut user = User::new(
            "testuser".to_string(),
            "oldpass",
            &vault_pass,
            UserRole::ReadWrite,
        ).unwrap();

        // Change password
        user.change_password("oldpass", "newpass").unwrap();

        // Old password should not work
        assert!(!user.verify_password("oldpass").unwrap());
        
        // New password should work
        assert!(user.verify_password("newpass").unwrap());

        // Should still decrypt vault passphrase with new password
        let decrypted = user.decrypt_vault_passphrase("newpass").unwrap();
        assert_eq!(decrypted.as_str(), vault_pass.as_str());
    }

    #[test]
    fn test_failed_login_attempts_and_locking() {
        let vault_pass = SecureString::new("vault".to_string());
        
        let mut user = User::new(
            "testuser".to_string(),
            "password",
            &vault_pass,
            UserRole::ReadOnly,
        ).unwrap();

        assert!(!user.is_locked());

        // Record 5 failed attempts
        for _ in 0..5 {
            user.record_failed_attempt();
        }

        assert!(user.is_locked());

        // Successful login should unlock
        user.record_successful_login();
        assert!(!user.is_locked());
        assert_eq!(user.failed_attempts, 0);
    }

    #[test]
    fn test_user_manager_initialization() {
        let dir = tempdir().unwrap();
        let db_file = dir.path().join("users.db").to_str().unwrap().to_string();
        
        let master_pass = SecureString::new("master_passphrase_secure".to_string());
        let manager = UserManager::new(db_file.clone(), &master_pass).unwrap();

        manager.initialize("admin".to_string(), "admin_password").unwrap();

        // Should not be able to initialize twice
        assert!(manager.initialize("admin2".to_string(), "pass").is_err());
    }

    #[test]
    fn test_user_authentication() {
        let dir = tempdir().unwrap();
        let db_file = dir.path().join("users.db").to_str().unwrap().to_string();
        
        let master_pass = SecureString::new("master".to_string());
        let mut manager = UserManager::new(db_file.clone(), &master_pass).unwrap();

        manager.initialize("admin".to_string(), "adminpass").unwrap();

        // Authenticate with correct credentials
        let result = manager.authenticate("admin", "adminpass");
        assert!(result.is_ok());

        let (user, _vault_pass) = result.unwrap();
        assert_eq!(user.username, "admin");
        assert_eq!(user.role, UserRole::Admin);

        // Wrong password should fail
        assert!(manager.authenticate("admin", "wrongpass").is_err());

        // Non-existent user should fail
        assert!(manager.authenticate("nobody", "pass").is_err());
    }
}