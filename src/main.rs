use rpassword::prompt_password;
use rprompt::prompt_reply;
use secure_secrets_storage::api_auth::UserRole;
use secure_secrets_storage::api_auth::add_user_cli;
use secure_secrets_storage::api_auth::init_user_database;
use secure_secrets_storage::api_auth::list_users_cli;
use secure_secrets_storage::vault::AuditOperation;
use secure_secrets_storage::vault::SecureString;
use secure_secrets_storage::vault::VaultError;
use secure_secrets_storage::vault::backup_vault;
use secure_secrets_storage::vault::check_and_fix_permissions;
use secure_secrets_storage::vault::derive_audit_key;
use secure_secrets_storage::vault::derive_counter_key;
use secure_secrets_storage::vault::emergency_key_rotation;
use secure_secrets_storage::vault::export_vault_plaintext;
use secure_secrets_storage::vault::import_vault_plaintext;
use secure_secrets_storage::vault::load_vault;
use secure_secrets_storage::vault::log_audit;
use secure_secrets_storage::vault::rekey_audit_log;
use secure_secrets_storage::vault::rekey_counter;
use secure_secrets_storage::vault::restore_vault;
use secure_secrets_storage::vault::rotate_encryption_keys;
use secure_secrets_storage::vault::save_vault;
use secure_secrets_storage::vault::verify_vault;
use secure_secrets_storage::vault::view_audit_log;
use secure_secrets_storage::{AUDIT_FILE, COUNTER_FILE, VAULT_FILE, VERSION};
use std::env;
use std::io;
use tracing::{error, info};

use secure_secrets_storage::api;
use secure_secrets_storage::api_auth::USER_DB_FILE;

fn print_usage() {
    println!("Secure Secrets Storage v{VERSION}.0");
    println!("\nUsage:");
    println!("  add <key>           - Add a secret");
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
    println!("  rotate-keys         - Rotate encryption keys (same passphrase)");
    println!("  emergency-rotate    - Emergency key rotation + verify");
    println!("  check-permissions   - Verify and fix file permissions");
    println!("\n🔐 Multi-User API Server:");
    println!("  init-users <admin_username>  - Initialize user database");
    println!("  list-users                   - List all users");
    println!("  add-user <username>          - Add new user");
    println!("  api [addr]                   - Start secure API server (default: 127.0.0.1:6666)");
    println!("\nSecurity features:");
    println!("  - XChaCha20-Poly1305 encryption");
    println!("  - Argon2id key derivation (256MB memory)");
    println!("  - HMAC-SHA256 authentication");
    println!("  - Rollback attack protection");
    println!("  - Encrypted audit logging");
    println!("  - Memory zeroization");
    println!("  - Multi-user authentication with role-based access control");
}

pub fn init_logging() {
    use tracing_subscriber::{filter::EnvFilter, fmt};

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .compact()
        .init();
}

// Prevent core dumps and lock memory pages (Unix only)
#[cfg(unix)]
fn secure_memory() -> io::Result<()> {
    use libc::{MCL_CURRENT, MCL_FUTURE, RLIMIT_CORE, mlockall, rlimit, setrlimit};

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

fn compare_passphrases(
    passphrase: &SecureString,
    passphrase_repeat: &SecureString,
) -> Result<(), io::Error> {
    if passphrase.as_str() != passphrase_repeat.as_str() {
        let error_message = "Passphrases do not match.";
        error!(error_message);
        return Err(io::Error::new(io::ErrorKind::InvalidInput, error_message).into());
    }

    Ok(())
}

fn main() -> secure_secrets_storage::vault::Result<()> {
    init_logging();

    info!("Secure Secrets Storage starting");

    // Secure memory before handling any secrets
    secure_memory()?;

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let command = &args[1];

    match command.as_str() {
        "init-users" if args.len() == 3 => {
            // Prompt passphrase securely (no echo)
            let master_passphrase =
                SecureString::new(prompt_password("Enter master passphrase: ")?);
            let master_passphrase_repeat =
                SecureString::new(prompt_password("Repeat master passphrase: ")?);
            compare_passphrases(&master_passphrase, &master_passphrase_repeat)?;
            let admin_passphrase = SecureString::new(prompt_password("Enter admin passphrase: ")?);
            let admin_passphrase_repeat =
                SecureString::new(prompt_password("Repeat admin passphrase: ")?);
            compare_passphrases(&admin_passphrase, &admin_passphrase_repeat)?;
            let admin_username = args[2].clone();
            init_user_database(
                USER_DB_FILE,
                &master_passphrase,
                admin_username,
                admin_passphrase.as_str(),
            )?;
            info!("User database initialized successfully.");
            return Ok(());
        }
        "add-user" if args.len() == 3 => {
            // Prompt passphrase securely (no echo)
            let master_passphrase =
                SecureString::new(prompt_password("Enter master passphrase: ")?);
            let username = args[2].clone();
            let password = SecureString::new(prompt_password("Enter user password: ")?);
            let password_repeat = SecureString::new(prompt_password("Repeat user password: ")?);
            compare_passphrases(&password, &password_repeat)?;
            let vault_passphrase = SecureString::new(prompt_password("Enter vault passphrase: ")?);
            let vault_passphrase_repeat =
                SecureString::new(prompt_password("Repeat vault password: ")?);
            compare_passphrases(&vault_passphrase, &vault_passphrase_repeat)?;
            let eol = if cfg!(windows) { "\r\n" } else { "\n" };
            let choices = format!(
                "Select user role:{eol}\t1. Admin{eol}\t2. Read-only{eol}\t3. Read + Write{eol}> "
            );
            let choice = prompt_reply(choices)?;
            let role = match choice.as_str() {
                "1" => UserRole::Admin,
                "2" => UserRole::ReadOnly,
                "3" => UserRole::ReadWrite,
                _ => {
                    return Err(
                        io::Error::new(io::ErrorKind::InvalidInput, "Invalid choice").into(),
                    );
                }
            };
            add_user_cli(
                USER_DB_FILE,
                &master_passphrase,
                username,
                password.as_str(),
                role,
                &vault_passphrase,
            )?;
            info!("User added successfully.");
            return Ok(());
        }
        "list-users" => {
            // Prompt passphrase securely (no echo)
            let master_passphrase =
                SecureString::new(prompt_password("Enter master passphrase: ")?);

            return list_users_cli(USER_DB_FILE, &master_passphrase);
        }
        "api" => {
            // Prompt passphrase securely (no echo)
            let master_passphrase =
                SecureString::new(prompt_password("Enter master passphrase: ")?);
            let bind_address = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:6666");

            return api::run_api_server(
                VAULT_FILE.to_string(),
                COUNTER_FILE.to_string(),
                AUDIT_FILE.to_string(),
                USER_DB_FILE.to_string(),
                master_passphrase,
                bind_address,
            )
            .map_err(|e| VaultError::Io(e));
        }
        _ => {}
    };

    let vault_commands_list = vec![
        "add",
        "get",
        "list",
        "delete",
        "change-passphrase",
        "audit",
        "backup",
        "restore",
        "verify",
        "export",
        "import",
        "rotate-keys",
        "emergency-rotate",
        "check-permissions",
    ];
    let is_command_found = vault_commands_list.iter().any(|&s| s == command);
    if !is_command_found {
        error!("Invalid command or arguments.");
        print_usage();
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "Invalid command or arguments.").into(),
        );
    }
    // Prompt passphrase securely (no echo)
    let passphrase = SecureString::new(prompt_password("Enter vault passphrase: ")?);

    // Derive audit key from passphrase
    let audit_key = derive_audit_key(&passphrase)?;
    let counter_key = derive_counter_key(&passphrase)?;

    // Load vault with rollback protection
    let (mut vault, _counter) =
        match load_vault(VAULT_FILE, COUNTER_FILE, &passphrase, &counter_key) {
            Ok((vault, counter)) => {
                info!(
                    secrets_count = vault.len(),
                    counter = counter,
                    "Vault loaded successfully"
                );

                (vault, counter)
            }
            Err(VaultError::AuthenticationFailed) => {
                error!("Wrong passphrase provided");
                return Err(VaultError::AuthenticationFailed.into());
            }
            Err(VaultError::RollbackDetected { vault, stored }) => {
                error!(
                    vault_counter = vault,
                    stored_counter = stored,
                    "Rollback attack detected - DO NOT PROCEED"
                );
                return Err(VaultError::RollbackDetected { vault, stored }.into());
            }
            Err(e) => {
                error!(error = %e, "Failed to load vault");
                return Err(e.into());
            }
        };

    match command.as_str() {
        "add" if args.len() == 3 => {
            let key = args[2].clone();
            let value = SecureString::new(prompt_password(&format!(
                "Enter secret value for '{}': ",
                key
            ))?);
            vault.insert(key.clone(), value);
            let (_counter, is_new) =
                save_vault(VAULT_FILE, COUNTER_FILE, &vault, &passphrase, &counter_key)?;
            if is_new {
                log_audit(AUDIT_FILE, AuditOperation::VaultCreated, true, &audit_key)?;
            }
            log_audit(AUDIT_FILE, AuditOperation::SecretWrite, true, &audit_key)?;
            info!("Secret added successfully.");
        }
        "get" if args.len() == 3 => {
            let key = &args[2];
            if let Some(value) = vault.get(key) {
                info!("{}", value.as_str());
                log_audit(AUDIT_FILE, AuditOperation::SecretRead, true, &audit_key)?;
            } else {
                info!("Key not found.");
                log_audit(AUDIT_FILE, AuditOperation::SecretRead, false, &audit_key)?;
            }
        }
        "list" if args.len() == 2 => {
            if vault.is_empty() {
                info!("No secrets stored.");
            } else {
                info!("Stored keys:");
                for key in vault.keys() {
                    info!("  - {}", key);
                }
            }
            log_audit(AUDIT_FILE, AuditOperation::VaultAccess, true, &audit_key)?;
        }
        "delete" if args.len() == 3 => {
            let key = &args[2];
            if vault.remove(key).is_some() {
                save_vault(VAULT_FILE, COUNTER_FILE, &vault, &passphrase, &counter_key)?;
                log_audit(AUDIT_FILE, AuditOperation::SecretDelete, true, &audit_key)?;
                info!("Secret deleted successfully.");
            } else {
                info!("Key not found.");
                log_audit(AUDIT_FILE, AuditOperation::SecretDelete, false, &audit_key)?;
            }
        }
        "change-passphrase" if args.len() == 2 => {
            let new_passphrase = SecureString::new(prompt_password("Enter new passphrase: ")?);
            let confirm = SecureString::new(prompt_password("Confirm new passphrase: ")?);

            if new_passphrase.as_str() != confirm.as_str() {
                info!("Passphrases do not match.");
                return Ok(());
            }

            let new_audit_key = derive_audit_key(&new_passphrase)?;
            let new_counter_key = derive_counter_key(&new_passphrase)?;

            // Rekey operations in order (most critical first)
            // 1. Rekey counter (CRITICAL - must succeed or abort)
            rekey_counter(COUNTER_FILE, &counter_key, &new_counter_key).map_err(|e| {
                error!("Failed to rekey counter file: {}", e);
                error!("Passphrase change ABORTED - vault unchanged");
                e
            })?;

            // 2. Rekey audit log (can continue if fails)
            if let Err(e) = rekey_audit_log(AUDIT_FILE, &audit_key, &new_audit_key) {
                error!("Warning: Failed to rekey audit log: {}", e);
                error!("Continuing with passphrase change...");
            }

            // 3. Save vault with new passphrase
            save_vault(
                VAULT_FILE,
                COUNTER_FILE,
                &vault,
                &new_passphrase,
                &new_counter_key,
            )?;

            // 4. Log the change
            log_audit(
                AUDIT_FILE,
                AuditOperation::PassphraseChange,
                true,
                &new_audit_key,
            )?;

            println!("Passphrase changed successfully.");
        }
        "audit" if args.len() == 2 => {
            view_audit_log(AUDIT_FILE, &audit_key)?;
            log_audit(AUDIT_FILE, AuditOperation::AuditView, true, &audit_key)?;
        }
        "backup" if args.len() == 3 => {
            let backup_path = &args[2];
            backup_vault(
                VAULT_FILE,
                COUNTER_FILE,
                AUDIT_FILE,
                backup_path,
                &passphrase,
            )?;
            log_audit(AUDIT_FILE, AuditOperation::BackupCreated, true, &audit_key)?;
            info!("Backup created successfully at: {}", backup_path);
        }
        "restore" if args.len() == 3 => {
            let backup_path = &args[2];
            restore_vault(
                backup_path,
                VAULT_FILE,
                COUNTER_FILE,
                AUDIT_FILE,
                &passphrase,
            )?;
            log_audit(AUDIT_FILE, AuditOperation::VaultRestored, true, &audit_key)?;
            info!("Vault restored successfully from: {}", backup_path);
        }
        "verify" if args.len() == 2 => {
            verify_vault(VAULT_FILE, COUNTER_FILE, &passphrase, &counter_key, true)?;
            info!("✓ Vault integrity verified successfully");
        }
        "export" if args.len() == 3 => {
            let export_path = &args[2];
            export_vault_plaintext(&vault, export_path)?;
            log_audit(AUDIT_FILE, AuditOperation::VaultAccess, true, &audit_key)?;
            info!(
                "⚠️  WARNING: Secrets exported in PLAINTEXT to: {}",
                export_path
            );
            println!("    Delete this file securely after use!");
        }
        "import" if args.len() == 3 => {
            let import_path = &args[2];
            let imported = import_vault_plaintext(import_path)?;
            vault.extend(imported);
            save_vault(VAULT_FILE, COUNTER_FILE, &vault, &passphrase, &counter_key)?;
            log_audit(AUDIT_FILE, AuditOperation::VaultAccess, true, &audit_key)?;
            info!("Secrets imported successfully");
        }
        "rotate-keys" if args.len() == 2 => {
            rotate_encryption_keys(VAULT_FILE, COUNTER_FILE, AUDIT_FILE, &passphrase)?;
            log_audit(AUDIT_FILE, AuditOperation::KeyRotation, true, &audit_key)?;
            info!("Encryption keys rotated successfully");
        }
        "emergency-rotate" if args.len() == 2 => {
            emergency_key_rotation(VAULT_FILE, COUNTER_FILE, AUDIT_FILE, &passphrase)?;
            log_audit(
                AUDIT_FILE,
                AuditOperation::EmergencyRotation,
                true,
                &audit_key,
            )?;
            info!("Emergency keys rotated successfully");
        }
        "check-permissions" if args.len() == 2 => {
            check_and_fix_permissions(VAULT_FILE, COUNTER_FILE, AUDIT_FILE)?;
            log_audit(
                AUDIT_FILE,
                AuditOperation::PermissionCheck,
                true,
                &audit_key,
            )?;
        }

        _ => {
            error!("Invalid command or arguments.");
            print_usage();
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid command or arguments.",
            )
            .into());
        }
    }

    Ok(())
}
