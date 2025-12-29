pub mod vault;
pub mod api;
pub mod api_auth;

pub const VERSION: u8 = 1;
pub const VAULT_FILE: &str = "vault.enc";
pub const AUDIT_FILE: &str = "vault_audit.log";
pub const COUNTER_FILE: &str = "vault.counter";