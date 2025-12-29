use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, middleware};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use chrono::{DateTime, Utc};

use crate::api_auth::{UserManager, User, UserRole};
use crate::vault::{
    load_vault, save_vault, derive_counter_key, 
    SecureString, VaultError, Result
};

// ============================================================================
// API Request/Response Models
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: String,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: String, // "Admin", "ReadWrite", "ReadOnly"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretRequest {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct SecretResponse {
    pub key: String,
    pub value: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: String,
    pub details: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub username: String,
    pub role: String,
    pub created_at: String,
    pub last_login: Option<String>,
    pub login_count: u64,
}

// ============================================================================
// Session Management with User Context
// ============================================================================

#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: String,
    pub user: User,
    pub vault_passphrase: SecureString,
    pub created_at: SystemTime,
    pub last_accessed: SystemTime,
    pub expires_at: SystemTime,
    pub ip_address: Option<String>,
}

impl Session {
    pub fn new(user: User, vault_passphrase: SecureString, duration: Duration, ip: Option<String>) -> Self {
        let now = SystemTime::now();
        let session_id = uuid::Uuid::new_v4().to_string();
        
        Session {
            session_id,
            user,
            vault_passphrase,
            created_at: now,
            last_accessed: now,
            expires_at: now + duration,
            ip_address: ip,
        }
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    pub fn refresh(&mut self) {
        self.last_accessed = SystemTime::now();
    }

    pub fn has_permission(&self, required_role: UserRole) -> bool {
        match required_role {
            UserRole::ReadOnly => self.user.role.can_read(),
            UserRole::ReadWrite => self.user.role.can_write(),
            UserRole::Admin => self.user.role.can_manage_users(),
        }
    }
}

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    max_sessions_per_user: usize,
}

impl SessionManager {
    pub fn new(max_sessions_per_user: usize) -> Self {
        SessionManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            max_sessions_per_user,
        }
    }

    pub fn create_session(&self, user: User, vault_passphrase: SecureString, ip: Option<String>) -> Result<Session> {
        let session = Session::new(user.clone(), vault_passphrase, Duration::from_secs(30 * 60), ip);
        let session_id = session.session_id.clone();
        
        let mut sessions = self.sessions.write().unwrap();
        
        // Cleanup expired sessions
        sessions.retain(|_, s| !s.is_expired());
        
        // Check session limit per user
        let user_sessions: Vec<_> = sessions.values()
            .filter(|s| s.user.username == user.username)
            .collect();
        
        if user_sessions.len() >= self.max_sessions_per_user {
            return Err(VaultError::InvalidDataFormat(
                format!("Maximum {} concurrent sessions exceeded", self.max_sessions_per_user)
            ));
        }
        
        sessions.insert(session_id.clone(), session.clone());
        
        Ok(session)
    }

    pub fn get_session(&self, token: &str) -> Option<Session> {
        let mut sessions = self.sessions.write().unwrap();
        
        if let Some(session) = sessions.get_mut(token) {
            if session.is_expired() {
                sessions.remove(token);
                return None;
            }
            session.refresh();
            return Some(session.clone());
        }
        
        None
    }

    pub fn remove_session(&self, token: &str) -> bool {
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(token).is_some()
    }

    pub fn remove_user_sessions(&self, username: &str) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.retain(|_, s| s.user.username != username);
    }
}

// ============================================================================
// Application State
// ============================================================================

pub struct AppState {
    pub vault_file: String,
    pub counter_file: String,
    pub audit_file: String,
    pub user_db_file: String,
    pub master_passphrase: SecureString,
    pub session_manager: SessionManager,
    pub start_time: SystemTime,
}

impl AppState {
    pub fn new(
        vault_file: String,
        counter_file: String,
        audit_file: String,
        user_db_file: String,
        master_passphrase: SecureString,
    ) -> Self {
        AppState {
            vault_file,
            counter_file,
            audit_file,
            user_db_file,
            master_passphrase,
            session_manager: SessionManager::new(5), // Max 5 sessions per user
            start_time: SystemTime::now(),
        }
    }

    pub fn user_manager(&self) -> Result<UserManager> {
        UserManager::new(self.user_db_file.clone(), &self.master_passphrase)
    }
}

// ============================================================================
// Authentication Middleware
// ============================================================================

fn get_client_ip(req: &HttpRequest) -> Option<String> {
    req.connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string())
}

async fn extract_session(
    req: &HttpRequest,
    state: &web::Data<AppState>,
) -> std::result::Result<Session, HttpResponse> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        _ => {
            return Err(HttpResponse::Unauthorized().json(ErrorResponse {
                success: false,
                error: "Missing or invalid Authorization header".to_string(),
                details: Some("Expected: Authorization: Bearer <token>".to_string()),
            }));
        }
    };

    match state.session_manager.get_session(token) {
        Some(session) => Ok(session),
        None => {
            Err(HttpResponse::Unauthorized().json(ErrorResponse {
                success: false,
                error: "Invalid or expired session".to_string(),
                details: None,
            }))
        }
    }
}

fn require_permission(session: &Session, min_role: UserRole) -> std::result::Result<(), HttpResponse> {
    if !session.has_permission(min_role) {
        return Err(HttpResponse::Forbidden().json(ErrorResponse {
            success: false,
            error: "Insufficient permissions".to_string(),
            details: Some(format!("This operation requires {:?} role", min_role)),
        }));
    }
    Ok(())
}

// ============================================================================
// API Handlers - Authentication
// ============================================================================

async fn login(
    req: HttpRequest,
    login_req: web::Json<LoginRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let ip = get_client_ip(&req);
    let mut user_manager = match state.user_manager() {
        Ok(m) => m,
        Err(_) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "User management system unavailable".to_string(),
                details: None,
            });
        }
    };

    // Authenticate user
    match user_manager.authenticate(&login_req.username, &login_req.password) {
        Ok((user, vault_passphrase)) => {
            // Create session
            match state.session_manager.create_session(user.clone(), vault_passphrase, ip) {
                Ok(session) => {
                    let expires_at = DateTime::<Utc>::from(session.expires_at)
                        .format("%Y-%m-%d %H:%M:%S UTC")
                        .to_string();

                    HttpResponse::Ok().json(LoginResponse {
                        token: session.session_id,
                        expires_at,
                        username: user.username,
                        role: format!("{:?}", user.role),
                    })
                }
                Err(e) => {
                    HttpResponse::TooManyRequests().json(ErrorResponse {
                        success: false,
                        error: "Session creation failed".to_string(),
                        details: Some(e.to_string()),
                    })
                }
            }
        }
        Err(VaultError::AuthenticationFailed) => {
            HttpResponse::Unauthorized().json(ErrorResponse {
                success: false,
                error: "Invalid username or password".to_string(),
                details: None,
            })
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Authentication failed".to_string(),
                details: Some(e.to_string()),
            })
        }
    }
}

async fn logout(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    match extract_session(&req, &state).await {
        Ok(session) => {
            state.session_manager.remove_session(&session.session_id);
            HttpResponse::Ok().json(ApiResponse::<()> {
                success: true,
                data: None,
                message: Some("Logged out successfully".to_string()),
            })
        }
        Err(response) => response,
    }
}

async fn change_password(
    req: HttpRequest,
    change_req: web::Json<ChangePasswordRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let session = match extract_session(&req, &state).await {
        Ok(s) => s,
        Err(response) => return response,
    };

    let user_manager = match state.user_manager() {
        Ok(m) => m,
        Err(_) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "User management unavailable".to_string(),
                details: None,
            });
        }
    };

    match user_manager.change_password(
        &session.user.username,
        &change_req.old_password,
        &change_req.new_password,
    ) {
        Ok(_) => {
            // Invalidate all sessions for this user (force re-login)
            state.session_manager.remove_user_sessions(&session.user.username);

            HttpResponse::Ok().json(ApiResponse::<()> {
                success: true,
                data: None,
                message: Some("Password changed successfully. Please log in again.".to_string()),
            })
        }
        Err(e) => {
            HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Password change failed".to_string(),
                details: Some(e.to_string()),
            })
        }
    }
}

async fn whoami(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let session = match extract_session(&req, &state).await {
        Ok(s) => s,
        Err(response) => return response,
    };

    let user_info = UserInfo {
        username: session.user.username.clone(),
        role: format!("{:?}", session.user.role),
        created_at: format_timestamp(session.user.created_at),
        last_login: session.user.last_login.map(format_timestamp),
        login_count: session.user.login_count,
    };

    HttpResponse::Ok().json(user_info)
}

// ============================================================================
// API Handlers - User Management (Admin Only)
// ============================================================================

async fn create_user(
    req: HttpRequest,
    user_req: web::Json<CreateUserRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let session = match extract_session(&req, &state).await {
        Ok(s) => s,
        Err(response) => return response,
    };

    if let Err(response) = require_permission(&session, UserRole::Admin) {
        return response;
    }

    let role = match user_req.role.as_str() {
        "Admin" => UserRole::Admin,
        "ReadWrite" => UserRole::ReadWrite,
        "ReadOnly" => UserRole::ReadOnly,
        _ => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid role".to_string(),
                details: Some("Valid roles: Admin, ReadWrite, ReadOnly".to_string()),
            });
        }
    };

    let user_manager = match state.user_manager() {
        Ok(m) => m,
        Err(_) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "User management unavailable".to_string(),
                details: None,
            });
        }
    };

    // Use the same vault passphrase (shared vault model)
    match user_manager.add_user(
        user_req.username.clone(),
        &user_req.password,
        role,
        &session.vault_passphrase,
    ) {
        Ok(_) => {
            HttpResponse::Ok().json(ApiResponse::<()> {
                success: true,
                data: None,
                message: Some(format!("User '{}' created successfully", user_req.username)),
            })
        }
        Err(e) => {
            HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "User creation failed".to_string(),
                details: Some(e.to_string()),
            })
        }
    }
}

async fn list_users(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let session = match extract_session(&req, &state).await {
        Ok(s) => s,
        Err(response) => return response,
    };

    if let Err(response) = require_permission(&session, UserRole::Admin) {
        return response;
    }

    let user_manager = match state.user_manager() {
        Ok(m) => m,
        Err(_) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "User management unavailable".to_string(),
                details: None,
            });
        }
    };

    match user_manager.list_users() {
        Ok(users) => {
            let user_infos: Vec<UserInfo> = users.iter().map(|u| UserInfo {
                username: u.username.clone(),
                role: format!("{:?}", u.role),
                created_at: format_timestamp(u.created_at),
                last_login: u.last_login.map(format_timestamp),
                login_count: u.login_count,
            }).collect();

            HttpResponse::Ok().json(user_infos)
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Failed to list users".to_string(),
                details: Some(e.to_string()),
            })
        }
    }
}

// ============================================================================
// API Handlers - Secrets (Permission-based)
// ============================================================================

async fn list_secrets(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let session = match extract_session(&req, &state).await {
        Ok(s) => s,
        Err(response) => return response,
    };

    if !session.user.role.can_read() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            success: false,
            error: "Read permission required".to_string(),
            details: None,
        });
    }

    let counter_key = match derive_counter_key(&session.vault_passphrase) {
        Ok(key) => key,
        Err(_) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Failed to derive keys".to_string(),
                details: None,
            });
        }
    };

    match load_vault(
        &state.vault_file,
        &state.counter_file,
        &session.vault_passphrase,
        &counter_key,
    ) {
        Ok((vault, _)) => {
            let keys: Vec<String> = vault.keys().cloned().collect();
            HttpResponse::Ok().json(keys)
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            success: false,
            error: "Failed to load vault".to_string(),
            details: Some(e.to_string()),
        }),
    }
}

async fn get_secret(
    req: HttpRequest,
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let session = match extract_session(&req, &state).await {
        Ok(s) => s,
        Err(response) => return response,
    };

    if !session.user.role.can_read() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            success: false,
            error: "Read permission required".to_string(),
            details: None,
        });
    }

    let key = path.into_inner();
    let counter_key = match derive_counter_key(&session.vault_passphrase) {
        Ok(key) => key,
        Err(_) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Failed to derive keys".to_string(),
                details: None,
            });
        }
    };

    match load_vault(
        &state.vault_file,
        &state.counter_file,
        &session.vault_passphrase,
        &counter_key,
    ) {
        Ok((vault, _)) => {
            if let Some(value) = vault.get(&key) {
                HttpResponse::Ok().json(SecretResponse {
                    key: key.clone(),
                    value: Some(value.as_str().to_string()),
                })
            } else {
                HttpResponse::NotFound().json(ErrorResponse {
                    success: false,
                    error: "Secret not found".to_string(),
                    details: None,
                })
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            success: false,
            error: "Failed to load vault".to_string(),
            details: Some(e.to_string()),
        }),
    }
}

async fn set_secret(
    req: HttpRequest,
    secret: web::Json<SecretRequest>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let session = match extract_session(&req, &state).await {
        Ok(s) => s,
        Err(response) => return response,
    };

    if !session.user.role.can_write() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            success: false,
            error: "Write permission required".to_string(),
            details: None,
        });
    }

    let counter_key = match derive_counter_key(&session.vault_passphrase) {
        Ok(key) => key,
        Err(_) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Failed to derive keys".to_string(),
                details: None,
            });
        }
    };

    let mut vault = match load_vault(
        &state.vault_file,
        &state.counter_file,
        &session.vault_passphrase,
        &counter_key,
    ) {
        Ok((v, _)) => v,
        Err(e) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Failed to load vault".to_string(),
                details: Some(e.to_string()),
            });
        }
    };

    vault.insert(
        secret.key.clone(),
        SecureString::new(secret.value.clone()),
    );

    match save_vault(
        &state.vault_file,
        &state.counter_file,
        &vault,
        &session.vault_passphrase,
        &counter_key,
    ) {
        Ok(_) => {
            HttpResponse::Ok().json(ApiResponse::<()> {
                success: true,
                data: None,
                message: Some(format!("Secret '{}' saved", secret.key)),
            })
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            success: false,
            error: "Failed to save vault".to_string(),
            details: Some(e.to_string()),
        }),
    }
}

async fn delete_secret(
    req: HttpRequest,
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> HttpResponse {
    let session = match extract_session(&req, &state).await {
        Ok(s) => s,
        Err(response) => return response,
    };

    if !session.user.role.can_delete() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            success: false,
            error: "Delete permission required".to_string(),
            details: None,
        });
    }

    let key = path.into_inner();
    let counter_key = match derive_counter_key(&session.vault_passphrase) {
        Ok(key) => key,
        Err(_) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Failed to derive keys".to_string(),
                details: None,
            });
        }
    };

    let mut vault = match load_vault(
        &state.vault_file,
        &state.counter_file,
        &session.vault_passphrase,
        &counter_key,
    ) {
        Ok((v, _)) => v,
        Err(e) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Failed to load vault".to_string(),
                details: Some(e.to_string()),
            });
        }
    };

    if vault.remove(&key).is_some() {
        match save_vault(
            &state.vault_file,
            &state.counter_file,
            &vault,
            &session.vault_passphrase,
            &counter_key,
        ) {
            Ok(_) => {
                HttpResponse::Ok().json(ApiResponse::<()> {
                    success: true,
                    data: None,
                    message: Some(format!("Secret '{}' deleted", key)),
                })
            }
            Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
                success: false,
                error: "Failed to save vault".to_string(),
                details: Some(e.to_string()),
            }),
        }
    } else {
        HttpResponse::NotFound().json(ErrorResponse {
            success: false,
            error: "Secret not found".to_string(),
            details: None,
        })
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

fn format_timestamp(timestamp: u64) -> String {
    DateTime::<Utc>::from(SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp))
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string()
}

async fn health_check(state: web::Data<AppState>) -> HttpResponse {
    let uptime = SystemTime::now()
        .duration_since(state.start_time)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": uptime,
    }))
}

// ============================================================================
// Server Configuration
// ============================================================================

#[actix_web::main]
pub async fn run_api_server(
    vault_file: String,
    counter_file: String,
    audit_file: String,
    user_db_file: String,
    master_passphrase: SecureString,
    bind_address: &str,
) -> std::io::Result<()> {
    println!("🔐 Starting Secure Vault API Server");
    println!("   Vault: {}", vault_file);
    println!("   User DB: {}", user_db_file);
    println!("   Listening on: {}", bind_address);
    println!();

    let state = web::Data::new(AppState::new(
        vault_file,
        counter_file,
        audit_file,
        user_db_file,
        master_passphrase,
    ));

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            // Public endpoints
            .route("/health", web::get().to(health_check))
            .route("/api/v1/auth/login", web::post().to(login))
            // Protected endpoints
            .service(
                web::scope("/api/v1")
                    .route("/auth/logout", web::post().to(logout))
                    .route("/auth/whoami", web::get().to(whoami))
                    .route("/auth/change-password", web::post().to(change_password))
                    // Secrets
                    .route("/secrets", web::get().to(list_secrets))
                    .route("/secrets", web::post().to(set_secret))
                    .route("/secrets/{key}", web::get().to(get_secret))
                    .route("/secrets/{key}", web::delete().to(delete_secret))
                    // Admin - User Management
                    .route("/admin/users", web::post().to(create_user))
                    .route("/admin/users", web::get().to(list_users))
            )
    })
    .bind(bind_address)?
    .run()
    .await
}