use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

#[derive(Error, Debug)]
pub enum VaultClientError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    
    #[error("Secret not found: {0}")]
    SecretNotFound(String),
    
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    
    #[error("Session expired")]
    SessionExpired,
    
    #[error("API error: {0}")]
    ApiError(String),
}

pub type Result<T> = std::result::Result<T, VaultClientError>;

// ============================================================================
// API Models
// ============================================================================

#[derive(Debug, Serialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    token: String,
    expires_at: String,
    username: String,
    role: String,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    success: bool,
    error: String,
    details: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SecretRequest {
    key: String,
    value: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SecretResponse {
    key: String,
    value: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    message: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UserInfo {
    pub username: String,
    pub role: String,
    pub created_at: String,
    pub last_login: Option<String>,
    pub login_count: u64,
}

#[derive(Debug, Serialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    role: String,
}

#[derive(Debug, Serialize)]
struct ChangePasswordRequest {
    old_password: String,
    new_password: String,
}

// ============================================================================
// Session Management
// ============================================================================

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct SessionInfo {
    token: String,
    username: String,
    role: String,
    expires_at: SystemTime,
}

impl SessionInfo {
    fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }
    
    fn is_expiring_soon(&self) -> bool {
        // Refresh if less than 5 minutes remaining
        if let Ok(remaining) = self.expires_at.duration_since(SystemTime::now()) {
            remaining < Duration::from_secs(5 * 60)
        } else {
            true
        }
    }
}

// ============================================================================
// Vault Client
// ============================================================================

pub struct VaultClient {
    base_url: String,
    client: Client,
    credentials: Arc<RwLock<Option<(String, String)>>>, // (username, password)
    session: Arc<RwLock<Option<SessionInfo>>>,
}

impl VaultClient {
    /// Create a new vault client
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10)
            .build()?;

        Ok(VaultClient {
            base_url: base_url.into(),
            client,
            credentials: Arc::new(RwLock::new(None)),
            session: Arc::new(RwLock::new(None)),
        })
    }

    /// Login and store credentials for automatic re-authentication
    pub async fn login(&self, username: &str, password: &str) -> Result<LoginResponse> {
        let login_req = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        };

        let response = self
            .client
            .post(format!("{}/api/v1/auth/login", self.base_url))
            .json(&login_req)
            .send()
            .await?;

        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(VaultClientError::AuthenticationFailed(
                "Invalid credentials".to_string(),
            ));
        }

        let login_response: LoginResponse = self.handle_response(response).await?;

        // Parse expires_at and store session
        let expires_at = self.parse_expiry(&login_response.expires_at)?;
        
        let session = SessionInfo {
            token: login_response.token.clone(),
            username: login_response.username.clone(),
            role: login_response.role.clone(),
            expires_at,
        };

        // Store credentials for auto re-login
        *self.credentials.write().unwrap() = Some((username.to_string(), password.to_string()));
        *self.session.write().unwrap() = Some(session);

        Ok(login_response)
    }

    /// Logout and clear stored credentials
    pub async fn logout(&self) -> Result<()> {
        if let Ok(token) = self.get_token() {
            let response = self
                .client
                .post(format!("{}/api/v1/auth/logout", self.base_url))
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await?;

            let _: ApiResponse<()> = self.handle_response(response).await?;
        }

        *self.credentials.write().unwrap() = None;
        *self.session.write().unwrap() = None;

        Ok(())
    }

    /// Get current user information
    pub async fn whoami(&self) -> Result<UserInfo> {
        let token = self.ensure_valid_token().await?;
        
        let response = self
            .client
            .get(format!("{}/api/v1/auth/whoami", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        self.handle_response(response).await
    }

    /// Change password
    pub async fn change_password(&self, old_password: &str, new_password: &str) -> Result<()> {
        let token = self.ensure_valid_token().await?;
        
        let change_req = ChangePasswordRequest {
            old_password: old_password.to_string(),
            new_password: new_password.to_string(),
        };

        let response = self
            .client
            .post(format!("{}/api/v1/auth/change-password", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&change_req)
            .send()
            .await?;

        let _: ApiResponse<()> = self.handle_response(response).await?;

        // Update stored password
        if let Some((username, _)) = self.credentials.read().unwrap().as_ref() {
            *self.credentials.write().unwrap() = Some((username.clone(), new_password.to_string()));
        }

        // Clear session to force re-login
        *self.session.write().unwrap() = None;

        Ok(())
    }

    /// List all secret keys
    pub async fn list_secrets(&self) -> Result<Vec<String>> {
        let token = self.ensure_valid_token().await?;
        
        let response = self
            .client
            .get(format!("{}/api/v1/secrets", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        self.handle_response(response).await
    }

    /// Get a secret value
    pub async fn get_secret(&self, key: &str) -> Result<Option<String>> {
        let token = self.ensure_valid_token().await?;
        
        let response = self
            .client
            .get(format!("{}/api/v1/secrets/{}", self.base_url, key))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let secret: SecretResponse = self.handle_response(response).await?;
        Ok(secret.value)
    }

    /// Set a secret
    pub async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        let token = self.ensure_valid_token().await?;
        
        let secret_req = SecretRequest {
            key: key.to_string(),
            value: value.to_string(),
        };

        let response = self
            .client
            .post(format!("{}/api/v1/secrets", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&secret_req)
            .send()
            .await?;

        let _: ApiResponse<()> = self.handle_response(response).await?;
        Ok(())
    }

    /// Delete a secret
    pub async fn delete_secret(&self, key: &str) -> Result<()> {
        let token = self.ensure_valid_token().await?;
        
        let response = self
            .client
            .delete(format!("{}/api/v1/secrets/{}", self.base_url, key))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Err(VaultClientError::SecretNotFound(key.to_string()));
        }

        let _: ApiResponse<()> = self.handle_response(response).await?;
        Ok(())
    }

    /// Create a new user (Admin only)
    pub async fn create_user(&self, username: &str, password: &str, role: &str) -> Result<()> {
        let token = self.ensure_valid_token().await?;
        
        let user_req = CreateUserRequest {
            username: username.to_string(),
            password: password.to_string(),
            role: role.to_string(),
        };

        let response = self
            .client
            .post(format!("{}/api/v1/admin/users", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&user_req)
            .send()
            .await?;

        let _: ApiResponse<()> = self.handle_response(response).await?;
        Ok(())
    }

    /// List all users (Admin only)
    pub async fn list_users(&self) -> Result<Vec<UserInfo>> {
        let token = self.ensure_valid_token().await?;
        
        let response = self
            .client
            .get(format!("{}/api/v1/admin/users", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        self.handle_response(response).await
    }

    /// Health check
    pub async fn health_check(&self) -> Result<serde_json::Value> {
        let response = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;

        self.handle_response(response).await
    }

    // ========================================================================
    // Internal Helper Methods
    // ========================================================================

    /// Ensure we have a valid token, refreshing if necessary
    async fn ensure_valid_token(&self) -> Result<String> {
        // Check if session exists and is valid
        {
            let session = self.session.read().unwrap();
            if let Some(ref s) = *session {
                if !s.is_expired() && !s.is_expiring_soon() {
                    return Ok(s.token.clone());
                }
            }
        }

        // Need to refresh - do we have credentials?
        let credentials = self.credentials.read().unwrap().clone();
        match credentials {
            Some((username, password)) => {
                // Auto re-login
                self.login(&username, &password).await?;
                self.get_token()
            }
            None => Err(VaultClientError::SessionExpired),
        }
    }

    /// Get current token without refresh
    fn get_token(&self) -> Result<String> {
        let session = self.session.read().unwrap();
        match *session {
            Some(ref s) => Ok(s.token.clone()),
            None => Err(VaultClientError::SessionExpired),
        }
    }

    /// Handle API response with error checking
    async fn handle_response<T: for<'de> Deserialize<'de>>(
        &self,
        response: reqwest::Response,
    ) -> Result<T> {
        let status = response.status();

        if status.is_success() {
            response
                .json::<T>()
                .await
                .map_err(|e| VaultClientError::InvalidResponse(e.to_string()))
        } else {
            // Try to parse error response
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            
            if let Ok(error_response) = serde_json::from_str::<ErrorResponse>(&error_text) {
                let message = if !error_response.success && let Some(details) = error_response.details {
                    format!("{}: {}", error_response.error, details)
                } else {
                    error_response.error
                };

                match status {
                    StatusCode::UNAUTHORIZED => Err(VaultClientError::AuthenticationFailed(message)),
                    StatusCode::FORBIDDEN => Err(VaultClientError::PermissionDenied(message)),
                    StatusCode::NOT_FOUND => Err(VaultClientError::SecretNotFound(message)),
                    _ => Err(VaultClientError::ApiError(message)),
                }
            } else {
                Err(VaultClientError::ApiError(format!("HTTP {}: {}", status, error_text)))
            }
        }
    }

    /// Parse expiry timestamp from server response
    fn parse_expiry(&self, expires_at: &str) -> Result<SystemTime> {
        // Parse format: "2025-12-30 15:30:00 UTC"
        use chrono::{DateTime, Utc, NaiveDateTime};
        
        let naive = NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S UTC")
            .map_err(|e| VaultClientError::InvalidResponse(format!("Invalid timestamp: {}", e)))?;
        
        let dt: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive, Utc);
        let duration = dt.timestamp() as u64;
        
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(duration))
    }
}

// ============================================================================
// Example Usage
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_workflow() -> Result<()> {
        let client = VaultClient::new("http://localhost:8080")?;

        // Login
        let login_resp = client.login("admin", "admin_password").await?;
        println!("Logged in as: {} ({})", login_resp.username, login_resp.role);

        // Get user info
        let user_info = client.whoami().await?;
        println!("User info: {:?}", user_info);

        // Set a secret
        client.set_secret("api_key", "super-secret-value").await?;
        println!("Secret saved");

        // Get the secret
        if let Some(value) = client.get_secret("api_key").await? {
            println!("Retrieved secret: {}", value);
        }

        // List all secrets
        let secrets = client.list_secrets().await?;
        println!("All secrets: {:?}", secrets);

        // Logout
        client.logout().await?;
        println!("Logged out");

        Ok(())
    }
}