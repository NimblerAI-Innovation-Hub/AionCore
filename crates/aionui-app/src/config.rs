//! Application configuration parsed from CLI arguments + key derivation.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMode {
    Local,
    WebUi,
    AionPro,
}

impl IdentityMode {
    pub fn auth_label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::WebUi => "webui",
            Self::AionPro => "aionpro",
        }
    }

    pub fn is_local(self) -> bool {
        self == Self::Local
    }
}

/// Server capability switches; user settings cannot override these gates.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RuntimeFeaturePolicy {
    pub session_messages: bool,
    pub midturn_delivery: bool,
    pub runtime_user_auth: bool,
}

impl RuntimeFeaturePolicy {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            session_messages: parse_feature_switch(
                "AIONUI_SESSION_MESSAGES_ENABLED",
                std::env::var("AIONUI_SESSION_MESSAGES_ENABLED").ok().as_deref(),
            )?,
            runtime_user_auth: parse_feature_switch(
                "AIONUI_RUNTIME_USER_AUTH_ENABLED",
                std::env::var("AIONUI_RUNTIME_USER_AUTH_ENABLED").ok().as_deref(),
            )?,
            midturn_delivery: parse_feature_switch(
                "AIONUI_MIDTURN_DELIVERY_ENABLED",
                std::env::var("AIONUI_MIDTURN_DELIVERY_ENABLED").ok().as_deref(),
            )?,
        })
    }
}

fn parse_feature_switch(name: &str, value: Option<&str>) -> anyhow::Result<bool> {
    match value {
        None | Some("1" | "true") => Ok(true),
        Some("0" | "false") => Ok(false),
        Some(_) => anyhow::bail!("{name} must be 0, 1, false, or true"),
    }
}

/// Application configuration parsed from CLI arguments.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub data_dir: PathBuf,
    pub work_dir: PathBuf,
    pub app_version: String,
    /// Run in local embedded mode (skip authentication, use system_default_user).
    pub local: bool,
    pub identity_mode: IdentityMode,
    pub bootstrap_secret: Option<String>,
    /// Dump prompt diagnostics under `data_dir/prompt-dumps`.
    pub dump_prompts: bool,
    /// Explicitly authorize backup and rebuild for corruption-like local databases.
    pub recover_corrupted_database: bool,
}

impl AppConfig {
    pub fn effective_identity_mode(&self) -> IdentityMode {
        if self.local {
            IdentityMode::Local
        } else {
            self.identity_mode
        }
    }

    /// Format as `host:port` for socket binding.
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Local URL helpers should use to call this backend from the same machine.
    pub fn local_base_url(&self) -> String {
        let host = match self.host.as_str() {
            "0.0.0.0" | "::" => "127.0.0.1",
            other => other,
        };
        format!("http://{host}:{}", self.port)
    }

    /// Path to the SQLite database file.
    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("aionui-backend.db")
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            host: aionui_common::constants::DEFAULT_HOST.to_string(),
            port: aionui_common::constants::DEFAULT_PORT,
            data_dir: PathBuf::from("data"),
            work_dir: PathBuf::from("data"),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            local: false,
            identity_mode: IdentityMode::WebUi,
            bootstrap_secret: None,
            dump_prompts: false,
            recover_corrupted_database: false,
        }
    }
}

/// Derive a 32-byte encryption key from the storage-encryption secret using
/// SHA-256. The domain-separation prefix is part of the on-disk contract and
/// must never change — doing so would orphan every stored ciphertext.
pub fn derive_encryption_key(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aionui-encryption-key:");
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_config_default() {
        let config = AppConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 25808);
        assert_eq!(config.data_dir, PathBuf::from("data"));
        assert_eq!(config.app_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(config.identity_mode, IdentityMode::WebUi);
        assert!(config.bootstrap_secret.is_none());
        assert!(!config.dump_prompts);
        assert!(!config.recover_corrupted_database);
    }

    #[test]
    fn test_app_config_socket_addr() {
        let config = AppConfig {
            host: "0.0.0.0".to_string(),
            port: 3000,
            ..Default::default()
        };
        assert_eq!(config.socket_addr(), "0.0.0.0:3000");
    }

    #[test]
    fn local_base_url_uses_loopback_for_wildcard_host() {
        let config = AppConfig {
            host: "0.0.0.0".to_string(),
            port: 49152,
            ..Default::default()
        };
        assert_eq!(config.local_base_url(), "http://127.0.0.1:49152");
    }

    #[test]
    fn test_app_config_database_path() {
        let config = AppConfig {
            data_dir: PathBuf::from("/tmp/aionui"),
            ..Default::default()
        };
        assert_eq!(config.database_path(), PathBuf::from("/tmp/aionui/aionui-backend.db"));
    }
}

#[cfg(test)]
mod runtime_feature_policy_tests {
    use super::parse_feature_switch;

    #[test]
    fn explicit_deployment_gates_are_validated() {
        assert!(!parse_feature_switch("gate", Some("0")).unwrap());
        assert!(!parse_feature_switch("gate", Some("false")).unwrap());
        assert!(parse_feature_switch("gate", Some("1")).unwrap());
        assert!(parse_feature_switch("gate", Some("TRUE")).is_err());
        assert!(parse_feature_switch("gate", Some("")).is_err());
    }
}
