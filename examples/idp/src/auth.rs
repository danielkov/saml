//! Local user store backed by `config/users.toml`.
//!
//! At startup the seed `password` cleartext from `users.toml` is hashed
//! once with argon2id (default parameters) and the cleartext is dropped.
//! [`UserStore::verify_password`] compares an inbound credential against
//! the stored hash via the argon2 verifier's constant-time check.

use std::collections::HashMap;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHashString, PasswordHasher, SaltString};
use argon2::{Argon2, PasswordVerifier};
use serde::Deserialize;

/// Wire layout for `users.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct UsersFile {
    #[serde(default)]
    pub user: Vec<UserConfig>,
}

/// One user as it appears in `users.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    pub id: String,
    pub email: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    #[serde(default)]
    pub department: Option<String>,
}

impl UsersFile {
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

/// One user, ready for authentication. Cleartext password from
/// `users.toml` has been hashed; only the [`PasswordHashString`] is kept
/// in memory.
#[derive(Debug, Clone)]
pub struct StoredUser {
    pub id: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub department: Option<String>,
    pub password_hash: PasswordHashString,
}

impl StoredUser {
    pub fn display_name(&self) -> String {
        format!("{} {}", self.first_name, self.last_name)
    }

    pub fn initial(&self) -> String {
        self.first_name
            .chars()
            .next()
            .map_or_else(|| "?".to_owned(), |c| c.to_uppercase().to_string())
    }
}

/// In-memory user store keyed by both `id` and lowercased `email`, so
/// the login form accepts either identifier.
#[derive(Debug, Clone, Default)]
pub struct UserStore {
    by_id: HashMap<String, StoredUser>,
    by_email: HashMap<String, String>,
}

impl UserStore {
    /// Hash each seed user's cleartext password and build the lookup
    /// tables. Argon2id default parameters; the hash bound to each user
    /// is the only material retained.
    pub fn from_users_file(file: &UsersFile) -> Result<Self, AuthError> {
        let mut by_id = HashMap::with_capacity(file.user.len());
        let mut by_email = HashMap::with_capacity(file.user.len());
        let argon = Argon2::default();
        for u in &file.user {
            let salt = SaltString::generate(&mut OsRng);
            let hash = argon
                .hash_password(u.password.as_bytes(), &salt)
                .map_err(AuthError::Argon2)?
                .serialize();
            let stored = StoredUser {
                id: u.id.clone(),
                email: u.email.clone(),
                first_name: u.first_name.clone(),
                last_name: u.last_name.clone(),
                department: u.department.clone(),
                password_hash: hash,
            };
            by_email.insert(u.email.to_ascii_lowercase(), u.id.clone());
            if by_id.insert(u.id.clone(), stored).is_some() {
                return Err(AuthError::DuplicateId(u.id.clone()));
            }
        }
        Ok(Self { by_id, by_email })
    }

    pub fn get_by_id(&self, id: &str) -> Option<&StoredUser> {
        self.by_id.get(id)
    }

    pub fn lookup(&self, username_or_email: &str) -> Option<&StoredUser> {
        if let Some(u) = self.by_id.get(username_or_email) {
            return Some(u);
        }
        let key = username_or_email.to_ascii_lowercase();
        let id = self.by_email.get(&key)?;
        self.by_id.get(id)
    }

    /// Validate a cleartext password against the stored argon2id hash.
    /// Returns the matched user on success.
    pub fn verify_password(&self, username_or_email: &str, password: &str) -> Option<&StoredUser> {
        let user = self.lookup(username_or_email)?;
        let parsed = PasswordHash::new(user.password_hash.as_str()).ok()?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .ok()?;
        Some(user)
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

#[derive(Debug)]
pub enum AuthError {
    Argon2(argon2::password_hash::Error),
    DuplicateId(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Argon2(e) => write!(f, "argon2 hashing failed: {e}"),
            Self::DuplicateId(id) => write!(f, "duplicate user id `{id}` in users.toml"),
        }
    }
}
impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_file() -> UsersFile {
        UsersFile {
            user: vec![
                UserConfig {
                    id: "alice".into(),
                    email: "alice@saml-demo.local".into(),
                    password: "password".into(),
                    first_name: "Alice".into(),
                    last_name: "Anderson".into(),
                    department: Some("Platform".into()),
                },
                UserConfig {
                    id: "bob".into(),
                    email: "bob@saml-demo.local".into(),
                    password: "hunter2".into(),
                    first_name: "Bob".into(),
                    last_name: "Builder".into(),
                    department: None,
                },
            ],
        }
    }

    #[test]
    fn loads_users_and_hashes_passwords() {
        let store = UserStore::from_users_file(&sample_file()).expect("loads");
        assert_eq!(store.len(), 2);
        let alice = store.get_by_id("alice").expect("alice present");
        assert_ne!(alice.password_hash.as_str(), "password");
        assert!(
            alice.password_hash.as_str().starts_with("$argon2"),
            "argon2id-marked hash: {}",
            alice.password_hash.as_str()
        );
    }

    #[test]
    fn verify_password_matches_correct_credentials_by_id_or_email() {
        let store = UserStore::from_users_file(&sample_file()).unwrap();
        assert!(store.verify_password("alice", "password").is_some());
        assert!(
            store
                .verify_password("alice@saml-demo.local", "password")
                .is_some()
        );
        assert!(
            store
                .verify_password("ALICE@SAML-DEMO.LOCAL", "password")
                .is_some(),
            "email lookup is case-insensitive",
        );
    }

    #[test]
    fn verify_password_rejects_wrong_password() {
        let store = UserStore::from_users_file(&sample_file()).unwrap();
        assert!(store.verify_password("alice", "wrong").is_none());
    }

    #[test]
    fn verify_password_rejects_unknown_user() {
        let store = UserStore::from_users_file(&sample_file()).unwrap();
        assert!(store.verify_password("eve", "password").is_none());
    }

    #[test]
    fn display_name_and_initial() {
        let store = UserStore::from_users_file(&sample_file()).unwrap();
        let alice = store.get_by_id("alice").unwrap();
        assert_eq!(alice.display_name(), "Alice Anderson");
        assert_eq!(alice.initial(), "A");
    }

    #[test]
    fn parse_toml_accepts_optional_department() {
        let raw = r#"
[[user]]
id = "carol"
email = "carol@example.com"
password = "pw"
first_name = "Carol"
last_name = "Cobalt"
"#;
        let file = UsersFile::from_toml(raw).expect("parses");
        assert_eq!(file.user.len(), 1);
        assert!(file.user[0].department.is_none());
    }
}
