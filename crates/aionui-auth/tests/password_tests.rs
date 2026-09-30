//! Full-password semantics and the compatibility boundary for legacy bcrypt.
use aionui_auth::{hash_password, verify_password, verify_password_timed};

#[test]
fn new_hashes_distinguish_suffixes_after_bcrypt_limit() {
    for prefix in ["a".repeat(72), "🦀".repeat(18), "a\0".repeat(36)] {
        let password = format!("{prefix}original");
        let alias = format!("{prefix}different");
        let hash = hash_password(&password).unwrap();
        assert!(verify_password(&password, &hash).unwrap());
        assert!(!verify_password(&alias, &hash).unwrap(), "suffix was ignored");
        assert!(!verify_password(&prefix, &hash).unwrap(), "suffix was discarded");
    }
}

#[test]
fn legacy_bcrypt_remains_verifiable_without_implicit_migration() {
    // A real old-format fixture, independent of the production hash function.
    // The legacy ambiguity is deliberately retained until an explicit change.
    let password = format!("{}original", "a".repeat(72));
    let hash = bcrypt::hash(&password, 4).unwrap();
    assert!(verify_password(&password, &hash).unwrap());
    assert!(verify_password(&format!("{}alias", "a".repeat(72)), &hash).unwrap());
    assert!(!verify_password("incorrect", &hash).unwrap());
}

#[tokio::test]
async fn oversized_passwords_fail_before_hashing_and_timed_verification() {
    let password = "🦀".repeat(129);
    assert!(matches!(
        hash_password(&password),
        Err(aionui_auth::AuthError::WeakPassword(_))
    ));
    // Invalid hash proves the bounded-input guard runs before bcrypt parsing.
    assert!(!verify_password(&password, "invalid hash").unwrap());
    assert!(!verify_password_timed(&password, "invalid hash").await.unwrap());
}

#[test]
fn hash_encoding_fails_closed_without_legacy_fallback() {
    let hash = hash_password("Strong password").unwrap();
    let unknown = hash.replacen("v1$", "v999$", 1);
    assert!(verify_password("Strong password", &unknown).is_err());
    assert!(verify_password("Strong password", "$aionui-bcrypt-sha256-v1$invalid").is_err());
}

#[test]
fn password_generation_bounds_requested_allocation() {
    let password = aionui_auth::generate_password(usize::MAX);
    assert_eq!(password.len(), 128);
    assert!(aionui_auth::validate_password(&password).is_ok());
}
