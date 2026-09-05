#![allow(clippy::disallowed_types)]

//! Separate read capacity from login failures, refreshes and account changes.
//! The aggregate key is process-owned, not derived from spoofable forwarding headers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

use crate::middleware::CurrentUser;
use aionui_common::ApiError;

const CREDIT_PER_TOKEN: u128 = 60_000;
const MAX_SUBJECTS: usize = 4096;
const IDLE_EXPIRY: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug)]
pub struct ReadRatePolicy {
    pub user_per_minute: u32,
    pub user_burst: u32,
    pub aggregate_per_minute: u32,
    pub aggregate_burst: u32,
}

impl Default for ReadRatePolicy {
    fn default() -> Self {
        Self {
            user_per_minute: 600,
            user_burst: 60,
            aggregate_per_minute: 1200,
            aggregate_burst: 120,
        }
    }
}

impl ReadRatePolicy {
    /// Validate all configured capacities before the server accepts traffic.
    pub fn from_env() -> Result<Self, String> {
        let defaults = Self::default();
        Self {
            user_per_minute: read_value("AIONUI_IDENTITY_READ_RPM", defaults.user_per_minute)?,
            user_burst: read_value("AIONUI_IDENTITY_READ_BURST", defaults.user_burst)?,
            aggregate_per_minute: read_value("AIONUI_IDENTITY_AGGREGATE_RPM", defaults.aggregate_per_minute)?,
            aggregate_burst: read_value("AIONUI_IDENTITY_AGGREGATE_BURST", defaults.aggregate_burst)?,
        }
        .validate()
    }

    pub fn validate(self) -> Result<Self, String> {
        if [
            self.user_per_minute,
            self.user_burst,
            self.aggregate_per_minute,
            self.aggregate_burst,
        ]
        .iter()
        .any(|value| !(1..=60_000).contains(value))
        {
            return Err("Identity read rate capacities must be between 1 and 60000".to_owned());
        }
        if self.user_burst > self.user_per_minute || self.aggregate_burst > self.aggregate_per_minute {
            return Err("Identity read bursts must not exceed the respective per-minute rate".to_owned());
        }
        Ok(self)
    }
}

fn read_value(name: &str, default: u32) -> Result<u32, String> {
    match std::env::var(name) {
        Ok(value) => value.parse().map_err(|_| format!("{name} must be a positive integer")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(_) => Err(format!("{name} must be a positive integer")),
    }
}

struct Bucket {
    credit: u128,
    updated: Instant,
}

struct BucketStore {
    entries: HashMap<String, Bucket>,
    last_cleanup: Instant,
}

struct TokenBuckets {
    store: Mutex<BucketStore>,
    per_minute: u32,
    burst: u32,
}

impl TokenBuckets {
    fn new(per_minute: u32, burst: u32) -> Self {
        Self {
            store: Mutex::new(BucketStore {
                entries: HashMap::new(),
                last_cleanup: Instant::now(),
            }),
            per_minute,
            burst,
        }
    }

    fn check_at(&self, key: &str, now: Instant) -> Result<(), u64> {
        let mut store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if now.saturating_duration_since(store.last_cleanup) >= Duration::from_secs(60) {
            store
                .entries
                .retain(|_, entry| now.saturating_duration_since(entry.updated) < IDLE_EXPIRY);
            store.last_cleanup = now;
        }
        // Bounded storage even if many authenticated users are active in one process.
        if store.entries.len() >= MAX_SUBJECTS && !store.entries.contains_key(key) {
            return Err(60);
        }
        let capacity = u128::from(self.burst) * CREDIT_PER_TOKEN;
        let bucket = store.entries.entry(key.to_owned()).or_insert(Bucket {
            credit: capacity,
            updated: now,
        });
        let refill = now.saturating_duration_since(bucket.updated).as_millis() * u128::from(self.per_minute);
        bucket.credit = capacity.min(bucket.credit.saturating_add(refill));
        bucket.updated = now;
        if bucket.credit < CREDIT_PER_TOKEN {
            let retry_ms = (CREDIT_PER_TOKEN - bucket.credit).div_ceil(u128::from(self.per_minute));
            return Err(retry_ms.div_ceil(1000).max(1) as u64);
        }
        bucket.credit -= CREDIT_PER_TOKEN;
        Ok(())
    }
}

pub struct IdentityReadLimits {
    users: TokenBuckets,
    aggregate: TokenBuckets,
    log_salt: [u8; 32],
}

impl IdentityReadLimits {
    pub fn new(policy: ReadRatePolicy) -> Result<Self, String> {
        let policy = policy.validate()?;
        let mut log_salt = [0; 32];
        getrandom::getrandom(&mut log_salt).map_err(|_| "Cannot initialize rate-limit diagnostics".to_owned())?;
        Ok(Self {
            users: TokenBuckets::new(policy.user_per_minute, policy.user_burst),
            aggregate: TokenBuckets::new(policy.aggregate_per_minute, policy.aggregate_burst),
            log_salt,
        })
    }

    fn limited(&self, class: &'static str, subject: &str, retry_after: u64) -> Response {
        let mut hash = Sha256::new();
        hash.update(self.log_salt);
        hash.update(subject.as_bytes());
        let subject_key = format!("{:x}", hash.finalize());
        tracing::warn!(
            limiter_class = class,
            subject_key = &subject_key[..16],
            retry_after,
            "identity read rate limited"
        );
        let mut response = ApiError::RateLimited.into_response();
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_str(&retry_after.to_string()).expect("integer header"),
        );
        response
    }
}

/// Outer gate: all read attempts share this server-owned process budget.
pub async fn aggregate_read_rate_limit_middleware(
    State(limits): State<Arc<IdentityReadLimits>>,
    request: Request,
    next: Next,
) -> Response {
    if let Err(retry) = limits.aggregate.check_at("process", Instant::now()) {
        return limits.limited("identity_aggregate", "process", retry);
    }
    next.run(request).await
}

/// Inner gate: only a successfully authenticated identity supplies the user key.
pub async fn user_read_rate_limit_middleware(
    State(limits): State<Arc<IdentityReadLimits>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(user) = request.extensions().get::<CurrentUser>() else {
        return ApiError::Unauthorized("Authentication required".to_owned()).into_response();
    };
    if let Err(retry) = limits.users.check_at(&user.id, Instant::now()) {
        return limits.limited("identity_user", &user.id, retry);
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_bounded_capacity() {
        assert!(ReadRatePolicy::default().validate().is_ok());
        assert!(
            ReadRatePolicy {
                user_per_minute: 0,
                ..ReadRatePolicy::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            ReadRatePolicy {
                user_burst: 601,
                ..ReadRatePolicy::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            ReadRatePolicy {
                aggregate_per_minute: 60_001,
                ..ReadRatePolicy::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn burst_refill_and_retry_are_deterministic() {
        let limiter = TokenBuckets::new(60, 2);
        let now = Instant::now();
        assert_eq!(limiter.check_at("a", now), Ok(()));
        assert_eq!(limiter.check_at("a", now), Ok(()));
        assert_eq!(limiter.check_at("a", now), Err(1));
        assert_eq!(limiter.check_at("a", now + Duration::from_millis(999)), Err(1));
        assert_eq!(limiter.check_at("a", now + Duration::from_secs(1)), Ok(()));
        assert_eq!(limiter.check_at("b", now), Ok(()));
    }

    #[test]
    fn concurrent_requests_cannot_exceed_burst() {
        let limiter = Arc::new(TokenBuckets::new(600, 10));
        let now = Instant::now();
        let accepted = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..40)
                .map(|_| scope.spawn(|| limiter.check_at("a", now).is_ok()))
                .collect();
            handles
                .into_iter()
                .filter_map(|h| h.join().ok())
                .filter(|allowed| *allowed)
                .count()
        });
        assert_eq!(accepted, 10);
    }

    #[test]
    fn subject_storage_is_bounded_and_expired_entries_are_reclaimed() {
        let limiter = TokenBuckets::new(60, 1);
        let now = Instant::now();
        for index in 0..MAX_SUBJECTS {
            assert_eq!(limiter.check_at(&index.to_string(), now), Ok(()));
        }
        assert_eq!(limiter.check_at("overflow", now), Err(60));
        assert_eq!(limiter.check_at("overflow", now + IDLE_EXPIRY), Ok(()));
        assert_eq!(limiter.store.lock().unwrap().entries.len(), 1);
    }

    #[test]
    fn rejection_carries_retry_after_without_exposing_subject() {
        let limits = IdentityReadLimits::new(ReadRatePolicy::default()).unwrap();
        let response = limits.limited("identity_user", "private-user", 2);
        assert_eq!(response.status(), 429);
        assert_eq!(response.headers()[header::RETRY_AFTER], "2");
    }
}
