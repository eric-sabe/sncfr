//! HTTP request policy (SAFE-9, PERF-6; NA-7): per-request timeout, `Retry-After`-aware retries
//! with a per-method matrix, and an optional in-process rate limit.

use crate::error::SncfrError;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

/// Allowed `--timeout` / `SNCFR_TIMEOUT` / profile `timeout_secs` range, in seconds.
pub const TIMEOUT_RANGE: std::ops::RangeInclusive<u64> = 1..=300;
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// What kind of request is being sent, which decides how a 429 may be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// GET/HEAD and read-only batch POSTs: retried up to 3 times.
    Read,
    /// PATCH: retried once, and only on a 429 whose body is the instance's JSON.
    Patch,
    /// POST (create, order_now, attachment): never retried; a duplicate would create twice.
    Post,
}

impl RequestKind {
    pub const fn is_write(self) -> bool {
        !matches!(self, Self::Read)
    }

    /// Retries allowed for a 429 (`json_body`: the 429 came from the instance, not a proxy).
    pub const fn retries_on_429(self, json_body: bool) -> u8 {
        match self {
            Self::Read => 3,
            Self::Patch if json_body => 1,
            Self::Patch | Self::Post => 0,
        }
    }
}

/// A simple token bucket: `rpm` requests per minute, burst of `rpm`.
#[derive(Debug)]
struct Bucket {
    rpm: u32,
    tokens: f64,
    last: Instant,
}

#[derive(Debug)]
pub struct RequestPolicy {
    pub timeout: Duration,
    /// Longest single wait (a larger `Retry-After` is clamped to this).
    pub max_retry_wait: Duration,
    /// Total time spent waiting on 429s for one request.
    pub retry_budget: Duration,
    /// Base for exponential backoff when no `Retry-After` is sent.
    pub backoff_base: Duration,
    bucket: Option<Mutex<Bucket>>,
}

impl Default for RequestPolicy {
    fn default() -> Self {
        Self::new(Duration::from_secs(DEFAULT_TIMEOUT_SECS), None)
    }
}

impl RequestPolicy {
    pub fn new(timeout: Duration, rpm: Option<u32>) -> Self {
        Self {
            timeout,
            max_retry_wait: Duration::from_secs(60),
            retry_budget: Duration::from_secs(120),
            backoff_base: Duration::from_secs(1),
            bucket: rpm.filter(|r| *r > 0).map(|rpm| {
                Mutex::new(Bucket {
                    rpm,
                    tokens: f64::from(rpm),
                    last: Instant::now(),
                })
            }),
        }
    }

    /// A policy for tests: the same rules, with waits scaled down to milliseconds.
    pub fn fast_for_tests(timeout: Duration) -> Self {
        Self {
            max_retry_wait: Duration::from_millis(50),
            retry_budget: Duration::from_millis(200),
            backoff_base: Duration::from_millis(5),
            ..Self::new(timeout, None)
        }
    }

    /// Waits for a rate-limit token, if a limit is configured.
    pub async fn acquire(&self) {
        let Some(bucket) = &self.bucket else { return };
        loop {
            let wait = {
                let mut b = bucket
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let now = Instant::now();
                let refill = now.duration_since(b.last).as_secs_f64() * f64::from(b.rpm) / 60.0;
                b.tokens = (b.tokens + refill).min(f64::from(b.rpm));
                b.last = now;
                if b.tokens >= 1.0 {
                    b.tokens -= 1.0;
                    return;
                }
                Duration::from_secs_f64((1.0 - b.tokens) * 60.0 / f64::from(b.rpm))
            };
            tokio::time::sleep(wait).await;
        }
    }

    /// How long to wait before retry number `attempt` (0-based), clamped to `max_retry_wait`.
    /// `Retry-After` may be delta-seconds or an HTTP-date; negative, malformed, or past values
    /// fall back to backoff.
    pub fn retry_wait(&self, retry_after: Option<&str>, attempt: u8, now: SystemTime) -> Duration {
        let parsed = retry_after.and_then(|v| {
            let v = v.trim();
            if let Ok(secs) = v.parse::<u64>() {
                return Some(Duration::from_secs(secs));
            }
            let when = chrono::DateTime::parse_from_rfc2822(v).ok()?;
            let when =
                SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(when.timestamp()).ok()?);
            when.duration_since(now).ok().filter(|d| !d.is_zero())
        });
        let wait = parsed.unwrap_or_else(|| {
            let exp = self.backoff_base.saturating_mul(1u32 << attempt.min(6));
            // Full jitter from the clock's sub-second noise (no RNG dependency needed).
            let nanos = now
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            exp.mul_f64(0.5 + f64::from(nanos % 1000) / 2000.0)
        });
        wait.min(self.max_retry_wait)
    }
}

static POLICY: OnceLock<Arc<RequestPolicy>> = OnceLock::new();

/// Installs this invocation's policy (once, from `main`).
pub fn install(policy: RequestPolicy) -> bool {
    POLICY.set(Arc::new(policy)).is_ok()
}

/// This invocation's policy (defaults when none is installed, e.g. in unit tests).
pub fn current() -> Arc<RequestPolicy> {
    POLICY
        .get_or_init(|| Arc::new(RequestPolicy::default()))
        .clone()
}

/// Resolves the timeout: `--timeout` / `SNCFR_TIMEOUT` > profile `timeout_secs` > 30 s.
/// Values outside 1–300 s are exit 2.
pub fn resolve_timeout(cli: Option<u64>, profile: Option<u64>) -> Result<Duration, SncfrError> {
    let secs = cli.or(profile).unwrap_or(DEFAULT_TIMEOUT_SECS);
    if !TIMEOUT_RANGE.contains(&secs) {
        return Err(SncfrError::InvalidArgs {
            message: format!("timeout {secs}s is out of range (1-300 seconds)"),
            remediation: Some("Pass --timeout between 1 and 300.".to_string()),
        });
    }
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_is_honored_and_clamped() {
        // CT-25 (NA-7): huge, negative, malformed, and past values never exceed the clamp.
        let p = RequestPolicy::default();
        let now = SystemTime::now();
        assert_eq!(p.retry_wait(Some("2"), 0, now), Duration::from_secs(2));
        assert_eq!(p.retry_wait(Some("99999"), 0, now), Duration::from_secs(60));
        for bad in ["-5", "abc", "Wed, 21 Oct 2015 07:28:00 GMT"] {
            let w = p.retry_wait(Some(bad), 0, now);
            assert!(
                w <= Duration::from_secs(60) && w <= Duration::from_secs(2),
                "{bad}: {w:?}"
            );
        }
        let future = chrono::Utc::now() + chrono::Duration::seconds(10);
        let w = p.retry_wait(Some(&future.to_rfc2822()), 0, now);
        assert!(
            w > Duration::from_secs(8) && w <= Duration::from_secs(11),
            "{w:?}"
        );
    }

    #[test]
    fn retry_matrix_never_retries_posts() {
        assert_eq!(RequestKind::Read.retries_on_429(false), 3);
        assert_eq!(RequestKind::Patch.retries_on_429(true), 1);
        assert_eq!(RequestKind::Patch.retries_on_429(false), 0);
        assert_eq!(RequestKind::Post.retries_on_429(true), 0);
    }

    #[test]
    fn timeout_is_clamped_to_its_range() {
        assert_eq!(
            resolve_timeout(None, None).unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            resolve_timeout(Some(5), Some(60)).unwrap(),
            Duration::from_secs(5)
        );
        assert_eq!(
            resolve_timeout(None, Some(60)).unwrap(),
            Duration::from_secs(60)
        );
        assert_eq!(
            resolve_timeout(Some(0), None)
                .unwrap_err()
                .code()
                .exit_code(),
            2
        );
        assert!(resolve_timeout(Some(301), None).is_err());
    }

    #[tokio::test]
    async fn token_bucket_limits_bursts() {
        let p = RequestPolicy::new(Duration::from_secs(1), Some(600));
        let start = Instant::now();
        for _ in 0..600 {
            p.acquire().await;
        }
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "a full bucket allows the burst"
        );
    }
}
