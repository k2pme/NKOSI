use sha2::{Sha256, Digest};
use tracing::warn;

use nkosi_common::types::IndicatorType;

pub const DEFAULT_MIN_FEED_BYTES: usize = 50;

pub fn validate_min_size(text: &str, min_bytes: usize, source: &str) -> bool {
    if text.len() < min_bytes {
        warn!(
            "{} response too short ({} bytes, minimum {}), possible tampering or empty feed",
            source,
            text.len(),
            min_bytes
        );
        false
    } else {
        true
    }
}

pub fn compute_audit_hash(text: &str) -> String {
    let full = format!("{:x}", Sha256::digest(text.as_bytes()));
    full[..16].to_string()
}

pub fn validate_indicator_value(ioc_type: &IndicatorType, value: &str) -> bool {
    match ioc_type {
        IndicatorType::Sha256 => {
            value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
        }
        IndicatorType::Sha1 => {
            value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit())
        }
        IndicatorType::Md5 => {
            value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit())
        }
        IndicatorType::Ip => {
            let ip_part = match value.rfind(':') {
                Some(pos) => &value[..pos],
                None => value,
            };
            ip_part.split('.').count() == 4
                && ip_part.split('.').all(|octet| octet.parse::<u8>().is_ok())
        }
        IndicatorType::Domain => {
            !value.is_empty() && !value.contains(' ') && value.contains('.') && value.len() <= 253
        }
        IndicatorType::Url => value.starts_with("http://") || value.starts_with("https://"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_min_size_pass() {
        assert!(validate_min_size(&"x".repeat(100), 50, "Test"));
    }

    #[test]
    fn validate_min_size_fail() {
        assert!(!validate_min_size("short", 50, "Test"));
    }

    #[test]
    fn validate_min_size_boundary() {
        assert!(validate_min_size(&"x".repeat(50), 50, "Test"));
    }

    #[test]
    fn compute_audit_hash_consistent() {
        let h1 = compute_audit_hash("hello world");
        let h2 = compute_audit_hash("hello world");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn compute_audit_hash_different() {
        let h1 = compute_audit_hash("input_a");
        let h2 = compute_audit_hash("input_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn sha256_valid() {
        assert!(validate_indicator_value(&IndicatorType::Sha256, &"a".repeat(64)));
    }

    #[test]
    fn sha256_invalid_length() {
        assert!(!validate_indicator_value(&IndicatorType::Sha256, "abc123"));
    }

    #[test]
    fn sha256_invalid_chars() {
        assert!(!validate_indicator_value(&IndicatorType::Sha256, &"g".repeat(64)));
    }

    #[test]
    fn md5_valid() {
        assert!(validate_indicator_value(&IndicatorType::Md5, &"a".repeat(32)));
    }

    #[test]
    fn md5_invalid() {
        assert!(!validate_indicator_value(&IndicatorType::Md5, "short"));
    }

    #[test]
    fn sha1_valid() {
        assert!(validate_indicator_value(&IndicatorType::Sha1, &"a".repeat(40)));
    }

    #[test]
    fn ip_port_valid() {
        assert!(validate_indicator_value(&IndicatorType::Ip, "1.2.3.4:443"));
        assert!(validate_indicator_value(&IndicatorType::Ip, "10.0.0.1:8080"));
    }

    #[test]
    fn ip_port_invalid() {
        assert!(!validate_indicator_value(&IndicatorType::Ip, "not-an-ip"));
        assert!(!validate_indicator_value(&IndicatorType::Ip, "999.999.999.999:80"));
    }

    #[test]
    fn domain_valid() {
        assert!(validate_indicator_value(&IndicatorType::Domain, "evil.com"));
        assert!(validate_indicator_value(&IndicatorType::Domain, "sub.evil.com"));
    }

    #[test]
    fn domain_invalid() {
        assert!(!validate_indicator_value(&IndicatorType::Domain, ""));
        assert!(!validate_indicator_value(&IndicatorType::Domain, "no-dot"));
    }

    #[test]
    fn url_valid() {
        assert!(validate_indicator_value(&IndicatorType::Url, "http://evil.com/payload"));
        assert!(validate_indicator_value(&IndicatorType::Url, "https://evil.com/payload"));
    }

    #[test]
    fn url_invalid() {
        assert!(!validate_indicator_value(&IndicatorType::Url, "ftp://evil.com"));
        assert!(!validate_indicator_value(&IndicatorType::Url, "not-a-url"));
    }
}
