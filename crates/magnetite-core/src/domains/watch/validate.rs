//! Watch write-time validation (screen_watch §3/§5). Pure, shared by form and
//! repository.

use chrono::{DateTime, Utc};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub const MSG_NAME: &str = "名称を正しく入力してください。";
pub const MSG_IP: &str = "有効な IP アドレスを入力してください。";
pub const MSG_HOSTNAME: &str = "有効なホスト名を入力してください。";
pub const MSG_TAG: &str = "タグは30文字以内で入力してください。";
pub const MSG_METRIC: &str = "いずれかを選択してください。";
pub const MSG_THRESHOLD: &str = "0〜100 の数値を入力してください。";
pub const MSG_THRESHOLD_ORDER: &str = "危険閾値は警告閾値以上にしてください。";
pub const MSG_END_AFTER_START: &str = "終了日時は開始日時より後にしてください。";

fn is_ip(value: &str) -> bool {
    Ipv4Addr::from_str(value).is_ok() || Ipv6Addr::from_str(value).is_ok()
}

fn is_name(value: &str) -> bool {
    (1..=100).contains(&value.trim().chars().count())
}

/// Whether a metric is a percentage metric (0..=100 range).
fn is_percent_metric(metric: &str) -> bool {
    matches!(metric, "cpu_percent" | "memory_percent" | "disk_percent")
}

/// Validate a monitored host's fields.
pub fn check_host(name: &str, ip_address: &str, tags: &[String]) -> Result<(), &'static str> {
    if !is_name(name) {
        return Err(MSG_NAME);
    }
    if !is_ip(ip_address) {
        return Err(MSG_IP);
    }
    if tags.iter().any(|t| t.chars().count() > 30) {
        return Err(MSG_TAG);
    }
    Ok(())
}

/// Validate a monitor rule's thresholds (screen_watch §3.3).
pub fn check_rule(
    name: &str,
    metric: &str,
    warning: Option<f64>,
    critical: Option<f64>,
) -> Result<(), &'static str> {
    if !is_name(name) {
        return Err(MSG_NAME);
    }
    if metric.trim().is_empty() {
        return Err(MSG_METRIC);
    }
    if warning.is_none() && critical.is_none() {
        return Err(MSG_THRESHOLD);
    }
    if is_percent_metric(metric) {
        for t in [warning, critical].into_iter().flatten() {
            if !(0.0..=100.0).contains(&t) {
                return Err(MSG_THRESHOLD);
            }
        }
    }
    if let (Some(w), Some(c)) = (warning, critical) {
        if c < w {
            return Err(MSG_THRESHOLD_ORDER);
        }
    }
    Ok(())
}

/// Validate a maintenance window's fields.
pub fn check_maintenance(
    name: &str,
    starts_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
) -> Result<(), &'static str> {
    if !is_name(name) {
        return Err(MSG_NAME);
    }
    if ends_at <= starts_at {
        return Err(MSG_END_AFTER_START);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_validation() {
        assert!(check_host("web1", "10.0.0.1", &["prod".into()]).is_ok());
        assert_eq!(check_host("web1", "nope", &[]), Err(MSG_IP));
        assert_eq!(
            check_host("web1", "10.0.0.1", &["x".repeat(31)]),
            Err(MSG_TAG)
        );
    }

    #[test]
    fn rule_thresholds() {
        assert!(check_rule("cpu", "cpu_percent", Some(80.0), Some(95.0)).is_ok());
        assert_eq!(
            check_rule("cpu", "cpu_percent", None, None),
            Err(MSG_THRESHOLD)
        );
        assert_eq!(
            check_rule("cpu", "cpu_percent", Some(80.0), Some(50.0)),
            Err(MSG_THRESHOLD_ORDER)
        );
        assert_eq!(
            check_rule("cpu", "cpu_percent", Some(150.0), None),
            Err(MSG_THRESHOLD)
        );
        // Non-percent metric skips the 0..100 clamp.
        assert!(check_rule("rx", "net_rx", Some(1000.0), None).is_ok());
    }

    #[test]
    fn maintenance_window_order() {
        let now = Utc::now();
        assert!(check_maintenance("m", now, now + chrono::Duration::hours(1)).is_ok());
        assert_eq!(check_maintenance("m", now, now), Err(MSG_END_AFTER_START));
    }
}
