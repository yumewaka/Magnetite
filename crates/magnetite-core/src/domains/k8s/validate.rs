//! K8s write-time validation (screen_k8s §5). Pure, shared by form and
//! repository.

use super::model::AlertConditionKind;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub const MSG_HOSTNAME: &str = "有効なホスト名を入力してください。";
pub const MSG_IP: &str = "有効な IP アドレスを入力してください。";
pub const MSG_PORT: &str = "1〜65535 の数値を入力してください。";
pub const MSG_CREDENTIAL: &str = "認証情報を入力してください。";
pub const MSG_THRESHOLD: &str = "有効な閾値を入力してください。";
pub const MSG_YAML: &str = "YAML の構文が不正です。";
pub const MSG_CIDR: &str = "有効な CIDR を入力してください。";
pub const MSG_NAME: &str = "名称を正しく入力してください。";

fn is_ip(value: &str) -> bool {
    Ipv4Addr::from_str(value).is_ok() || Ipv6Addr::from_str(value).is_ok()
}

fn is_hostname(name: &str) -> bool {
    let name = name.trim();
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

fn is_cidr(value: &str) -> bool {
    let Some((addr, prefix)) = value.trim().split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    if Ipv4Addr::from_str(addr).is_ok() {
        prefix <= 32
    } else if Ipv6Addr::from_str(addr).is_ok() {
        prefix <= 128
    } else {
        false
    }
}

/// Validate a host's create fields.
pub fn check_host(
    hostname: &str,
    address: &str,
    ssh_port: u16,
    credential: &str,
) -> Result<(), &'static str> {
    if !is_hostname(hostname) {
        return Err(MSG_HOSTNAME);
    }
    if !is_ip(address) {
        return Err(MSG_IP);
    }
    if ssh_port == 0 {
        return Err(MSG_PORT);
    }
    if credential.trim().is_empty() {
        return Err(MSG_CREDENTIAL);
    }
    Ok(())
}

/// Validate a cluster's fields.
pub fn check_cluster(name: &str, pod_cidr: &str, service_cidr: &str) -> Result<(), &'static str> {
    if name.trim().is_empty() {
        return Err(MSG_NAME);
    }
    if !is_cidr(pod_cidr) || !is_cidr(service_cidr) {
        return Err(MSG_CIDR);
    }
    Ok(())
}

/// Validate an alert rule's threshold for its condition.
pub fn check_alert_rule(
    name: &str,
    condition: AlertConditionKind,
    threshold: f64,
) -> Result<(), &'static str> {
    if name.trim().is_empty() {
        return Err(MSG_NAME);
    }
    let ok = match condition {
        AlertConditionKind::Cpu | AlertConditionKind::Memory => (0.0..=100.0).contains(&threshold),
        AlertConditionKind::PodRestart => threshold >= 1.0,
        AlertConditionKind::NodeNotReady => threshold >= 0.0,
    };
    if ok {
        Ok(())
    } else {
        Err(MSG_THRESHOLD)
    }
}

/// Validate a template's YAML (light structural check).
pub fn check_template(name: &str, manifest_yaml: &str) -> Result<(), &'static str> {
    if name.trim().is_empty() {
        return Err(MSG_NAME);
    }
    // Minimal check: non-empty and contains a `kind:` line (real YAML parsing
    // is a later concern).
    if manifest_yaml.trim().is_empty() || !manifest_yaml.contains("kind:") {
        return Err(MSG_YAML);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_validation() {
        assert!(check_host("node1", "10.0.0.1", 22, "secret").is_ok());
        assert_eq!(check_host("node1", "nope", 22, "x"), Err(MSG_IP));
        assert_eq!(check_host("node1", "10.0.0.1", 22, ""), Err(MSG_CREDENTIAL));
    }

    #[test]
    fn cluster_cidr() {
        assert!(check_cluster("c1", "10.244.0.0/16", "10.96.0.0/12").is_ok());
        assert_eq!(check_cluster("c1", "bad", "10.96.0.0/12"), Err(MSG_CIDR));
    }

    #[test]
    fn alert_threshold_by_condition() {
        assert!(check_alert_rule("r", AlertConditionKind::Cpu, 80.0).is_ok());
        assert_eq!(
            check_alert_rule("r", AlertConditionKind::Cpu, 150.0),
            Err(MSG_THRESHOLD)
        );
        assert!(check_alert_rule("r", AlertConditionKind::PodRestart, 3.0).is_ok());
        assert_eq!(
            check_alert_rule("r", AlertConditionKind::PodRestart, 0.0),
            Err(MSG_THRESHOLD)
        );
    }

    #[test]
    fn template_yaml_shape() {
        assert!(check_template("t", "apiVersion: v1\nkind: ConfigMap").is_ok());
        assert_eq!(check_template("t", "no kind here"), Err(MSG_YAML));
    }
}
