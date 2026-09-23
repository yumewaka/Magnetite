//! Mail write-time validation (screen_mail §5). Pure, shared by form and
//! repository.

use super::model::ProtocolConfig;
use std::collections::BTreeMap;

pub const MSG_NAME: &str = "名称を正しく入力してください。";
pub const MSG_SELECT_DOMAIN: &str = "いずれかを選択してください。";
pub const MSG_PASSWORD: &str = "パスワードを正しく入力してください。";
pub const MSG_QUOTA: &str = "0 以上の数値を入力してください。";
pub const MSG_MAX_USERS: &str = "1 以上の数値を入力してください。";
pub const MSG_DEST_REQUIRED: &str = "宛先を 1 件以上入力してください。";
pub const MSG_DEST_MISSING: &str = "宛先のアカウントが存在しません。";
pub const MSG_MEMBER_EMAIL: &str = "宛先を正しく入力してください。";
pub const MSG_PORT_RANGE: &str = "1〜65535 の数値を入力してください。";
pub const MSG_PORT_DUP: &str = "ポートが他プロトコルと重複しています。";
pub const MSG_HOSTNAME: &str = "ホスト名を正しく入力してください。";
pub const MSG_MSG_SIZE: &str = "1 以上の数値を入力してください。";
pub const MSG_ACME_EMAIL: &str = "メールアドレスを正しく入力してください。";

/// Minimal email shape check: `local@domain.tld`.
pub fn is_email(value: &str) -> bool {
    match value.trim().split_once('@') {
        Some((local, domain)) => {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
        }
        None => false,
    }
}

/// Whether `name` is a syntactically valid FQDN (>= 2 dot-separated labels).
pub fn is_fqdn(name: &str) -> bool {
    let name = name.trim().trim_end_matches('.');
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// Valid local part: non-empty, RFC-ish character set.
pub fn is_local_part(value: &str) -> bool {
    let v = value.trim();
    !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
}

/// Validate a mail user's create fields.
pub fn check_user(
    local_part: &str,
    domain: &str,
    quota_mb: Option<u64>,
) -> Result<(), &'static str> {
    if !is_local_part(local_part) {
        return Err(MSG_NAME);
    }
    if domain.trim().is_empty() {
        return Err(MSG_SELECT_DOMAIN);
    }
    // quota is a u64 already so a negative is impossible; nothing to reject here.
    let _ = quota_mb;
    Ok(())
}

/// Validate a mail domain's create/update fields.
pub fn check_domain(name: &str, max_users: Option<u32>) -> Result<(), &'static str> {
    if !is_fqdn(name) {
        return Err(MSG_NAME);
    }
    if let Some(max) = max_users {
        if max == 0 {
            return Err(MSG_MAX_USERS);
        }
    }
    Ok(())
}

/// Validate an alias's source + destination shape (existence is checked in the
/// repository).
pub fn check_alias(source: &str, destinations: &[String]) -> Result<(), &'static str> {
    if !is_email(source) {
        return Err(MSG_NAME);
    }
    let dests: Vec<&String> = destinations
        .iter()
        .filter(|d| !d.trim().is_empty())
        .collect();
    if dests.is_empty() {
        return Err(MSG_DEST_REQUIRED);
    }
    if dests.iter().any(|d| !is_email(d)) {
        return Err(MSG_DEST_REQUIRED);
    }
    Ok(())
}

/// Validate a mailing list's create fields.
pub fn check_list(address: &str, name: &str, owner: &str) -> Result<(), &'static str> {
    if !is_email(address) || !is_email(owner) {
        return Err(MSG_NAME);
    }
    if name.trim().is_empty() {
        return Err(MSG_NAME);
    }
    Ok(())
}

/// Validate the protocol set: every port in range and unique.
pub fn check_protocols(protocols: &BTreeMap<String, ProtocolConfig>) -> Result<(), &'static str> {
    let mut seen = std::collections::BTreeSet::new();
    for cfg in protocols.values() {
        if cfg.port == 0 {
            return Err(MSG_PORT_RANGE);
        }
        if !seen.insert(cfg.port) {
            return Err(MSG_PORT_DUP);
        }
    }
    Ok(())
}

/// Validate the mail server settings.
pub fn check_server_config(
    hostname: &str,
    max_message_size: u64,
    acme_enabled: bool,
    acme_email: Option<&str>,
) -> Result<(), &'static str> {
    if !is_fqdn(hostname) {
        return Err(MSG_HOSTNAME);
    }
    if max_message_size == 0 {
        return Err(MSG_MSG_SIZE);
    }
    if acme_enabled {
        match acme_email {
            Some(e) if is_email(e) => {}
            _ => return Err(MSG_ACME_EMAIL),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_and_fqdn() {
        assert!(is_email("alice@example.com"));
        assert!(!is_email("nope"));
        assert!(is_fqdn("example.com"));
        assert!(!is_fqdn("localhost"));
    }

    #[test]
    fn alias_requires_valid_destinations() {
        assert!(check_alias("a@x.com", &["b@x.com".into()]).is_ok());
        assert_eq!(check_alias("a@x.com", &[]), Err(MSG_DEST_REQUIRED));
        assert_eq!(check_alias("bad", &["b@x.com".into()]), Err(MSG_NAME));
    }

    #[test]
    fn protocol_port_uniqueness() {
        let mut p = BTreeMap::new();
        p.insert(
            "smtp".to_string(),
            ProtocolConfig {
                enabled: true,
                port: 25,
            },
        );
        p.insert(
            "imap".to_string(),
            ProtocolConfig {
                enabled: true,
                port: 143,
            },
        );
        assert!(check_protocols(&p).is_ok());
        p.insert(
            "dup".to_string(),
            ProtocolConfig {
                enabled: true,
                port: 25,
            },
        );
        assert_eq!(check_protocols(&p), Err(MSG_PORT_DUP));
    }

    #[test]
    fn server_config_acme_requires_email() {
        assert!(check_server_config("mail.example.com", 100, false, None).is_ok());
        assert_eq!(
            check_server_config("mail.example.com", 100, true, None),
            Err(MSG_ACME_EMAIL)
        );
        assert!(check_server_config("mail.example.com", 100, true, Some("a@x.com")).is_ok());
        assert_eq!(
            check_server_config("bad", 100, false, None),
            Err(MSG_HOSTNAME)
        );
    }
}
