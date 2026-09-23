//! Proxy write-time validation (screen_proxy §5). Pure, shared by form and
//! repository.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub const MSG_HOSTNAME: &str = "有効なホスト名を入力してください。";
pub const MSG_PORT: &str = "1〜65535 の数値を入力してください。";
pub const MSG_CERT_NAME: &str = "証明書名を入力してください。";
pub const MSG_PEM: &str = "有効な PEM を入力してください。";
pub const MSG_CIDR: &str = "有効な CIDR を入力してください。";
pub const MSG_ACL_HOST: &str = "対象ホスト名を入力してください。";
pub const MSG_CERT_REQUIRED: &str = "TLS 有効時は証明書を選択してください。";

/// Whether `name` is a syntactically valid FQDN (>= 2 dot-separated labels).
pub fn is_hostname(name: &str) -> bool {
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

/// Whether `value` is a valid IPv4/IPv6 CIDR (`addr/prefix`).
pub fn is_cidr(value: &str) -> bool {
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

fn is_pem(value: &str) -> bool {
    value.contains("-----BEGIN") && value.contains("-----END")
}

/// Validate a virtual host's fields.
pub fn check_vhost(
    hostname: &str,
    listen_port: u16,
    tls_enabled: bool,
    certificate_ref: Option<&str>,
) -> Result<(), &'static str> {
    if !is_hostname(hostname) {
        return Err(MSG_HOSTNAME);
    }
    if listen_port == 0 {
        return Err(MSG_PORT);
    }
    if tls_enabled && certificate_ref.map(|c| c.trim().is_empty()).unwrap_or(true) {
        return Err(MSG_CERT_REQUIRED);
    }
    Ok(())
}

/// Validate a certificate's create fields.
pub fn check_certificate(name: &str, cert_pem: &str, chain_pem: &str) -> Result<(), &'static str> {
    if name.trim().is_empty() || name.trim().chars().count() > 100 {
        return Err(MSG_CERT_NAME);
    }
    if !is_pem(cert_pem) {
        return Err(MSG_PEM);
    }
    if !chain_pem.trim().is_empty() && !is_pem(chain_pem) {
        return Err(MSG_PEM);
    }
    Ok(())
}

/// Validate an ACL rule's fields.
pub fn check_acl(
    cidr: &str,
    scope_vhost: bool,
    vhost_ref: Option<&str>,
) -> Result<(), &'static str> {
    if !is_cidr(cidr) {
        return Err(MSG_CIDR);
    }
    if scope_vhost && vhost_ref.map(|v| v.trim().is_empty()).unwrap_or(true) {
        return Err(MSG_ACL_HOST);
    }
    Ok(())
}

pub const MSG_FWD_MATCHER: &str =
    "有効なホスト名またはドメイン（例: .example.com, *）を入力してください。";

/// Validate a forward-proxy rule's matcher. A `Source` rule must be a CIDR; a
/// `Destination` rule must be `*`/`.` (any), a `.domain` suffix, or a hostname made
/// of alnum/`-`/`.` labels.
pub fn check_forward_rule(is_source: bool, matcher: &str) -> Result<(), &'static str> {
    let m = matcher.trim();
    if is_source {
        return if is_cidr(m) { Ok(()) } else { Err(MSG_CIDR) };
    }
    if m == "*" || m == "." {
        return Ok(());
    }
    let host = m.strip_prefix('.').unwrap_or(m);
    let ok = !host.is_empty()
        && host
            .split('.')
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    if ok {
        Ok(())
    } else {
        Err(MSG_FWD_MATCHER)
    }
}

/// Validate an IP block's CIDR.
pub fn check_ip_block(cidr: &str) -> Result<(), &'static str> {
    if is_cidr(cidr) {
        Ok(())
    } else {
        Err(MSG_CIDR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_and_hostname() {
        assert!(is_cidr("10.0.0.0/8"));
        assert!(is_cidr("2001:db8::/32"));
        assert!(!is_cidr("10.0.0.0"));
        assert!(!is_cidr("10.0.0.0/40"));
        assert!(is_hostname("a.example.com"));
        assert!(!is_hostname("localhost"));
    }

    #[test]
    fn vhost_tls_requires_cert() {
        assert!(check_vhost("a.example.com", 443, false, None).is_ok());
        assert_eq!(
            check_vhost("a.example.com", 443, true, None),
            Err(MSG_CERT_REQUIRED)
        );
        assert!(check_vhost("a.example.com", 443, true, Some("star")).is_ok());
    }

    #[test]
    fn certificate_pem_shape() {
        let pem = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----";
        assert!(check_certificate("web", pem, "").is_ok());
        assert_eq!(check_certificate("web", "nope", ""), Err(MSG_PEM));
        assert_eq!(check_certificate("", pem, ""), Err(MSG_CERT_NAME));
    }

    #[test]
    fn acl_vhost_scope_requires_host() {
        assert!(check_acl("10.0.0.0/8", false, None).is_ok());
        assert_eq!(check_acl("10.0.0.0/8", true, None), Err(MSG_ACL_HOST));
        assert!(check_acl("10.0.0.0/8", true, Some("a.example.com")).is_ok());
    }
}
