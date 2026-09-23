//! SPF inbound evaluation (RFC 7208). The `ip4:` / `ip6:` / `all` mechanisms are
//! evaluated against the connecting IP; `a` / `mx` / `include:` / `redirect=` /
//! `exists:` are not resolved (a bounded, common subset). The sender domain's
//! SPF TXT record is fetched via DNS; the result is recorded as a `Received-SPF`
//! header (record-only — mail is never rejected on a failure here).

use hickory_resolver::TokioResolver;
use std::net::IpAddr;
use tokio::sync::OnceCell;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpfResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
}

impl SpfResult {
    fn as_str(self) -> &'static str {
        match self {
            SpfResult::Pass => "pass",
            SpfResult::Fail => "fail",
            SpfResult::SoftFail => "softfail",
            SpfResult::Neutral => "neutral",
            SpfResult::None => "none",
        }
    }
}

/// Evaluate an SPF record against `client_ip` (ip4/ip6/all mechanisms only).
pub(crate) fn check_spf_record(record: &str, client_ip: IpAddr) -> SpfResult {
    if !record.starts_with("v=spf1") {
        return SpfResult::None;
    }
    for mech in record.split_whitespace().skip(1) {
        let (qualifier, body) = parse_qualifier(mech);
        let matched = if let Some(cidr) = body.strip_prefix("ip4:") {
            client_ip.is_ipv4() && cidr_contains(cidr, client_ip)
        } else if let Some(cidr) = body.strip_prefix("ip6:") {
            client_ip.is_ipv6() && cidr_contains(cidr, client_ip)
        } else if body == "all" {
            true
        } else {
            // a / mx / include: / redirect= / exists: — not evaluated here.
            false
        };
        if matched {
            return qualifier_result(qualifier);
        }
    }
    SpfResult::Neutral
}

/// Find the SPF record among a domain's TXT records.
pub(crate) fn find_spf_record(txts: &[String]) -> Option<String> {
    txts.iter().find(|t| t.starts_with("v=spf1")).cloned()
}

/// A `Received-SPF` header line for the evaluated result.
pub(crate) fn received_spf_header(result: SpfResult, domain: &str, ip: IpAddr) -> String {
    format!(
        "Received-SPF: {} (domain of {domain} {} {ip})",
        result.as_str(),
        match result {
            SpfResult::Pass => "designates",
            SpfResult::Fail | SpfResult::SoftFail => "does not designate",
            _ => "for",
        }
    )
}

/// Resolve + evaluate SPF for a sender domain and connecting IP, returning the
/// result and a `Received-SPF` header. Best-effort: any DNS problem yields
/// `None` and never rejects.
pub(crate) async fn evaluate(domain: &str, ip: IpAddr) -> (SpfResult, String) {
    let result = match resolve_spf(domain).await {
        Some(record) => check_spf_record(&record, ip),
        None => SpfResult::None,
    };
    (result, received_spf_header(result, domain, ip))
}

/// The process-wide resolver (built once from system configuration).
async fn resolver() -> Option<&'static TokioResolver> {
    static RESOLVER: OnceCell<Option<TokioResolver>> = OnceCell::const_new();
    RESOLVER
        .get_or_init(|| async { TokioResolver::builder_tokio().ok().map(|b| b.build()) })
        .await
        .as_ref()
}

/// Fetch the sender domain's SPF TXT record, if any.
async fn resolve_spf(domain: &str) -> Option<String> {
    let resolver = resolver().await?;
    let lookup = resolver.txt_lookup(format!("{domain}.")).await.ok()?;
    let txts: Vec<String> = lookup
        .iter()
        .map(|txt| {
            txt.txt_data()
                .iter()
                .map(|b| String::from_utf8_lossy(b))
                .collect::<String>()
        })
        .collect();
    find_spf_record(&txts)
}

fn parse_qualifier(mech: &str) -> (char, &str) {
    match mech.as_bytes().first() {
        Some(b'+') => ('+', &mech[1..]),
        Some(b'-') => ('-', &mech[1..]),
        Some(b'~') => ('~', &mech[1..]),
        Some(b'?') => ('?', &mech[1..]),
        _ => ('+', mech),
    }
}

fn qualifier_result(qualifier: char) -> SpfResult {
    match qualifier {
        '+' => SpfResult::Pass,
        '-' => SpfResult::Fail,
        '~' => SpfResult::SoftFail,
        _ => SpfResult::Neutral,
    }
}

fn cidr_contains(cidr: &str, addr: IpAddr) -> bool {
    let Some((net, prefix)) = cidr.split_once('/') else {
        return cidr.parse::<IpAddr>().map(|ip| ip == addr).unwrap_or(false);
    };
    let Ok(prefix_len) = prefix.parse::<u32>() else {
        return false;
    };
    match (net.parse::<IpAddr>(), addr) {
        (Ok(IpAddr::V4(n)), IpAddr::V4(c)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - prefix_len)
            };
            (u32::from(n) & mask) == (u32::from(c) & mask)
        }
        (Ok(IpAddr::V6(n)), IpAddr::V6(c)) => {
            if prefix_len > 128 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u128 << (128 - prefix_len)
            };
            (u128::from(n) & mask) == (u128::from(c) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn ip4_pass_and_fail() {
        let record = "v=spf1 ip4:192.168.1.0/24 -all";
        assert_eq!(check_spf_record(record, ip("192.168.1.5")), SpfResult::Pass);
        assert_eq!(check_spf_record(record, ip("10.0.0.1")), SpfResult::Fail);
    }

    #[test]
    fn softfail_and_neutral_all() {
        assert_eq!(
            check_spf_record("v=spf1 ip4:1.2.3.4 ~all", ip("9.9.9.9")),
            SpfResult::SoftFail
        );
        assert_eq!(
            check_spf_record("v=spf1 ip4:1.2.3.4 ?all", ip("9.9.9.9")),
            SpfResult::Neutral
        );
    }

    #[test]
    fn ip6_and_bare_ip() {
        assert_eq!(
            check_spf_record("v=spf1 ip6:2001:db8::/32 -all", ip("2001:db8::1")),
            SpfResult::Pass
        );
        assert_eq!(check_spf_record("not spf", ip("1.1.1.1")), SpfResult::None);
    }

    #[test]
    fn finds_spf_and_builds_header() {
        let txts = vec!["some=other".into(), "v=spf1 -all".into()];
        assert_eq!(find_spf_record(&txts).as_deref(), Some("v=spf1 -all"));
        let h = received_spf_header(SpfResult::Pass, "example.com", ip("1.2.3.4"));
        assert!(h.starts_with("Received-SPF: pass"));
        assert!(h.contains("example.com"));
    }
}
