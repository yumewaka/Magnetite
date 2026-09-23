//! Routing & access-control decisions for the embedded reverse proxy (E3).
//!
//! All functions here are **pure** over the DB-loaded config, so vhost matching,
//! IP blocklisting, ACL evaluation and CIDR containment are unit-testable
//! without sockets. The `service` module loads the config and applies these.

use chrono::{DateTime, Utc};
use magnetite_core::domains::proxy::model::{
    AclAction, AclRule, AclScope, ForwardRule, ForwardRuleKind, IpBlock, LbStrategy, ProxyMode,
    Upstream, VirtualHost,
};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

/// Whether `ip` falls within `cidr` (`a.b.c.d/n`, v4 or v6; a bare address means
/// a /32 or /128). Mismatched families never match.
pub fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let (net_s, prefix_s) = cidr.split_once('/').unwrap_or((cidr, ""));
    let Ok(net) = net_s.trim().parse::<IpAddr>() else {
        return false;
    };
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let prefix: u32 = prefix_s.parse().unwrap_or(32).min(32);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(n) & mask) == (u32::from(a) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let prefix: u32 = prefix_s.parse().unwrap_or(128).min(128);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(n) & mask) == (u128::from(a) & mask)
        }
        _ => false,
    }
}

/// The enabled HTTP virtual host serving `host` (the `Host` header, port stripped) and
/// request `path`. Case-insensitive exact hostname match; among vhosts sharing the host,
/// the one whose `path_prefix` matches `path` and is LONGEST wins (nginx `location`
/// semantics), with an unset/empty prefix acting as the host's default route.
pub fn match_vhost<'a>(
    vhosts: &'a [VirtualHost],
    host: &str,
    path: &str,
) -> Option<&'a VirtualHost> {
    let host = host
        .split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .to_ascii_lowercase();
    vhosts
        .iter()
        .filter(|v| {
            v.enabled && v.proxy_mode == ProxyMode::Http && v.hostname.eq_ignore_ascii_case(&host)
        })
        .filter(|v| {
            v.path_prefix
                .as_deref()
                .filter(|p| !p.is_empty())
                .is_none_or(|p| path.starts_with(p))
        })
        .max_by_key(|v| v.path_prefix.as_deref().map_or(0, str::len))
}

/// The enabled TCP (L4) virtual host for a raw stream: matched by TLS SNI hostname when the
/// stream begins with a TLS ClientHello (nginx `ssl_preread` — routes several hosts on ONE
/// port), else by the `listen_port` it arrived on. Case-insensitive hostname match.
pub fn match_tcp_vhost<'a>(
    vhosts: &'a [VirtualHost],
    sni: Option<&str>,
    port: u16,
) -> Option<&'a VirtualHost> {
    if let Some(name) = sni {
        let name = name.trim().to_ascii_lowercase();
        if let Some(v) = vhosts.iter().find(|v| {
            v.enabled && v.proxy_mode == ProxyMode::Tcp && v.hostname.eq_ignore_ascii_case(&name)
        }) {
            return Some(v);
        }
    }
    vhosts
        .iter()
        .find(|v| v.enabled && v.proxy_mode == ProxyMode::Tcp && v.listen_port == port)
}

/// Extract the SNI server name from a buffered TLS ClientHello, without terminating TLS
/// (the `ssl_preread` primitive for L4 routing). Returns `None` for non-TLS bytes or a
/// ClientHello with no SNI. Fully bounds-checked over possibly-partial input.
pub fn parse_sni(buf: &[u8]) -> Option<String> {
    let be16 = |b: &[u8], i: usize| ((b[i] as usize) << 8) | b[i + 1] as usize;
    // TLS record: content_type(1)=0x16 handshake, version(2), length(2).
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_end = (5 + be16(buf, 3)).min(buf.len());
    let hs = &buf[5..rec_end];
    // Handshake: msg_type(1)=0x01 client_hello, length(3), then the body.
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let mut p = 4usize + 2 + 32; // handshake header + client_version + random
    if hs.len() < p + 1 {
        return None;
    }
    p += 1 + hs[p] as usize; // session_id
    if hs.len() < p + 2 {
        return None;
    }
    p += 2 + be16(hs, p); // cipher_suites
    if hs.len() < p + 1 {
        return None;
    }
    p += 1 + hs[p] as usize; // compression_methods
    if hs.len() < p + 2 {
        return None;
    }
    let ext_end = (p + 2 + be16(hs, p)).min(hs.len());
    p += 2;
    while p + 4 <= ext_end {
        let etype = be16(hs, p);
        let elen = be16(hs, p + 2);
        let data_start = p + 4;
        let data_end = (data_start + elen).min(hs.len());
        if etype == 0x0000 {
            // server_name extension: list_len(2), entries of name_type(1)+name_len(2)+name.
            let d = &hs[data_start..data_end];
            let mut q = 2usize;
            while q + 3 <= d.len() {
                let name_len = be16(d, q + 1);
                let name_start = q + 3;
                let name_end = (name_start + name_len).min(d.len());
                if d[q] == 0 {
                    return std::str::from_utf8(&d[name_start..name_end])
                        .ok()
                        .map(str::to_string);
                }
                q = name_end;
            }
            return None;
        }
        p = data_end;
    }
    None
}

/// Whether `ip` is on the (enabled, unexpired) IP blocklist.
pub fn is_blocked(blocks: &[IpBlock], ip: IpAddr, now: DateTime<Utc>) -> bool {
    blocks.iter().any(|b| {
        b.enabled && b.expires_at.map(|e| e > now).unwrap_or(true) && cidr_contains(&b.cidr, ip)
    })
}

/// Evaluate ACL rules for `ip` against a vhost: rules in scope (global + this
/// vhost) are checked by ascending `priority`; the first CIDR match decides.
/// Default when nothing matches is Allow.
pub fn acl_decision(rules: &[AclRule], ip: IpAddr, vhost_id: &str) -> AclAction {
    let mut applicable: Vec<&AclRule> = rules
        .iter()
        .filter(|r| r.enabled)
        .filter(|r| match r.scope {
            AclScope::Global => true,
            AclScope::Vhost => r.vhost_ref.as_deref() == Some(vhost_id),
        })
        .collect();
    applicable.sort_by_key(|r| r.priority);
    applicable
        .iter()
        .find(|r| cidr_contains(&r.cidr, ip))
        .map(|r| r.action)
        .unwrap_or(AclAction::Allow)
}

/// Evaluate the forward-proxy **source** rules for a client `ip`: enabled `Source`
/// rules by ascending `priority`, first CIDR match decides; default Allow.
pub fn forward_source_decision(rules: &[ForwardRule], ip: IpAddr) -> AclAction {
    let mut applicable: Vec<&ForwardRule> = rules
        .iter()
        .filter(|r| r.enabled && r.kind == ForwardRuleKind::Source)
        .collect();
    applicable.sort_by_key(|r| r.priority);
    applicable
        .iter()
        .find(|r| cidr_contains(&r.matcher, ip))
        .map(|r| r.action)
        .unwrap_or(AclAction::Allow)
}

/// Evaluate the forward-proxy **destination** rules for a target `host`: enabled
/// `Destination` rules by ascending `priority`, first host match decides; default
/// Allow. See [`host_matches`] for the matcher grammar.
pub fn forward_dest_decision(rules: &[ForwardRule], host: &str) -> AclAction {
    let mut applicable: Vec<&ForwardRule> = rules
        .iter()
        .filter(|r| r.enabled && r.kind == ForwardRuleKind::Destination)
        .collect();
    applicable.sort_by_key(|r| r.priority);
    applicable
        .iter()
        .find(|r| host_matches(&r.matcher, host))
        .map(|r| r.action)
        .unwrap_or(AclAction::Allow)
}

/// Whether a destination-rule `matcher` matches `host`. `*` or `.` matches any host;
/// a `.example.com` matcher matches `example.com` and any subdomain; otherwise the
/// match is a case-insensitive exact hostname.
pub fn host_matches(matcher: &str, host: &str) -> bool {
    let m = matcher.trim().to_ascii_lowercase();
    let h = host.trim().to_ascii_lowercase();
    if m == "*" || m == "." {
        return true;
    }
    match m.strip_prefix('.') {
        Some(dom) => h == dom || h.ends_with(&format!(".{dom}")),
        None => h == m,
    }
}

fn hash_ip(ip: IpAddr) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    ip.hash(&mut hasher);
    hasher.finish()
}

/// Select an upstream per the vhost's load-balancing strategy:
/// - `RoundRobin`: `rr_counter % len` (caller advances the counter),
/// - `IpHash`: stable by client IP,
/// - `LeastConn`: the upstream with the fewest in-flight requests (via
///   `inflight`), ties broken by order.
pub fn select_upstream<F: Fn(&Upstream) -> usize>(
    upstreams: &[Upstream],
    strategy: LbStrategy,
    client_ip: IpAddr,
    rr_counter: usize,
    inflight: F,
) -> Option<&Upstream> {
    if upstreams.is_empty() {
        return None;
    }
    match strategy {
        LbStrategy::RoundRobin => Some(&upstreams[rr_counter % upstreams.len()]),
        LbStrategy::IpHash => {
            let idx = (hash_ip(client_ip) % upstreams.len() as u64) as usize;
            Some(&upstreams[idx])
        }
        LbStrategy::LeastConn => upstreams.iter().min_by_key(|u| inflight(u)),
        LbStrategy::Weighted => {
            // Weighted round-robin: step through the counter across the summed weights,
            // so each upstream is picked in proportion to its weight. A zero/absent weight
            // counts as 1 (never starved); an all-zero set falls back to plain round-robin.
            let total: usize = upstreams.iter().map(|u| u.weight.max(1) as usize).sum();
            if total == 0 {
                return Some(&upstreams[rr_counter % upstreams.len()]);
            }
            let mut pos = rr_counter % total;
            for u in upstreams {
                let w = u.weight.max(1) as usize;
                if pos < w {
                    return Some(u);
                }
                pos -= w;
            }
            upstreams.last()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use magnetite_core::domains::proxy::model::{LbStrategy, UpstreamScheme};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn vhost(hostname: &str, enabled: bool, mode: ProxyMode) -> VirtualHost {
        VirtualHost {
            id: format!("vh:{hostname}"),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            hostname: hostname.into(),
            path_prefix: None,
            listen_port: 80,
            upstream: vec![Upstream {
                host: "10.0.0.1".into(),
                port: 8080,
                weight: 1,
                scheme: UpstreamScheme::Http,
            }],
            tls_enabled: false,
            certificate_ref: None,
            force_https: false,
            proxy_mode: mode,
            lb_strategy: LbStrategy::RoundRobin,
            enabled,
        }
    }

    fn block(cidr: &str, expires: Option<DateTime<Utc>>) -> IpBlock {
        IpBlock {
            id: "b".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            cidr: cidr.into(),
            reason: None,
            order: 0,
            expires_at: expires,
            enabled: true,
        }
    }

    fn acl(
        cidr: &str,
        action: AclAction,
        scope: AclScope,
        vhost: Option<&str>,
        priority: i32,
    ) -> AclRule {
        AclRule {
            id: "a".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            cidr: cidr.into(),
            action,
            scope,
            vhost_ref: vhost.map(String::from),
            priority,
            enabled: true,
            description: None,
        }
    }

    #[test]
    fn cidr_v4_and_v6() {
        assert!(cidr_contains("192.0.2.0/24", ip("192.0.2.55")));
        assert!(!cidr_contains("192.0.2.0/24", ip("192.0.3.1")));
        assert!(cidr_contains("10.1.2.3", ip("10.1.2.3")));
        assert!(cidr_contains("2001:db8::/32", ip("2001:db8::1")));
        assert!(!cidr_contains("192.0.2.0/24", ip("2001:db8::1")));
    }

    #[test]
    fn vhost_matching() {
        let vhosts = [
            vhost("a.example.com", true, ProxyMode::Http),
            vhost("b.example.com", false, ProxyMode::Http),
            vhost("c.example.com", true, ProxyMode::Tcp),
        ];
        assert!(match_vhost(&vhosts, "A.example.com:80", "/").is_some());
        assert!(match_vhost(&vhosts, "b.example.com", "/").is_none()); // disabled
        assert!(match_vhost(&vhosts, "c.example.com", "/").is_none()); // not http
        assert!(match_vhost(&vhosts, "nope.example.com", "/").is_none());
    }

    #[test]
    fn path_prefix_longest_match_wins() {
        let mut root = vhost("app.test", true, ProxyMode::Http);
        root.path_prefix = None; // default route
        let mut api = vhost("app.test", true, ProxyMode::Http);
        api.path_prefix = Some("/api".into());
        let mut api_v2 = vhost("app.test", true, ProxyMode::Http);
        api_v2.path_prefix = Some("/api/v2".into());
        api_v2.hostname = "app.test".into();
        // Give each a distinct upstream so we can tell them apart.
        root.upstream[0].port = 1;
        api.upstream[0].port = 2;
        api_v2.upstream[0].port = 3;
        let vhosts = [root, api, api_v2];

        // Longest matching prefix wins; the default (no prefix) catches everything else.
        assert_eq!(
            match_vhost(&vhosts, "app.test", "/").unwrap().upstream[0].port,
            1
        );
        assert_eq!(
            match_vhost(&vhosts, "app.test", "/api/x").unwrap().upstream[0].port,
            2
        );
        assert_eq!(
            match_vhost(&vhosts, "app.test", "/api/v2/y")
                .unwrap()
                .upstream[0]
                .port,
            3
        );
        assert_eq!(
            match_vhost(&vhosts, "app.test", "/other").unwrap().upstream[0].port,
            1
        );
    }

    #[test]
    fn blocklist_honours_enabled_and_expiry() {
        let now = Utc::now();
        let past = now - chrono::Duration::hours(1);
        assert!(is_blocked(
            &[block("203.0.113.0/24", None)],
            ip("203.0.113.9"),
            now
        ));
        assert!(!is_blocked(
            &[block("203.0.113.0/24", Some(past))],
            ip("203.0.113.9"),
            now
        ));
        assert!(!is_blocked(
            &[block("203.0.113.0/24", None)],
            ip("198.51.100.1"),
            now
        ));
    }

    #[test]
    fn acl_priority_first_match_wins() {
        let rules = [
            acl("0.0.0.0/0", AclAction::Deny, AclScope::Global, None, 100),
            acl("192.0.2.0/24", AclAction::Allow, AclScope::Global, None, 10),
        ];
        // Lower priority number is evaluated first.
        assert_eq!(
            acl_decision(&rules, ip("192.0.2.5"), "vh"),
            AclAction::Allow
        );
        assert_eq!(acl_decision(&rules, ip("10.0.0.1"), "vh"), AclAction::Deny);
        // No rule → default allow.
        assert_eq!(acl_decision(&[], ip("10.0.0.1"), "vh"), AclAction::Allow);
    }

    fn fwd(kind: ForwardRuleKind, matcher: &str, action: AclAction, priority: i32) -> ForwardRule {
        ForwardRule {
            id: "f".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            kind,
            matcher: matcher.into(),
            action,
            priority,
            enabled: true,
            description: None,
        }
    }

    #[test]
    fn forward_source_first_match_wins() {
        let rules = [
            fwd(ForwardRuleKind::Source, "0.0.0.0/0", AclAction::Deny, 100),
            fwd(ForwardRuleKind::Source, "10.0.0.0/8", AclAction::Allow, 10),
            // A destination rule must not affect the source decision.
            fwd(ForwardRuleKind::Destination, "*", AclAction::Deny, 1),
        ];
        assert_eq!(
            forward_source_decision(&rules, ip("10.1.2.3")),
            AclAction::Allow
        );
        assert_eq!(
            forward_source_decision(&rules, ip("192.0.2.1")),
            AclAction::Deny
        );
        assert_eq!(
            forward_source_decision(&[], ip("10.1.2.3")),
            AclAction::Allow
        );
    }

    #[test]
    fn forward_dest_domain_and_catchall() {
        assert!(host_matches(".example.com", "example.com"));
        assert!(host_matches(".example.com", "a.b.example.com"));
        assert!(!host_matches(".example.com", "notexample.com"));
        assert!(host_matches("host.test", "HOST.TEST"));
        assert!(host_matches("*", "anything.net"));

        let rules = [
            fwd(ForwardRuleKind::Destination, "*", AclAction::Deny, 100),
            fwd(
                ForwardRuleKind::Destination,
                ".example.com",
                AclAction::Allow,
                10,
            ),
        ];
        assert_eq!(
            forward_dest_decision(&rules, "www.example.com"),
            AclAction::Allow
        );
        assert_eq!(forward_dest_decision(&rules, "evil.test"), AclAction::Deny);
        assert_eq!(forward_dest_decision(&[], "anything"), AclAction::Allow);
    }

    #[test]
    fn lb_strategies() {
        let ups = vec![
            Upstream {
                host: "a".into(),
                port: 1,
                weight: 1,
                scheme: UpstreamScheme::Http,
            },
            Upstream {
                host: "b".into(),
                port: 2,
                weight: 1,
                scheme: UpstreamScheme::Http,
            },
        ];
        let none = |_: &Upstream| 0;
        // Round-robin advances with the counter.
        assert_eq!(
            select_upstream(&ups, LbStrategy::RoundRobin, ip("10.0.0.1"), 0, none)
                .unwrap()
                .host,
            "a"
        );
        assert_eq!(
            select_upstream(&ups, LbStrategy::RoundRobin, ip("10.0.0.1"), 1, none)
                .unwrap()
                .host,
            "b"
        );
        // IP-hash is stable for the same client.
        let h1 = select_upstream(&ups, LbStrategy::IpHash, ip("10.0.0.5"), 0, none)
            .unwrap()
            .host
            .clone();
        let h2 = select_upstream(&ups, LbStrategy::IpHash, ip("10.0.0.5"), 9, none)
            .unwrap()
            .host
            .clone();
        assert_eq!(h1, h2);
        // Least-conn picks the upstream with fewest in-flight ("b" here).
        let counts = |u: &Upstream| if u.host == "a" { 5 } else { 1 };
        assert_eq!(
            select_upstream(&ups, LbStrategy::LeastConn, ip("10.0.0.1"), 0, counts)
                .unwrap()
                .host,
            "b"
        );
        assert!(select_upstream(&[], LbStrategy::RoundRobin, ip("10.0.0.1"), 0, none).is_none());
    }

    #[test]
    fn tcp_vhost_matches_by_sni_then_port() {
        let mut d1 = vhost("desktop1.test", true, ProxyMode::Tcp);
        d1.listen_port = 3389;
        let mut d2 = vhost("desktop2.test", true, ProxyMode::Tcp);
        d2.listen_port = 3389;
        let mut pg = vhost("pg.test", true, ProxyMode::Tcp);
        pg.listen_port = 5432;
        let vhosts = [d1, d2, pg];
        // SNI disambiguates two hosts sharing port 3389 (RDP via ssl_preread).
        assert_eq!(
            match_tcp_vhost(&vhosts, Some("desktop2.test"), 3389)
                .unwrap()
                .hostname,
            "desktop2.test"
        );
        // No SNI → match by the listen port.
        assert_eq!(
            match_tcp_vhost(&vhosts, None, 5432).unwrap().hostname,
            "pg.test"
        );
        // An HTTP vhost is never matched as an L4/TCP stream.
        let http = [vhost("web.test", true, ProxyMode::Http)];
        assert!(match_tcp_vhost(&http, Some("web.test"), 80).is_none());
        assert!(match_tcp_vhost(&vhosts, Some("nope.test"), 9999).is_none());
    }

    #[test]
    fn sni_preread_extracts_hostname() {
        let name = b"stream.test";
        let mut sni = Vec::new();
        sni.extend_from_slice(&((1 + 2 + name.len()) as u16).to_be_bytes()); // list length
        sni.push(0); // name_type = host_name
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        let mut exts = Vec::new();
        exts.extend_from_slice(&0u16.to_be_bytes()); // extension type server_name
        exts.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni);
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // cipher suites
        body.extend_from_slice(&[0x01, 0x00]); // compression methods
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![0x01]; // client_hello
        let bl = body.len();
        hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        assert_eq!(parse_sni(&rec).as_deref(), Some("stream.test"));
        assert_eq!(parse_sni(b"not a tls hello"), None);
        assert_eq!(parse_sni(&[]), None);
        // A truncated ClientHello must never panic (bounds-checked).
        let _ = parse_sni(&rec[..rec.len() / 2]);
    }

    #[test]
    fn weighted_lb_picks_in_proportion() {
        // a:weight 3, b:weight 1 → over 4 ticks, a is chosen 3×, b once.
        let ups = vec![
            Upstream {
                host: "a".into(),
                port: 1,
                weight: 3,
                scheme: UpstreamScheme::Http,
            },
            Upstream {
                host: "b".into(),
                port: 2,
                weight: 1,
                scheme: UpstreamScheme::Http,
            },
        ];
        let none = |_: &Upstream| 0;
        let picks: Vec<&str> = (0..4)
            .map(|i| {
                select_upstream(&ups, LbStrategy::Weighted, ip("10.0.0.1"), i, none)
                    .unwrap()
                    .host
                    .as_str()
            })
            .collect();
        assert_eq!(picks.iter().filter(|h| **h == "a").count(), 3);
        assert_eq!(picks.iter().filter(|h| **h == "b").count(), 1);
    }
}
