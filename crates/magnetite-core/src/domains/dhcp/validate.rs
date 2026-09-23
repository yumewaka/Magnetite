//! DHCP write-time validation (08_dhcp_logic §5). Pure, shared by form and
//! repository; confirmed messages come from screen_dhcp §5.

use super::model::Pool;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub const MSG_NAME: &str = "名称を正しく入力してください。";
pub const MSG_IP: &str = "有効な IP アドレスを入力してください。";
pub const MSG_RANGE_ORDER: &str = "範囲の開始 IP は終了 IP 以下にしてください。";
pub const MSG_OVERLAP: &str = "指定範囲は既存プールと重複しています。";
pub const MSG_CIDR: &str = "有効なサブネット（CIDR）を入力してください。";
pub const MSG_LEASE_SECS: &str = "正の整数（秒）を入力してください。";
pub const MSG_NO_RANGE: &str = "IPv4 または IPv6 の配布範囲を指定してください。";
pub const MSG_MAC: &str = "有効な MAC アドレスを入力してください。";
pub const MSG_RESERVATION_RANGE: &str = "指定範囲は既存プールと重複しています。";

/// Normalize a MAC address to `aa:bb:cc:dd:ee:ff`, or `None` if malformed.
/// Accepts `:`, `-` or `.` separators and mixed case.
pub fn normalize_mac(mac: &str) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.'))
        .collect();
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let lower = hex.to_ascii_lowercase();
    let parts: Vec<String> = (0..6)
        .map(|i| lower[i * 2..i * 2 + 2].to_string())
        .collect();
    Some(parts.join(":"))
}

fn is_ip(value: &str) -> bool {
    Ipv4Addr::from_str(value).is_ok() || Ipv6Addr::from_str(value).is_ok()
}

/// Validate a CIDR like `192.168.1.0/24` or `2001:db8::/64`.
fn is_cidr(value: &str) -> bool {
    let Some((addr, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    if let Ok(_v4) = Ipv4Addr::from_str(addr) {
        prefix <= 32
    } else if Ipv6Addr::from_str(addr).is_ok() {
        prefix <= 128
    } else {
        false
    }
}

/// The IPv4 distribution interval `[start, end]` as `u32`, if both ends parse.
pub fn v4_range(pool: &Pool) -> Option<(u32, u32)> {
    let start = pool
        .range_start_v4
        .as_deref()
        .and_then(|s| Ipv4Addr::from_str(s).ok())?;
    let end = pool
        .range_end_v4
        .as_deref()
        .and_then(|s| Ipv4Addr::from_str(s).ok())?;
    Some((u32::from(start), u32::from(end)))
}

/// The IPv6 distribution interval `[start, end]` as `u128`, if both ends parse.
pub fn v6_range(pool: &Pool) -> Option<(u128, u128)> {
    let start = pool
        .range_start_v6
        .as_deref()
        .and_then(|s| Ipv6Addr::from_str(s).ok())?;
    let end = pool
        .range_end_v6
        .as_deref()
        .and_then(|s| Ipv6Addr::from_str(s).ok())?;
    Some((u128::from(start), u128::from(end)))
}

/// Whether two closed integer intervals intersect.
pub fn intervals_overlap<T: Ord>(a: (T, T), b: (T, T)) -> bool {
    a.0 <= b.1 && b.0 <= a.1
}

/// Validate a pool's own fields (08_dhcp_logic §5; range-overlap against other
/// pools is enforced by the repository).
pub fn check_pool(pool: &Pool) -> Result<(), &'static str> {
    if pool.name.trim().is_empty() {
        return Err(MSG_NAME);
    }
    if let Some(cidr) = pool.subnet_v4.as_deref().filter(|s| !s.is_empty()) {
        if !is_cidr(cidr) {
            return Err(MSG_CIDR);
        }
    }
    if let Some(cidr) = pool.subnet_v6.as_deref().filter(|s| !s.is_empty()) {
        if !is_cidr(cidr) {
            return Err(MSG_CIDR);
        }
    }
    check_family(&pool.range_start_v4, &pool.range_end_v4)?;
    check_family(&pool.range_start_v6, &pool.range_end_v6)?;
    if v4_range(pool).is_none() && v6_range(pool).is_none() {
        return Err(MSG_NO_RANGE);
    }
    if let Some(gw) = pool.gateway.as_deref().filter(|s| !s.is_empty()) {
        if !is_ip(gw) {
            return Err(MSG_IP);
        }
    }
    if pool.dns_servers.iter().any(|s| !s.is_empty() && !is_ip(s)) {
        return Err(MSG_IP);
    }
    if let Some(secs) = pool.lease_duration_secs {
        if secs == 0 {
            return Err(MSG_LEASE_SECS);
        }
    }
    Ok(())
}

/// When either range end is present, both must be valid IPs of the same family
/// with start ≤ end.
fn check_family(start: &Option<String>, end: &Option<String>) -> Result<(), &'static str> {
    let start = start.as_deref().filter(|s| !s.is_empty());
    let end = end.as_deref().filter(|s| !s.is_empty());
    match (start, end) {
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => Err(MSG_IP),
        (Some(s), Some(e)) => {
            if let (Ok(s4), Ok(e4)) = (Ipv4Addr::from_str(s), Ipv4Addr::from_str(e)) {
                if u32::from(s4) <= u32::from(e4) {
                    Ok(())
                } else {
                    Err(MSG_RANGE_ORDER)
                }
            } else if let (Ok(s6), Ok(e6)) = (Ipv6Addr::from_str(s), Ipv6Addr::from_str(e)) {
                if u128::from(s6) <= u128::from(e6) {
                    Ok(())
                } else {
                    Err(MSG_RANGE_ORDER)
                }
            } else {
                Err(MSG_IP)
            }
        }
    }
}

/// Validate reservation MAC + IP field formats (uniqueness/in-range checks are
/// done in the repository against the pool).
pub fn check_reservation_fields(mac: &str, ip: &str) -> Result<(), &'static str> {
    if normalize_mac(mac).is_none() {
        return Err(MSG_MAC);
    }
    if !is_ip(ip) {
        return Err(MSG_IP);
    }
    Ok(())
}

/// Whether `ip` (v4) falls within the pool's IPv4 range.
pub fn ip_in_pool_v4(pool: &Pool, ip: &str) -> bool {
    match (Ipv4Addr::from_str(ip), v4_range(pool)) {
        (Ok(addr), Some((start, end))) => {
            let n = u32::from(addr);
            n >= start && n <= end
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn pool_v4(start: &str, end: &str) -> Pool {
        Pool {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: String::new(),
            name: "p".into(),
            subnet_v4: Some("192.168.1.0/24".into()),
            range_start_v4: Some(start.into()),
            range_end_v4: Some(end.into()),
            subnet_v6: None,
            range_start_v6: None,
            range_end_v6: None,
            gateway: None,
            dns_servers: vec![],
            domain_name: None,
            lease_duration_secs: None,
            enabled: true,
        }
    }

    #[test]
    fn mac_normalizes() {
        assert_eq!(
            normalize_mac("AA-BB-CC-DD-EE-FF"),
            Some("aa:bb:cc:dd:ee:ff".into())
        );
        assert_eq!(
            normalize_mac("aabb.ccdd.eeff"),
            Some("aa:bb:cc:dd:ee:ff".into())
        );
        assert_eq!(normalize_mac("nope"), None);
    }

    #[test]
    fn pool_range_and_order() {
        assert!(check_pool(&pool_v4("192.168.1.10", "192.168.1.200")).is_ok());
        assert_eq!(
            check_pool(&pool_v4("192.168.1.200", "192.168.1.10")),
            Err(MSG_RANGE_ORDER)
        );
        assert_eq!(check_pool(&pool_v4("bad", "192.168.1.9")), Err(MSG_IP));
    }

    #[test]
    fn pool_requires_a_range() {
        let mut p = pool_v4("192.168.1.10", "192.168.1.20");
        p.subnet_v4 = None;
        p.range_start_v4 = None;
        p.range_end_v4 = None;
        assert_eq!(check_pool(&p), Err(MSG_NO_RANGE));
    }

    #[test]
    fn overlap_detects_intersection() {
        let a = v4_range(&pool_v4("192.168.1.10", "192.168.1.100")).unwrap();
        let b = v4_range(&pool_v4("192.168.1.50", "192.168.1.150")).unwrap();
        let c = v4_range(&pool_v4("192.168.1.200", "192.168.1.250")).unwrap();
        assert!(intervals_overlap(a, b));
        assert!(!intervals_overlap(a, c));
    }

    #[test]
    fn reservation_in_pool_range() {
        let p = pool_v4("192.168.1.10", "192.168.1.200");
        assert!(ip_in_pool_v4(&p, "192.168.1.50"));
        assert!(!ip_in_pool_v4(&p, "192.168.1.5"));
    }
}
