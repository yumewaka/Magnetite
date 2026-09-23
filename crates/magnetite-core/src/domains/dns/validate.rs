//! DNS write-time validation (08_dns_logic §5). Pure functions shared by the
//! form (client) and the repository (server); each returns the confirmed
//! Japanese message (screen_dns §5) on failure.

use super::model::{Record, RecordType, RpzAction, RpzRule, Soa, Zone};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub const MSG_ZONE_NAME: &str = "ゾーン名の形式が正しくありません。（例: example.com）";
pub const MSG_MNAME: &str = "プライマリネームサーバーを FQDN で入力してください。";
pub const MSG_RNAME: &str = "管理者メールをドット表記で入力してください。（例: admin.example.com）";
pub const MSG_SOA: &str =
    "SOA の値が正しくありません。（refresh・retry は 1 以上、expire は refresh より大きく）";
pub const MSG_RECORD_NAME: &str = "レコード名の形式が正しくありません。";
pub const MSG_RECORD_TYPE: &str = "レコード種別を選択してください。";
pub const MSG_A: &str = "IPv4 アドレスを入力してください。（例: 192.0.2.1）";
pub const MSG_AAAA: &str = "IPv6 アドレスを入力してください。（例: 2001:db8::1）";
pub const MSG_FQDN: &str = "FQDN を入力してください。（例: host.example.com）";
pub const MSG_MX: &str = "優先度（0〜65535）と交換先 FQDN を入力してください。";
pub const MSG_TXT: &str = "テキストを入力してください。";
pub const MSG_RECORD_VALUE: &str = "値を入力してください。";
pub const MSG_RPZ_DOMAIN: &str = "対象ドメインの形式が正しくありません。";
pub const MSG_RPZ_REDIRECT: &str = "リダイレクト先を入力してください。";

/// Normalize a DNS name: lower-cased, trailing dot removed.
pub fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn is_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return false;
    }
    label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Whether `name` is a syntactically valid FQDN (>= 2 labels). When
/// `allow_wildcard`, a leading `*` label is accepted (for RPZ targets).
pub fn is_fqdn(name: &str, allow_wildcard: bool) -> bool {
    let normalized = normalize_name(name);
    if normalized.is_empty() {
        return false;
    }
    let labels: Vec<&str> = normalized.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().enumerate().all(|(i, label)| {
        if i == 0 && allow_wildcard && *label == "*" {
            true
        } else {
            is_label(label)
        }
    })
}

/// Validate a zone name (08_dns_logic §5.1). Returns the confirmed message on
/// failure.
pub fn check_zone_name(name: &str) -> Result<(), &'static str> {
    if is_fqdn(name, false) {
        Ok(())
    } else {
        Err(MSG_ZONE_NAME)
    }
}

/// Validate the SOA block of a zone.
pub fn check_soa(soa: &Soa) -> Result<(), &'static str> {
    if !is_fqdn(&soa.mname, false) {
        return Err(MSG_MNAME);
    }
    if soa.rname.contains('@') || !is_fqdn(&soa.rname, false) {
        return Err(MSG_RNAME);
    }
    if soa.refresh == 0 || soa.retry == 0 || soa.expire <= soa.refresh {
        return Err(MSG_SOA);
    }
    Ok(())
}

/// Validate a whole zone (name + SOA).
pub fn check_zone(zone: &Zone) -> Result<(), &'static str> {
    check_zone_name(&zone.name)?;
    check_soa(&zone.soa)
}

fn data_str<'a>(data: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    data.get(key).and_then(|v| v.as_str())
}

/// Read a `u64` from a JSON value that may be a number OR a numeric string. The default
/// leptos server-fn codec is form-urlencoded, which stringifies every `serde_json::Value`
/// scalar in a record's `data` — so an MX `preference` submitted as the number `10`
/// arrives at the server as the string `"10"`. Accepting both keeps numeric record fields
/// working regardless of how `data` was transported.
pub fn as_u64_lenient(v: &serde_json::Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
}

/// Coerce a record's `data` so numeric fields are stored as JSON numbers even when the
/// transport delivered them as strings (see [`as_u64_lenient`]). Call this before
/// validating and storing a record, so every downstream reader — validation, the DNS wire
/// encoder and the UI, all of which use `as_u64` — sees a proper number. Currently only MX
/// carries a numeric `data` field (`preference`).
pub fn normalize_record_data(record_type: RecordType, data: &mut serde_json::Value) {
    if record_type == RecordType::Mx {
        if let Some(v) = data.get_mut("preference") {
            if let Some(n) = as_u64_lenient(v) {
                *v = serde_json::Value::from(n);
            }
        }
    }
}

/// Validate a record's name/shape against its zone (08_dns_logic §5.2). Does
/// not check cross-record CNAME coexistence (that needs the sibling set — the
/// repository enforces it).
pub fn check_record(zone_name: &str, record: &Record) -> Result<(), &'static str> {
    let zone = normalize_name(zone_name);
    let name = normalize_name(&record.name);
    // Name must be the apex or a suffix of the zone.
    if name != zone && !name.ends_with(&format!(".{zone}")) {
        return Err(MSG_RECORD_NAME);
    }
    check_record_data(record.record_type, &record.data)
}

/// Validate that `data` matches `record_type` (07_data_dns §3.2).
pub fn check_record_data(
    record_type: RecordType,
    data: &serde_json::Value,
) -> Result<(), &'static str> {
    match record_type {
        RecordType::A => match data_str(data, "address") {
            Some(a) if Ipv4Addr::from_str(a).is_ok() => Ok(()),
            _ => Err(MSG_A),
        },
        RecordType::Aaaa => match data_str(data, "address") {
            Some(a) if Ipv6Addr::from_str(a).is_ok() => Ok(()),
            _ => Err(MSG_AAAA),
        },
        RecordType::Cname => check_fqdn_field(data, "target"),
        RecordType::Ns => check_fqdn_field(data, "nsdname"),
        RecordType::Ptr => check_fqdn_field(data, "ptrdname"),
        RecordType::Mx => {
            let pref_ok = data
                .get("preference")
                .and_then(as_u64_lenient)
                .is_some_and(|n| n <= u16::MAX as u64);
            let exch_ok = data_str(data, "exchange").is_some_and(|e| is_fqdn(e, false));
            if pref_ok && exch_ok {
                Ok(())
            } else {
                Err(MSG_MX)
            }
        }
        RecordType::Txt => match data_str(data, "text") {
            Some(t) if !t.is_empty() => Ok(()),
            _ => Err(MSG_TXT),
        },
        // SRV/CAA accept a raw value string in this iteration (screen_dns §1).
        RecordType::Srv | RecordType::Caa => match data_str(data, "value") {
            Some(v) if !v.trim().is_empty() => Ok(()),
            _ => Err(MSG_RECORD_VALUE),
        },
    }
}

fn check_fqdn_field(data: &serde_json::Value, key: &str) -> Result<(), &'static str> {
    match data_str(data, key) {
        Some(v) if is_fqdn(v, false) => Ok(()),
        _ => Err(MSG_FQDN),
    }
}

/// Validate an RPZ rule (08_dns_logic §5.3).
pub fn check_rpz(rule: &RpzRule) -> Result<(), &'static str> {
    if !is_fqdn(&rule.domain, true) {
        return Err(MSG_RPZ_DOMAIN);
    }
    if rule.action == RpzAction::Redirect {
        match rule.redirect_to.as_deref() {
            Some(t) if is_fqdn(t, false) => Ok(()),
            _ => Err(MSG_RPZ_REDIRECT),
        }
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn zone_name_rules() {
        assert!(check_zone_name("example.com").is_ok());
        assert!(check_zone_name("sub.example.com.").is_ok());
        assert!(check_zone_name("localhost").is_err());
        assert!(check_zone_name("-bad.example.com").is_err());
        assert!(check_zone_name("").is_err());
    }

    #[test]
    fn soa_integrity() {
        let mut soa = Soa {
            mname: "ns1.example.com".into(),
            rname: "admin.example.com".into(),
            ..Soa::default()
        };
        assert!(check_soa(&soa).is_ok());
        soa.rname = "admin@example.com".into();
        assert!(check_soa(&soa).is_err());
        soa.rname = "admin.example.com".into();
        soa.expire = soa.refresh; // expire must exceed refresh
        assert!(check_soa(&soa).is_err());
    }

    #[test]
    fn record_data_by_type() {
        assert!(check_record_data(RecordType::A, &json!({"address": "192.0.2.1"})).is_ok());
        assert!(check_record_data(RecordType::A, &json!({"address": "2001:db8::1"})).is_err());
        assert!(check_record_data(RecordType::Aaaa, &json!({"address": "2001:db8::1"})).is_ok());
        assert!(
            check_record_data(RecordType::Cname, &json!({"target": "host.example.com"})).is_ok()
        );
        assert!(check_record_data(RecordType::Cname, &json!({"target": "nope"})).is_err());
        assert!(check_record_data(
            RecordType::Mx,
            &json!({"preference": 10, "exchange": "mail.example.com"})
        )
        .is_ok());
        assert!(check_record_data(
            RecordType::Mx,
            &json!({"preference": 70000, "exchange": "mail.example.com"})
        )
        .is_err());
        assert!(check_record_data(RecordType::Txt, &json!({"text": "v=spf1"})).is_ok());
        assert!(check_record_data(RecordType::Txt, &json!({"text": ""})).is_err());
    }

    #[test]
    fn mx_preference_accepts_a_numeric_string_and_normalizes() {
        // The form-urlencoded server-fn codec stringifies the numeric preference: MX must
        // still validate, and normalization must restore it to a JSON number so the wire
        // encoder / UI (which use `as_u64`) work.
        let string_pref = json!({"preference": "10", "exchange": "mail.example.com"});
        assert!(
            check_record_data(RecordType::Mx, &string_pref).is_ok(),
            "a numeric-string preference must validate"
        );
        let mut data = string_pref;
        normalize_record_data(RecordType::Mx, &mut data);
        assert_eq!(data["preference"], json!(10), "coerced to a JSON number");
        assert!(data["preference"].as_u64().is_some());

        // A non-numeric preference is still rejected, and normalization leaves it alone.
        let mut bad = json!({"preference": "abc", "exchange": "mail.example.com"});
        assert!(check_record_data(RecordType::Mx, &bad).is_err());
        normalize_record_data(RecordType::Mx, &mut bad);
        assert_eq!(bad["preference"], json!("abc"));
    }

    #[test]
    fn record_name_suffix() {
        let record = Record {
            id: String::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            created_by: String::new(),
            zone: "z1".into(),
            name: "www.example.com".into(),
            ttl: 3600,
            record_type: RecordType::A,
            data: json!({"address": "192.0.2.1"}),
            enabled: true,
        };
        assert!(check_record("example.com", &record).is_ok());
        assert!(check_record("other.org", &record).is_err());
    }

    #[test]
    fn rpz_redirect_requires_target() {
        let mut rule = RpzRule {
            id: String::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            created_by: String::new(),
            domain: "malware.example.com".into(),
            action: RpzAction::Redirect,
            redirect_to: None,
            enabled: true,
        };
        assert!(check_rpz(&rule).is_err());
        rule.redirect_to = Some("safe.example.com".into());
        assert!(check_rpz(&rule).is_ok());
        rule.action = RpzAction::Nxdomain;
        rule.redirect_to = None;
        assert!(check_rpz(&rule).is_ok());
        assert!(check_rpz(&RpzRule {
            domain: "*.evil.example.com".into(),
            ..rule.clone()
        })
        .is_ok());
    }
}
