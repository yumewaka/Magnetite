//! LDAP write-time validation (08_ldap_logic §2, §4-light). Pure, shared by the
//! form and repository; confirmed messages from screen_ldap §5.

pub const MSG_CN: &str = "CN を正しく入力してください。";
pub const MSG_UID: &str = "uid を正しく入力してください。";
pub const MSG_SN: &str = "姓 (sn) を正しく入力してください。";
pub const MSG_OU: &str = "OU 名を正しく入力してください。";
pub const MSG_MAIL: &str = "メールアドレスの形式が正しくありません。";
pub const MSG_DN: &str = "DN の形式が正しくありません。";
pub const MSG_PARENT: &str = "親 DN が存在しません。";
pub const MSG_PASSWORD: &str = "パスワードがポリシーを満たしていません。";

/// Lower-case a DN for case-insensitive comparison.
pub fn normalize_dn(dn: &str) -> String {
    dn.trim().to_ascii_lowercase()
}

/// Whether `dn` is a syntactically valid RFC 4514-ish DN: comma-separated
/// `attr=value` components with non-empty parts. (Escaped commas are not
/// handled in this iteration.)
pub fn is_valid_dn(dn: &str) -> bool {
    let dn = dn.trim();
    if dn.is_empty() {
        return false;
    }
    dn.split(',').all(|comp| {
        let comp = comp.trim();
        match comp.split_once('=') {
            Some((a, v)) => !a.trim().is_empty() && !v.trim().is_empty(),
            None => false,
        }
    })
}

/// The RDN (leftmost component) of a DN.
pub fn rdn_of(dn: &str) -> String {
    dn.split(',').next().unwrap_or("").trim().to_string()
}

/// Build a child DN from an RDN and its parent DN.
pub fn build_dn(rdn: &str, parent_dn: &str) -> String {
    format!("{},{}", rdn.trim(), parent_dn.trim())
}

fn check_name(value: &str, msg: &'static str) -> Result<(), &'static str> {
    let len = value.trim().chars().count();
    if (1..=64).contains(&len) {
        Ok(())
    } else {
        Err(msg)
    }
}

fn check_email(mail: &str) -> Result<(), &'static str> {
    if mail.is_empty() {
        return Ok(());
    }
    // Minimal shape check: `local@domain.tld`.
    match mail.split_once('@') {
        Some((local, domain)) if !local.is_empty() && domain.contains('.') => Ok(()),
        _ => Err(MSG_MAIL),
    }
}

/// Validate the fields for creating a user (07_data_ldap §2.2).
pub fn check_user(uid: &str, cn: &str, sn: &str, mail: &str) -> Result<(), &'static str> {
    if uid.trim().is_empty()
        || uid.trim().chars().count() > 64
        || !uid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(MSG_UID);
    }
    check_name(cn, MSG_CN)?;
    check_name(sn, MSG_SN)?;
    check_email(mail.trim())
}

/// Validate the fields for creating a group.
pub fn check_group(cn: &str) -> Result<(), &'static str> {
    check_name(cn, MSG_CN)
}

/// Validate the fields for creating an OU.
pub fn check_ou(ou: &str) -> Result<(), &'static str> {
    check_name(ou, MSG_OU)
}

/// Validate a member DN string.
pub fn check_member_dn(dn: &str) -> Result<(), &'static str> {
    if is_valid_dn(dn) {
        Ok(())
    } else {
        Err(MSG_DN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dn_validity_and_rdn() {
        assert!(is_valid_dn("uid=jsmith,ou=People,dc=example,dc=com"));
        assert!(!is_valid_dn("not a dn"));
        assert!(!is_valid_dn("uid=,dc=example"));
        assert_eq!(
            rdn_of("uid=jsmith,ou=People,dc=example,dc=com"),
            "uid=jsmith"
        );
        assert_eq!(build_dn("uid=a", "ou=People,dc=x"), "uid=a,ou=People,dc=x");
    }

    #[test]
    fn user_validation() {
        assert!(check_user("jsmith", "John Smith", "Smith", "j@example.com").is_ok());
        assert!(check_user("jsmith", "John Smith", "Smith", "").is_ok());
        assert_eq!(check_user("", "John", "Smith", ""), Err(MSG_UID));
        assert_eq!(check_user("js", "", "Smith", ""), Err(MSG_CN));
        assert_eq!(check_user("js", "John", "Smith", "bad"), Err(MSG_MAIL));
        assert_eq!(check_user("bad uid!", "John", "Smith", ""), Err(MSG_UID));
    }

    #[test]
    fn ou_and_member() {
        assert!(check_ou("People").is_ok());
        assert_eq!(check_ou(""), Err(MSG_OU));
        assert!(check_member_dn("uid=a,dc=x").is_ok());
        assert_eq!(check_member_dn("nope"), Err(MSG_DN));
    }
}
