//! SSO write-time validation (screen_sso §5). Pure, shared by form and
//! repository.

pub const MSG_NAME: &str = "名称を正しく入力してください。";
pub const MSG_SELECT: &str = "いずれかを選択してください。";
pub const MSG_CLIENT_ID: &str = "クライアントIDを入力してください。";
pub const MSG_SECRET: &str = "クライアントシークレットを入力してください。";
pub const MSG_URL_HTTPS: &str = "URLを正しく入力してください（https）。";
pub const MSG_REDIRECT: &str = "リダイレクトURIを1件以上入力してください。";
pub const MSG_GRANT: &str = "グラント種別を1つ以上選択してください。";

const PROVIDER_TYPES: [&str; 5] = ["oidc", "google", "github", "azure", "custom"];

fn is_https_url(value: &str) -> bool {
    let v = value.trim();
    (v.starts_with("https://") || v.starts_with("http://")) && v.len() > 8 && v.contains('.')
}

/// Validate a provider's create/update fields.
pub fn check_provider(
    name: &str,
    provider_type: &str,
    client_id: &str,
    is_create: bool,
    has_secret_input: bool,
) -> Result<(), &'static str> {
    let len = name.trim().chars().count();
    if !(1..=100).contains(&len) {
        return Err(MSG_NAME);
    }
    if !PROVIDER_TYPES.contains(&provider_type) {
        return Err(MSG_SELECT);
    }
    if client_id.trim().is_empty() {
        return Err(MSG_CLIENT_ID);
    }
    // Secret required on create; on edit an empty value keeps the stored one.
    if is_create && !has_secret_input {
        return Err(MSG_SECRET);
    }
    Ok(())
}

/// Validate the OIDC-custom-only URL fields (required only for that type).
pub fn check_custom_urls(
    provider_type: &str,
    authorize_url: &str,
    token_url: &str,
    userinfo_url: &str,
) -> Result<(), &'static str> {
    if provider_type == "custom" || provider_type == "oidc" {
        for url in [authorize_url, token_url, userinfo_url] {
            if !url.trim().is_empty() && !is_https_url(url) {
                return Err(MSG_URL_HTTPS);
            }
        }
    }
    Ok(())
}

/// Validate an OIDC client's fields.
pub fn check_client(
    client_name: &str,
    redirect_uris: &[String],
    grant_types: &[String],
) -> Result<(), &'static str> {
    let len = client_name.trim().chars().count();
    if !(1..=100).contains(&len) {
        return Err(MSG_NAME);
    }
    if redirect_uris.iter().all(|u| u.trim().is_empty()) {
        return Err(MSG_REDIRECT);
    }
    if grant_types.iter().all(|g| g.trim().is_empty()) {
        return Err(MSG_GRANT);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_requires_secret_on_create() {
        assert!(check_provider("Google", "google", "cid", true, true).is_ok());
        assert_eq!(
            check_provider("Google", "google", "cid", true, false),
            Err(MSG_SECRET)
        );
        // Edit without new secret is OK.
        assert!(check_provider("Google", "google", "cid", false, false).is_ok());
        assert_eq!(
            check_provider("Google", "unknown", "cid", true, true),
            Err(MSG_SELECT)
        );
    }

    #[test]
    fn custom_urls_must_be_https() {
        assert!(check_custom_urls("custom", "https://idp.example.com/auth", "", "").is_ok());
        assert_eq!(
            check_custom_urls("custom", "ftp://idp.example.com", "", ""),
            Err(MSG_URL_HTTPS)
        );
        // Non-custom ignores the URLs.
        assert!(check_custom_urls("google", "bad", "", "").is_ok());
    }

    #[test]
    fn client_requires_redirect_and_grant() {
        assert!(check_client(
            "app",
            &["https://app/cb".into()],
            &["authorization_code".into()]
        )
        .is_ok());
        assert_eq!(
            check_client("app", &[], &["authorization_code".into()]),
            Err(MSG_REDIRECT)
        );
        assert_eq!(
            check_client("app", &["https://app/cb".into()], &[]),
            Err(MSG_GRANT)
        );
    }
}
