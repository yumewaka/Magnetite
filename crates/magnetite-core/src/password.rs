//! Password policy checks (05 §5 / AC-03). Hashing lives in the DB layer; this
//! is the pure, shared rule so the same policy applies at setup and account
//! creation on both client and server.

/// Validate a password against the policy: at least `min_length` characters and
/// containing both a letter and a digit.
///
/// Returns `Ok(())` when the password complies, otherwise `Err` with the i18n
/// key of the confirmed message to display.
pub fn check_password(password: &str, min_length: usize) -> Result<(), &'static str> {
    let long_enough = password.chars().count() >= min_length;
    let has_letter = password.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    if long_enough && has_letter && has_digit {
        Ok(())
    } else {
        Err("setup.error.policy")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_compliant_password() {
        assert!(check_password("abcd1234", 8).is_ok());
    }

    #[test]
    fn rejects_too_short() {
        assert!(check_password("ab12", 8).is_err());
    }

    #[test]
    fn rejects_missing_digit_or_letter() {
        assert!(check_password("abcdefgh", 8).is_err());
        assert!(check_password("12345678", 8).is_err());
    }
}
