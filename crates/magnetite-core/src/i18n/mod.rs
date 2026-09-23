//! Internationalization (ja/en). Japanese is the canonical source; English is
//! the paired translation (06/10). Text is keyed so all copy lives in one place.

pub mod en;
pub mod ja;

use leptos::prelude::*;

/// Supported UI locales.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Locale {
    Ja,
    En,
}

impl Locale {
    /// BCP-47-ish short code.
    pub fn code(self) -> &'static str {
        match self {
            Locale::Ja => "ja",
            Locale::En => "en",
        }
    }

    /// Native language label for the switcher.
    pub fn label(self) -> &'static str {
        match self {
            Locale::Ja => "日本語",
            Locale::En => "English",
        }
    }

    /// Parse a locale from a code, defaulting to Japanese.
    pub fn from_code(code: &str) -> Self {
        match code {
            "en" => Locale::En,
            _ => Locale::Ja,
        }
    }

    /// The other locale (for a two-way toggle).
    pub fn toggle(self) -> Self {
        match self {
            Locale::Ja => Locale::En,
            Locale::En => Locale::Ja,
        }
    }
}

/// Reactive i18n context provided at the app root.
#[derive(Clone, Copy)]
pub struct I18nContext {
    pub locale: RwSignal<Locale>,
}

impl I18nContext {
    /// Translate `key` in the current locale, falling back to the key itself.
    pub fn t<'a>(&self, key: &'a str) -> &'a str {
        translate(self.locale.get(), key)
    }
}

/// Install the i18n context (default Japanese).
pub fn provide_i18n() {
    let locale = RwSignal::new(Locale::Ja);
    provide_context(I18nContext { locale });
}

/// Access the i18n context.
pub fn use_i18n() -> I18nContext {
    expect_context::<I18nContext>()
}

/// Translate `key` for `locale`. Unknown keys return the key verbatim so
/// missing translations are visible rather than silently blank.
pub fn translate(locale: Locale, key: &str) -> &str {
    let translated = match locale {
        Locale::Ja => ja::lookup(key),
        Locale::En => en::lookup(key),
    };
    translated.unwrap_or(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_keys_translate() {
        assert_eq!(translate(Locale::Ja, "app.title"), "Magnetite");
        assert_eq!(translate(Locale::En, "action.save"), "Save");
    }

    #[test]
    fn unknown_key_returns_key() {
        assert_eq!(translate(Locale::En, "no.such.key"), "no.such.key");
    }

    #[test]
    fn locale_toggles_and_round_trips() {
        assert_eq!(Locale::Ja.toggle(), Locale::En);
        assert_eq!(Locale::from_code("en"), Locale::En);
        assert_eq!(Locale::from_code("zz"), Locale::Ja);
    }

    #[test]
    fn ja_and_en_cover_the_same_keys() {
        for key in ja::KEYS {
            assert!(
                en::lookup(key).is_some(),
                "English dictionary is missing key: {key}"
            );
        }
        for key in en::KEYS {
            assert!(
                ja::lookup(key).is_some(),
                "Japanese dictionary is missing key: {key}"
            );
        }
    }
}
