//! Light/dark theme context and toggle (06 §1b / F-09).

use leptos::prelude::*;
use magnetite_core::i18n::use_i18n;

/// Reactive theme state (dark on/off). Default is light (06 policy).
#[derive(Clone, Copy)]
pub struct ThemeContext {
    pub dark_mode: RwSignal<bool>,
}

/// Install the theme context.
pub fn provide_theme_context() {
    provide_context(ThemeContext {
        dark_mode: RwSignal::new(false),
    });
}

/// Access the theme context.
pub fn use_theme() -> ThemeContext {
    expect_context::<ThemeContext>()
}

/// Header button that toggles between light and dark.
#[component]
pub fn ThemeToggle() -> impl IntoView {
    let theme = use_theme();
    let i18n = use_i18n();
    let toggle = move |_| theme.dark_mode.update(|d| *d = !*d);
    view! {
        <button class="icon-button" title=move || i18n.t("theme.toggle") on:click=toggle>
            {move || if theme.dark_mode.get() { "\u{2600}" } else { "\u{263D}" }}
        </button>
    }
}
