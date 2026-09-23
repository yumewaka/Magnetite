//! Placeholder page for screens scheduled in later phases. Keeps every sidebar
//! link navigable while the domain/cross-cutting screens are built out.

use crate::components::ui::PageHeader;
use leptos::prelude::*;

/// A "coming soon" page carrying the localized title of the target screen.
#[component]
pub fn PlaceholderPage(#[prop(into)] title_key: String) -> impl IntoView {
    let i18n = magnetite_core::i18n::use_i18n();
    let key = title_key.clone();
    view! {
        <PageHeader title=Signal::derive(move || i18n.t(&key).to_string())/>
        <div class="state-block empty-state">
            <p>"\u{1F6A7} 準備中 / Under construction"</p>
        </div>
    }
}
