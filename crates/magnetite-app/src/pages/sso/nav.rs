//! SSO sub-navigation (screen_sso §6).

use leptos::prelude::*;
use leptos_router::components::A;

/// Horizontal tab bar linking the SSO sub-screens.
#[component]
pub fn SsoNav() -> impl IntoView {
    let links = [
        ("/sso", "連携プロバイダ"),
        ("/sso/clients", "OIDCクライアント"),
        ("/sso/sessions", "セッション"),
        ("/sso/audit-sink", "監査連携先"),
    ];
    view! {
        <nav class="sub-nav" aria-label="SSO">
            {links
                .into_iter()
                .map(|(href, label)| view! {
                    <A href=href attr:class="sub-nav-link" exact=true>{label}</A>
                })
                .collect_view()}
        </nav>
    }
}
