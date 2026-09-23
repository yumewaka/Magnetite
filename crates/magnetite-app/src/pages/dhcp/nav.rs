//! DHCP sub-navigation (screen_dhcp §6).

use leptos::prelude::*;
use leptos_router::components::A;

/// Horizontal tab bar linking the DHCP sub-screens.
#[component]
pub fn DhcpNav() -> impl IntoView {
    let links = [
        ("/dhcp", "ダッシュボード"),
        ("/dhcp/pools", "プール"),
        ("/dhcp/leases", "リース"),
        ("/dhcp/config", "設定"),
    ];
    view! {
        <nav class="sub-nav" aria-label="DHCP">
            {links
                .into_iter()
                .map(|(href, label)| view! {
                    <A href=href attr:class="sub-nav-link" exact=true>{label}</A>
                })
                .collect_view()}
        </nav>
    }
}
