//! Proxy sub-navigation (screen_proxy §6).

use leptos::prelude::*;
use leptos_router::components::A;

/// Horizontal tab bar linking the Proxy sub-screens.
#[component]
pub fn ProxyNav() -> impl IntoView {
    let links = [
        ("/proxy", "ダッシュボード"),
        ("/proxy/vhosts", "仮想ホスト"),
        ("/proxy/certificates", "証明書"),
        ("/proxy/acl-rules", "ACL"),
        ("/proxy/forward", "フォワード"),
        ("/proxy/ip-blocklist", "IPブロック"),
        ("/proxy/access-logs", "アクセスログ"),
        ("/proxy/health", "ヘルス"),
    ];
    view! {
        <nav class="sub-nav" aria-label="Proxy">
            {links
                .into_iter()
                .map(|(href, label)| view! {
                    <A href=href attr:class="sub-nav-link" exact=true>{label}</A>
                })
                .collect_view()}
        </nav>
    }
}
