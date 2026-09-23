//! Watch sub-navigation (screen_watch header).

use leptos::prelude::*;
use leptos_router::components::A;

/// Horizontal tab bar linking the Watch sub-screens.
#[component]
pub fn WatchNav() -> impl IntoView {
    let links = [
        ("/watch", "ダッシュボード"),
        ("/watch/hosts", "監視ホスト"),
        ("/watch/rules", "監視ルール"),
        ("/watch/groups", "グループ"),
        ("/watch/maintenance", "メンテナンス窓"),
    ];
    view! {
        <nav class="sub-nav" aria-label="Watch">
            {links
                .into_iter()
                .map(|(href, label)| view! {
                    <A href=href attr:class="sub-nav-link" exact=true>{label}</A>
                })
                .collect_view()}
        </nav>
    }
}
