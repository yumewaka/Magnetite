//! K8s sub-navigation (screen_k8s §6).

use leptos::prelude::*;
use leptos_router::components::A;

/// Horizontal tab bar linking the K8s sub-screens.
#[component]
pub fn K8sNav() -> impl IntoView {
    let links = [
        ("/k8s", "ダッシュボード"),
        ("/k8s/hosts", "ホスト"),
        ("/k8s/clusters", "クラスタ"),
        ("/k8s/workloads", "ワークロード"),
        ("/k8s/alerts", "アラートルール"),
        ("/k8s/backups", "バックアップ"),
        ("/k8s/templates", "テンプレート"),
    ];
    view! {
        <nav class="sub-nav" aria-label="K8s">
            {links
                .into_iter()
                .map(|(href, label)| view! {
                    <A href=href attr:class="sub-nav-link" exact=true>{label}</A>
                })
                .collect_view()}
        </nav>
    }
}
