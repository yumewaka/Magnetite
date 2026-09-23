//! AD DC sub-navigation shown atop every AD DC screen.

use leptos::prelude::*;
use leptos_router::components::A;

struct AddcLink {
    href: &'static str,
    label: &'static str,
}

/// Horizontal tab bar linking the AD DC sub-screens.
#[component]
pub fn AddcNav() -> impl IntoView {
    let links = [
        AddcLink {
            href: "/addc",
            label: "ダッシュボード",
        },
        AddcLink {
            href: "/addc/gpo",
            label: "グループポリシー",
        },
        AddcLink {
            href: "/addc/logon-scripts",
            label: "ログオンスクリプト",
        },
        AddcLink {
            href: "/addc/domain",
            label: "ドメイン参加/離脱",
        },
        AddcLink {
            href: "/addc/fsmo",
            label: "FSMO ロール",
        },
    ];
    view! {
        <nav class="sub-nav" aria-label="AD DC">
            {links
                .into_iter()
                .map(|l| view! {
                    <A href=l.href attr:class="sub-nav-link" exact=true>{l.label}</A>
                })
                .collect_view()}
        </nav>
    }
}
