//! DNS sub-navigation shown atop every DNS screen (screen_dns 全体遷移).

use leptos::prelude::*;
use leptos_router::components::A;

struct DnsLink {
    href: &'static str,
    label: &'static str,
}

/// Horizontal tab bar linking the DNS sub-screens.
#[component]
pub fn DnsNav() -> impl IntoView {
    let links = [
        DnsLink {
            href: "/dns",
            label: "ダッシュボード",
        },
        DnsLink {
            href: "/dns/zones",
            label: "ゾーン",
        },
        DnsLink {
            href: "/dns/rpz",
            label: "RPZ",
        },
        DnsLink {
            href: "/dns/dnssec",
            label: "DNSSEC",
        },
        DnsLink {
            href: "/dns/geo",
            label: "GeoDNS",
        },
        DnsLink {
            href: "/dns/forwarders",
            label: "フォワーダ",
        },
        DnsLink {
            href: "/dns/ddns",
            label: "ダイナミックDNS",
        },
        DnsLink {
            href: "/dns/replication",
            label: "レプリケーション",
        },
        DnsLink {
            href: "/dns/query-logs",
            label: "クエリログ",
        },
        DnsLink {
            href: "/dns/query-test",
            label: "クエリテスト",
        },
        DnsLink {
            href: "/dns/templates",
            label: "テンプレート",
        },
    ];
    view! {
        <nav class="sub-nav" aria-label="DNS">
            {links
                .into_iter()
                .map(|l| view! {
                    <A href=l.href attr:class="sub-nav-link" exact=true>{l.label}</A>
                })
                .collect_view()}
        </nav>
    }
}
