//! Sidebar navigation (S-00 §0 / 10 §1.1): three groups — cross-cutting, the
//! enabled domains, and administration (hidden from Viewers).

use crate::types::DomainNav;
use leptos::prelude::*;
use leptos_router::components::A;
use magnetite_core::authz::Role;
use magnetite_core::i18n::use_i18n;

struct Link {
    href: String,
    label_key: &'static str,
}

#[component]
pub fn Sidebar(role: Role, domains: Vec<DomainNav>) -> impl IntoView {
    let i18n = use_i18n();

    let cross = vec![
        Link {
            href: "/".into(),
            label_key: "nav.dashboard",
        },
        Link {
            href: "/audit".into(),
            label_key: "nav.audit",
        },
        Link {
            href: "/alerts".into(),
            label_key: "nav.alerts",
        },
        Link {
            href: "/backup".into(),
            label_key: "nav.backup",
        },
        Link {
            href: "/logs".into(),
            label_key: "nav.logs",
        },
    ];
    // Management group is hidden from Viewers (S-00 §0).
    let show_admin = role > Role::Viewer;

    let render_links = move |links: Vec<Link>| {
        links
            .into_iter()
            .map(|link| {
                view! {
                    <li>
                        <A href=link.href attr:class="nav-link">
                            {move || i18n.t(link.label_key)}
                        </A>
                    </li>
                }
            })
            .collect_view()
    };

    let domain_links = domains
        .into_iter()
        .map(|domain| {
            let href = format!("/{}", domain.key.as_str());
            view! {
                <li>
                    <A href=href attr:class="nav-link">{domain.display_name}</A>
                </li>
            }
        })
        .collect_view();

    view! {
        <nav class="sidebar" aria-label="main navigation">
            <div class="sidebar-brand">
                <span class="brand-mark">{"\u{25C8}"}</span>
                <span class="brand-name">{move || i18n.t("app.title")}</span>
            </div>
            <ul class="sidebar-nav">
                <li class="nav-group">
                    <span class="nav-group-label">{move || i18n.t("nav.group.cross")}</span>
                    <ul>{render_links(cross)}</ul>
                </li>
                <li class="nav-group">
                    <span class="nav-group-label">{move || i18n.t("nav.group.domains")}</span>
                    // AD DC is a served protocol domain but not one of the eight
                    // settings-driven UI tiles, so it is linked directly here.
                    <ul>
                        {domain_links}
                        <li>
                            <A href="/addc" attr:class="nav-link">
                                {move || i18n.t("domain.addc")}
                            </A>
                        </li>
                    </ul>
                </li>
                <Show when=move || show_admin fallback=|| ()>
                    <li class="nav-group">
                        <span class="nav-group-label">{move || i18n.t("nav.group.admin")}</span>
                        <ul>{render_links(vec![
                            Link { href: "/settings".into(), label_key: "nav.settings" },
                            Link { href: "/account".into(), label_key: "nav.account" },
                        ])}</ul>
                    </li>
                </Show>
            </ul>
        </nav>
    }
}
