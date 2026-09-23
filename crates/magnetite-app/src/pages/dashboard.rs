//! Integrated dashboard (S-Dash / F-03): one status card per enabled domain.
//! Phase 0 shows every domain as "unknown" until daemon health is wired in.

use crate::components::ui::{ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::shell::get_dashboard_cards;
use leptos::prelude::*;
use magnetite_core::i18n::use_i18n;

#[component]
pub fn DashboardPage() -> impl IntoView {
    let i18n = use_i18n();
    let cards = Resource::new(|| (), |_| get_dashboard_cards());
    let reload = Callback::new(move |_| cards.refetch());

    view! {
        <PageHeader
            title=Signal::derive(move || i18n.t("dashboard.title").to_string())
            subtitle=Signal::derive(move || i18n.t("dashboard.subtitle").to_string())
        />
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                cards.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=reload/> }.into_any(),
                    Ok(list) => {
                        let items = list
                            .into_iter()
                            .map(|card| {
                                let health = card.health.clone();
                                view! {
                                    <DashboardCard
                                        href=format!("/{}", card.key.as_str())
                                        name=card.display_name
                                        health=health
                                    />
                                }
                            })
                            .collect_view();
                        view! { <div class="dashboard-grid">{items}</div> }.into_any()
                    }
                })
            }}
        </Suspense>
    }
}

/// A single dashboard status card linking to the domain landing page.
#[component]
fn DashboardCard(href: String, name: String, health: String) -> impl IntoView {
    use leptos_router::components::A;
    view! {
        <A href=href attr:class="dashboard-card">
            <div class="card-head">
                <span class="card-name">{name}</span>
                <StatusBadge health=Signal::derive(move || health.clone())/>
            </div>
        </A>
    }
}
