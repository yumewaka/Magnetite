//! LDAP dashboard (S-LDAP-01): entry/user/group/OU counts and the base DN.

use super::nav::LdapNav;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::ldap::get_ldap_metrics;
use leptos::prelude::*;

#[component]
pub fn LdapDashboard() -> impl IntoView {
    let metrics = Resource::new(|| (), |_| get_ldap_metrics());
    let reload = Callback::new(move |_| metrics.refetch());

    view! {
        <PageHeader title=Signal::derive(|| "LDAP ダッシュボード".to_string())>
            <button class="btn btn-secondary" on:click=move |_| metrics.refetch()>"更新"</button>
        </PageHeader>
        <LdapNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                metrics.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=reload/> }.into_any(),
                    Ok(m) => {
                        let base = m.base_dn.clone();
                        view! {
                            <div class="dashboard-grid">
                                <div class="stat-card"><span class="stat-value">{m.entry_count}</span><span class="stat-label">"エントリ数"</span></div>
                                <div class="stat-card"><span class="stat-value">{m.user_count}</span><span class="stat-label">"ユーザ数"</span></div>
                                <div class="stat-card"><span class="stat-value">{m.group_count}</span><span class="stat-label">"グループ数"</span></div>
                                <div class="stat-card"><span class="stat-value">{m.ou_count}</span><span class="stat-label">"OU 数"</span></div>
                            </div>
                            <p class="base-dn">"ベース DN: " <span class="mono">{base}</span></p>
                        }
                        .into_any()
                    }
                })
            }}
        </Suspense>
    }
}
