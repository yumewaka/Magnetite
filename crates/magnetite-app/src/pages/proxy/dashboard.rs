//! Proxy dashboard (S-PROXY-01): vhost / certificate / ACL counts.

use super::nav::ProxyNav;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::proxy::get_proxy_metrics;
use leptos::prelude::*;

#[component]
pub fn ProxyDashboard() -> impl IntoView {
    let metrics = Resource::new(|| (), |_| get_proxy_metrics());
    let reload = Callback::new(move |_| metrics.refetch());

    view! {
        <PageHeader title=Signal::derive(|| "プロキシダッシュボード".to_string())>
            <button class="btn btn-secondary" on:click=move |_| metrics.refetch()>"更新"</button>
        </PageHeader>
        <ProxyNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                metrics.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=reload/> }.into_any(),
                    Ok(m) => view! {
                        <div class="dashboard-grid">
                            <div class="stat-card"><span class="stat-value">{m.vhost_count}</span><span class="stat-label">"仮想ホスト数"</span></div>
                            <div class="stat-card"><span class="stat-value">{m.cert_count}</span><span class="stat-label">"証明書数"</span></div>
                            <div class="stat-card"><span class="stat-value">{m.acl_count}</span><span class="stat-label">"ACL ルール数"</span></div>
                        </div>
                    }.into_any(),
                })
            }}
        </Suspense>
    }
}
