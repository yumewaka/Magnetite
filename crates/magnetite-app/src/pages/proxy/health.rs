//! Proxy health (S-PROXY-07). Shows the embedded reverse proxy's live status
//! and a summary of the routing config it is serving.

use super::nav::ProxyNav;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::proxy::get_proxy_health;
use leptos::prelude::*;

fn health_meta(health: &str) -> (&'static str, &'static str) {
    match health {
        "healthy" => ("稼働中", "badge badge-success"),
        "warning" => ("警告", "badge badge-warning"),
        "error" => ("エラー", "badge badge-danger"),
        _ => ("未稼働", "badge badge-unknown"),
    }
}

#[component]
pub fn HealthPage() -> impl IntoView {
    let reload = RwSignal::new(0_u32);
    let health = Resource::new(move || reload.get(), |_| get_proxy_health());

    view! {
        <PageHeader title=Signal::derive(|| "プロキシ ヘルス".to_string())/>
        <ProxyNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || health.get().map(|res| match res {
                Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                Ok(h) => {
                    let (label, class) = health_meta(&h.health);
                    view! {
                        <div class="proxy-health">
                            <div class="proxy-health-status">
                                <span class="field-label">"サーバ状態"</span>
                                <span class=class>{label}</span>
                            </div>
                            <dl class="proxy-health-summary">
                                <dt>"仮想ホスト"</dt><dd>{h.vhosts}" （有効 "{h.enabled_vhosts}"）"</dd>
                                <dt>"アップストリーム総数"</dt><dd>{h.upstreams}</dd>
                                <dt>"有効なIPブロック"</dt><dd>{h.active_blocks}</dd>
                            </dl>
                            <p class="field-hint">"「未稼働」は [domains.proxy.server] が未設定でプロキシが起動していないことを示します。"</p>
                        </div>
                    }.into_any()
                }
            })}
        </Suspense>
    }
}
