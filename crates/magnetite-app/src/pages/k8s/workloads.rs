//! Live cluster workloads: pick a registered cluster, configure its kube-API
//! connection (endpoint + bearer token), then list its Deployments / Services /
//! Pods and tail a pod's log — all fetched live from the cluster's API server via
//! the read-only `magnetite-k8s` client.

use super::nav::K8sNav;
use crate::components::toast::use_toast;
use crate::components::ui::{LoadingState, PageHeader};
use crate::server_fns::k8s::{list_k8s_clusters, GetPodLogs, ListClusterWorkloads, SetClusterApi};
use leptos::prelude::*;
use magnetite_core::domains::k8s::model::Cluster;

#[component]
pub fn WorkloadsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let clusters = Resource::new(move || reload.get(), |_| list_k8s_clusters());

    let selected = RwSignal::new(String::new());
    let namespace = RwSignal::new(String::new());

    // Connection form (endpoint + token) for the selected cluster.
    let conn_open = RwSignal::new(false);
    let endpoint = RwSignal::new(String::new());
    let token = RwSignal::new(String::new());
    let set_api = ServerAction::<SetClusterApi>::new();
    let conn_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = set_api.value().get() {
            match result {
                Ok(()) => {
                    conn_error.set(None);
                    conn_open.set(false);
                    toast.success("接続設定を保存しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => conn_error.set(Some(e.to_string())),
            }
        }
    });
    let save_conn = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        set_api.dispatch(SetClusterApi {
            id: selected.get(),
            endpoint: endpoint.get(),
            token: token.get(),
        });
    };

    // Fetch workloads.
    let fetch = ServerAction::<ListClusterWorkloads>::new();
    let run_fetch = move |_| {
        if selected.get().is_empty() {
            toast.error("クラスタを選択してください。");
            return;
        }
        fetch.dispatch(ListClusterWorkloads {
            cluster_id: selected.get(),
            namespace: namespace.get(),
        });
    };

    // Pod log viewer.
    let log_open = RwSignal::new(false);
    let log_pod = RwSignal::new(String::new());
    let logs = ServerAction::<GetPodLogs>::new();
    let open_logs = move |ns: String, pod: String| {
        log_pod.set(pod.clone());
        log_open.set(true);
        logs.dispatch(GetPodLogs {
            cluster_id: selected.get(),
            namespace: ns,
            pod,
            tail_lines: 200,
        });
    };

    view! {
        <PageHeader title=Signal::derive(|| "ワークロード".to_string())/>
        <K8sNav/>
        <p class="page-intro">
            "登録済みクラスタの kube API サーバに接続し、Deployment / Service / Pod を"
            "ライブ表示します。まずクラスタを選び、API 接続（エンドポイント + トークン）を"
            "設定してください。名前空間が空の場合は全名前空間を対象にします。"
        </p>

        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || clusters.get().map(|res| match res {
                Err(e) => view! { <p class="field-error">{e.to_string()}</p> }.into_any(),
                Ok(list) => {
                    let options = list.iter().map(|c: &Cluster| {
                        let id = c.id.clone();
                        let label = format!("{}{}", c.name, if c.api_token_set { "" } else { "（未接続）" });
                        view! { <option value=id>{label}</option> }
                    }).collect_view();
                    // Endpoint lookup for the connection form, primed on open.
                    let endpoints: Vec<(String, String)> = list.iter()
                        .map(|c| (c.id.clone(), c.api_server_endpoint.clone().unwrap_or_default()))
                        .collect();
                    let open_conn = move |_| {
                        let sel = selected.get();
                        let ep = endpoints.iter().find(|(id, _)| *id == sel).map(|(_, e)| e.clone()).unwrap_or_default();
                        endpoint.set(ep);
                        token.set(String::new());
                        conn_error.set(None);
                        conn_open.set(true);
                    };
                    view! {
                        <div class="toolbar">
                            <label class="field">
                                <span class="field-label">"クラスタ"</span>
                                <select class="input" on:change=move |ev| selected.set(event_target_value(&ev))>
                                    <option value="">"— 選択 —"</option>
                                    {options}
                                </select>
                            </label>
                            <label class="field">
                                <span class="field-label">"名前空間（空=全て）"</span>
                                <input class="input" prop:value=move || namespace.get() on:input=move |ev| namespace.set(event_target_value(&ev)) placeholder="default"/>
                            </label>
                            <button class="btn btn-secondary" prop:disabled=move || selected.get().is_empty() on:click=open_conn>"接続設定"</button>
                            <button class="btn btn-primary" prop:disabled=move || fetch.pending().get() on:click=run_fetch>{move || if fetch.pending().get() { "取得中…" } else { "取得" }}</button>
                        </div>
                    }.into_any()
                }
            })}
        </Suspense>

        {move || fetch.value().get().map(|res| match res {
            Err(e) => view! { <p class="field-error" role="alert">{e.to_string()}</p> }.into_any(),
            Ok(w) => {
                let dep_rows = w.deployments.into_iter().map(|d| view! {
                    <tr><td>{d.namespace}</td><td class="mono">{d.name}</td><td>{format!("{}/{}", d.ready_replicas, d.replicas)}</td><td>{d.available_replicas}</td><td class="mono">{d.images.join(", ")}</td></tr>
                }).collect_view();
                let svc_rows = w.services.into_iter().map(|s| view! {
                    <tr><td>{s.namespace}</td><td class="mono">{s.name}</td><td>{s.service_type}</td><td class="mono">{s.cluster_ip}</td><td class="mono">{s.ports.join(", ")}</td></tr>
                }).collect_view();
                let pod_rows = w.pods.into_iter().map(|p| {
                    let ns = p.namespace.clone();
                    let pod = p.name.clone();
                    view! {
                        <tr>
                            <td>{p.namespace.clone()}</td>
                            <td class="mono">{p.name.clone()}</td>
                            <td>{p.phase}</td>
                            <td>{p.ready}</td>
                            <td>{p.restarts}</td>
                            <td class="mono">{p.node}</td>
                            <td class="row-actions"><button class="btn btn-secondary btn-sm" on:click=move |_| open_logs(ns.clone(), pod.clone())>"ログ"</button></td>
                        </tr>
                    }
                }).collect_view();
                view! {
                    <h2 class="panel-title">"Deployments"</h2>
                    <table class="data-table"><thead><tr><th>"名前空間"</th><th>"名前"</th><th>"Ready"</th><th>"Available"</th><th>"イメージ"</th></tr></thead><tbody>{dep_rows}</tbody></table>
                    <h2 class="panel-title">"Services"</h2>
                    <table class="data-table"><thead><tr><th>"名前空間"</th><th>"名前"</th><th>"種別"</th><th>"ClusterIP"</th><th>"ポート"</th></tr></thead><tbody>{svc_rows}</tbody></table>
                    <h2 class="panel-title">"Pods"</h2>
                    <table class="data-table"><thead><tr><th>"名前空間"</th><th>"名前"</th><th>"Phase"</th><th>"Ready"</th><th>"再起動"</th><th>"ノード"</th><th>"操作"</th></tr></thead><tbody>{pod_rows}</tbody></table>
                }.into_any()
            }
        })}

        <Show when=move || conn_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| conn_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=save_conn>
                    <h2 class="slideover-title">"kube API 接続設定"</h2>
                    <label class="field"><span class="field-label">"API サーバ URL（例: https://10.0.0.1:6443）"</span><input class="input" prop:value=move || endpoint.get() on:input=move |ev| endpoint.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"ベアラートークン（空欄で変更なし）"</span><textarea class="input" rows="4" prop:value=move || token.get() on:input=move |ev| token.set(event_target_value(&ev))/></label>
                    <p class="field-hint">"トークンは保存後は表示されません。ServiceAccount の閲覧権限トークンを推奨します。"</p>
                    {move || conn_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| conn_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || set_api.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        <Show when=move || log_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| log_open.set(false)>
                <div class="slideover slideover-wide" on:click=|ev| ev.stop_propagation()>
                    <h2 class="slideover-title">{move || format!("ログ: {}", log_pod.get())}</h2>
                    {move || match logs.value().get() {
                        None => view! { <LoadingState/> }.into_any(),
                        Some(Err(e)) => view! { <p class="field-error" role="alert">{e.to_string()}</p> }.into_any(),
                        Some(Ok(text)) => view! { <pre class="log-view">{text}</pre> }.into_any(),
                    }}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| log_open.set(false)>"閉じる"</button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
