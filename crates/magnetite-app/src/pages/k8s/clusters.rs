//! K8s cluster management (S-K8S-03): create from member hosts, node detail and
//! delete (releases member hosts).

use super::nav::K8sNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::k8s::{
    list_k8s_clusters, list_k8s_hosts, CreateK8sCluster, DeleteK8sCluster,
};
use leptos::prelude::*;
use magnetite_core::domains::k8s::model::{Cluster, ClusterState};

#[component]
pub fn ClustersPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let clusters = Resource::new(move || reload.get(), |_| list_k8s_clusters());
    let hosts = Resource::new(move || reload.get(), |_| list_k8s_hosts());

    // Create form.
    let form_open = RwSignal::new(false);
    let name = RwSignal::new(String::new());
    let version = RwSignal::new("1.30.2".to_string());
    let pod_cidr = RwSignal::new("10.244.0.0/16".to_string());
    let service_cidr = RwSignal::new("10.96.0.0/12".to_string());
    let cni = RwSignal::new("calico".to_string());
    let members = RwSignal::new(Vec::<String>::new());
    let create = ServerAction::<CreateK8sCluster>::new();
    let save_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = create.value().get() {
            match result {
                Ok(()) => {
                    save_error.set(None);
                    form_open.set(false);
                    toast.success("保存しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => save_error.set(Some(e.to_string())),
            }
        }
    });
    let open_create = move |_| {
        name.set(String::new());
        version.set("1.30.2".into());
        pod_cidr.set("10.244.0.0/16".into());
        service_cidr.set("10.96.0.0/12".into());
        cni.set("calico".into());
        members.set(Vec::new());
        save_error.set(None);
        form_open.set(true);
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateK8sCluster {
            name: name.get(),
            k8s_version: version.get(),
            pod_cidr: pod_cidr.get(),
            service_cidr: service_cidr.get(),
            cni: cni.get(),
            member_hostnames: members.get(),
        });
    };

    // Node detail.
    let detail = RwSignal::new(Option::<Cluster>::None);

    // Delete.
    let delete = ServerAction::<DeleteK8sCluster>::new();
    let confirm_open = RwSignal::new(false);
    let delete_target = RwSignal::new(Option::<(String, String)>::None);
    Effect::new(move |_| {
        if let Some(Ok(())) = delete.value().get() {
            toast.success("削除しました。");
            reload.update(|n| *n += 1);
        }
    });
    Effect::new(move |_| {
        if !confirm_open.get() {
            delete_target.set(None);
        }
    });
    let confirm_body = Signal::derive(move || match delete_target.get() {
        Some((_, n)) => format!("クラスタ「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, name)) = delete_target.get() {
            delete.dispatch(DeleteK8sCluster { id, name });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "クラスタ".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 作成"</button>
        </PageHeader>
        <K8sNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                clusters.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "クラスタがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|c: Cluster| {
                            let c_detail = c.clone();
                            let id_d = c.id.clone();
                            let name_d = c.name.clone();
                            let health = match c.state { ClusterState::Ready => "healthy", ClusterState::Failed => "error", ClusterState::Error => "warning" };
                            view! {
                                <tr>
                                    <td>{c.name.clone()}</td>
                                    <td class="mono">{c.pod_cidr.clone()}</td>
                                    <td class="mono">{c.service_cidr.clone()}</td>
                                    <td>{c.cni.clone()}</td>
                                    <td>{c.node_count}</td>
                                    <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" on:click=move |_| detail.set(Some(c_detail.clone()))>"詳細"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_d.clone(), name_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"名称"</th><th>"Pod CIDR"</th><th>"Service CIDR"</th><th>"CNI"</th><th>"ノード数"</th><th>"状態"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        // Create slide-over.
        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">"クラスタの作成"</h2>
                    <label class="field"><span class="field-label">"クラスタ名"</span><input class="input" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"K8s バージョン"</span><input class="input" prop:value=move || version.get() on:input=move |ev| version.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"Pod CIDR"</span><input class="input" prop:value=move || pod_cidr.get() on:input=move |ev| pod_cidr.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"Service CIDR"</span><input class="input" prop:value=move || service_cidr.get() on:input=move |ev| service_cidr.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"CNI"</span><input class="input" prop:value=move || cni.get() on:input=move |ev| cni.set(event_target_value(&ev))/></label>
                    <span class="field-label">"構成ホスト（先頭がコントロールプレーン）"</span>
                    <div class="host-picker">
                        <Suspense fallback=|| ()>
                            {move || hosts.get().map(|res| {
                                res.unwrap_or_default().into_iter().filter(|h| h.cluster_ref.is_none()).map(|h| {
                                    let hn = h.hostname.clone();
                                    let hn2 = h.hostname.clone();
                                    view! {
                                        <label class="host-check">
                                            <input type="checkbox" on:change=move |ev| {
                                                let checked = event_target_checked(&ev);
                                                members.update(|m| { if checked { if !m.contains(&hn) { m.push(hn.clone()); } } else { m.retain(|x| x != &hn); } });
                                            }/>
                                            <span class="mono">{hn2}</span>
                                        </label>
                                    }
                                }).collect_view()
                            })}
                        </Suspense>
                    </div>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || create.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        // Node detail slide-over.
        <Show when=move || detail.get().is_some() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| detail.set(None)>
                <div class="slideover" on:click=|ev| ev.stop_propagation()>
                    <h2 class="slideover-title">"構成ノード"</h2>
                    {move || detail.get().map(|c| {
                        let node_rows = c.nodes.iter().cloned().map(|n| view! {
                            <tr>
                                <td class="mono">{n.hostname}</td>
                                <td class="mono">{n.address}</td>
                                <td>{match n.role { magnetite_core::domains::k8s::model::HostRole::ControlPlane => "control-plane", magnetite_core::domains::k8s::model::HostRole::Worker => "worker" }}</td>
                            </tr>
                        }).collect_view();
                        view! {
                            <p class="mono">{c.name.clone()}</p>
                            <table class="data-table"><thead><tr><th>"ホスト名"</th><th>"アドレス"</th><th>"ロール"</th></tr></thead><tbody>{node_rows}</tbody></table>
                        }
                    })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| detail.set(None)>"閉じる"</button>
                    </div>
                </div>
            </div>
        </Show>

        <ConfirmDialog title=Signal::derive(|| "削除の確認".to_string()) body=confirm_body open=confirm_open on_confirm=on_confirm_delete/>
    }
}
