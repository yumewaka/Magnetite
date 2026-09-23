//! K8s host management (S-K8S-02). Credential is write-only (masked after save).

use super::nav::K8sNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::k8s::{list_k8s_hosts, CreateK8sHost, DeleteK8sHost};
use leptos::prelude::*;
use magnetite_core::domains::k8s::model::{Host, HostState};

fn host_health(s: HostState) -> &'static str {
    match s {
        HostState::Ready | HostState::Online => "healthy",
        HostState::Offline => "unknown",
        HostState::Error => "error",
    }
}

#[component]
pub fn HostsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let hosts = Resource::new(move || reload.get(), |_| list_k8s_hosts());

    let form_open = RwSignal::new(false);
    let hostname = RwSignal::new(String::new());
    let address = RwSignal::new(String::new());
    let ssh_port = RwSignal::new("22".to_string());
    let ssh_user = RwSignal::new(String::new());
    let auth_method = RwSignal::new("password".to_string());
    let credential = RwSignal::new(String::new());

    let open_create = move |_| {
        hostname.set(String::new());
        address.set(String::new());
        ssh_port.set("22".into());
        ssh_user.set(String::new());
        auth_method.set("password".into());
        credential.set(String::new());
        form_open.set(true);
    };

    let create = ServerAction::<CreateK8sHost>::new();
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
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateK8sHost {
            hostname: hostname.get(),
            address: address.get(),
            ssh_port: ssh_port.get().trim().parse::<u16>().unwrap_or(22),
            ssh_user: ssh_user.get(),
            auth_method: auth_method.get(),
            credential: credential.get(),
        });
    };

    let delete = ServerAction::<DeleteK8sHost>::new();
    let confirm_open = RwSignal::new(false);
    let delete_target = RwSignal::new(Option::<(String, String)>::None);
    Effect::new(move |_| {
        if let Some(result) = delete.value().get() {
            match result {
                Ok(()) => {
                    toast.success("削除しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });
    Effect::new(move |_| {
        if !confirm_open.get() {
            delete_target.set(None);
        }
    });
    let confirm_body = Signal::derive(move || match delete_target.get() {
        Some((_, h)) => format!("ホスト「{h}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, hostname)) = delete_target.get() {
            delete.dispatch(DeleteK8sHost { id, hostname });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "コンテナホスト".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 登録"</button>
        </PageHeader>
        <K8sNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                hosts.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "登録済みホストがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|h: Host| {
                            let health = host_health(h.state);
                            let id_d = h.id.clone();
                            let host_d = h.hostname.clone();
                            let cluster = h.cluster_ref.clone().unwrap_or_else(|| "-".into());
                            view! {
                                <tr>
                                    <td class="mono">{h.hostname.clone()}</td>
                                    <td class="mono">{h.address.clone()}</td>
                                    <td>{h.ssh_port}</td>
                                    <td>{h.ssh_user.clone()}</td>
                                    <td>{cluster}</td>
                                    <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_d.clone(), host_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"ホスト名"</th><th>"IP"</th><th>"ポート"</th><th>"ユーザー"</th><th>"クラスタ"</th><th>"状態"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">"ホストの登録"</h2>
                    <label class="field"><span class="field-label">"ホスト名"</span><input class="input" prop:value=move || hostname.get() on:input=move |ev| hostname.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"IP アドレス"</span><input class="input" prop:value=move || address.get() on:input=move |ev| address.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"SSH ポート"</span><input class="input" type="number" prop:value=move || ssh_port.get() on:input=move |ev| ssh_port.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"SSH ユーザー"</span><input class="input" prop:value=move || ssh_user.get() on:input=move |ev| ssh_user.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"認証方式"</span>
                        <select class="input" prop:value=move || auth_method.get() on:change=move |ev| auth_method.set(event_target_value(&ev))>
                            <option value="password">"パスワード"</option><option value="key">"秘密鍵"</option>
                        </select></label>
                    <label class="field"><span class="field-label">"認証情報（保存後は非表示）"</span><textarea class="input" rows="3" prop:value=move || credential.get() on:input=move |ev| credential.set(event_target_value(&ev))></textarea></label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || create.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        <ConfirmDialog title=Signal::derive(|| "削除の確認".to_string()) body=confirm_body open=confirm_open on_confirm=on_confirm_delete/>
    }
}
