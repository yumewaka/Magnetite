//! Backup MX (secondary MX) management: the domains Magnetite acts as a backup
//! MX for, and the durable forwarding queue that holds mail while a primary is
//! unreachable. Accepting inbound mail for these domains and forwarding it to the
//! primary provides standard, interoperable mail redundancy.

use super::nav::MailNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::mail::{
    list_backup_mx, list_backup_queue, DeleteBackupMx, DeleteBackupQueue, SaveBackupMx,
};
use leptos::prelude::*;
use magnetite_core::domains::mail::model::BackupMxDomain;

#[component]
pub fn BackupMxPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let domains = Resource::new(move || reload.get(), |_| list_backup_mx());
    let queue = Resource::new(move || reload.get(), |_| list_backup_queue());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let host = RwSignal::new(String::new());
    let port = RwSignal::new("25".to_string());
    let enabled = RwSignal::new(true);

    let open_create = move |_| {
        edit_id.set(String::new());
        name.set(String::new());
        host.set(String::new());
        port.set("25".to_string());
        enabled.set(true);
        form_open.set(true);
    };
    let open_edit = move |d: BackupMxDomain| {
        edit_id.set(d.id.clone());
        name.set(d.name.clone());
        host.set(d.primary_host.clone());
        port.set(d.primary_port.to_string());
        enabled.set(d.enabled);
        form_open.set(true);
    };

    let save = ServerAction::<SaveBackupMx>::new();
    let save_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = save.value().get() {
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
        let now = chrono::Utc::now();
        let domain = BackupMxDomain {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            name: name.get().trim().to_string(),
            primary_host: host.get().trim().to_string(),
            primary_port: port.get().trim().parse::<u16>().unwrap_or(0),
            enabled: enabled.get(),
        };
        save.dispatch(SaveBackupMx { domain });
    };

    let delete = ServerAction::<DeleteBackupMx>::new();
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
        Some((_, n)) => format!("バックアップ MX「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, name)) = delete_target.get() {
            delete.dispatch(DeleteBackupMx { id, name });
        }
    });

    // Forwarding-queue row deletion (manual drop of a stuck message).
    let drop_msg = ServerAction::<DeleteBackupQueue>::new();
    Effect::new(move |_| {
        if let Some(result) = drop_msg.value().get() {
            match result {
                Ok(()) => {
                    toast.success("キューから削除しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "バックアップ MX".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <MailNav/>
        <p class="page-hint">
            "ここで登録したドメイン宛のメールを、プライマリ（一次 MX）が停止している間も受理し、\
             復旧するまでキューに保持して転送します（セカンダリ MX）。"
        </p>

        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                domains.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "バックアップ MX ドメインがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|d| {
                            let d_edit = d.clone();
                            let dn = d.name.clone();
                            let did = d.id.clone();
                            let health = if d.enabled { "healthy" } else { "unknown" };
                            let primary = format!("{}:{}", d.primary_host, d.primary_port);
                            view! {
                                <tr>
                                    <td>{d.name.clone()}</td>
                                    <td>{primary}</td>
                                    <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="編集" on:click=move |_| open_edit(d_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((did.clone(), dn.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"ドメイン"</th><th>"プライマリ"</th><th>"状態"</th><th>"操作"</th></tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                        }.into_any()
                    }
                })
            }}
        </Suspense>

        <h2 class="section-title">"転送キュー"</h2>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                queue.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "キューは空です。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|q| {
                            let qid = q.id.clone();
                            let sender = if q.sender.is_empty() { "<>".to_string() } else { q.sender.clone() };
                            let rcpts = q.recipients.join(", ");
                            let primary = format!("{}:{}", q.primary_host, q.primary_port);
                            let next = q.next_attempt.format("%Y-%m-%d %H:%M").to_string();
                            let err = q.last_error.clone().unwrap_or_default();
                            view! {
                                <tr>
                                    <td>{sender}</td>
                                    <td>{rcpts}</td>
                                    <td>{primary}</td>
                                    <td>{q.attempts}</td>
                                    <td>{next}</td>
                                    <td class="cell-muted">{err}</td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="キューから削除" on:click=move |_| { drop_msg.dispatch(DeleteBackupQueue { id: qid.clone() }); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"送信元"</th><th>"宛先"</th><th>"プライマリ"</th><th>"試行"</th><th>"次回"</th><th>"最終エラー"</th><th>"操作"</th></tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                        }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">{move || if edit_id.get().is_empty() { "バックアップ MX の追加" } else { "バックアップ MX の編集" }}</h2>
                    <label class="field"><span class="field-label">"ドメイン"</span>
                        <input class="input" prop:value=move || name.get() prop:disabled=move || !edit_id.get().is_empty()
                            on:input=move |ev| name.set(event_target_value(&ev)) placeholder="example.com"/></label>
                    <label class="field"><span class="field-label">"プライマリ ホスト"</span>
                        <input class="input" prop:value=move || host.get() on:input=move |ev| host.set(event_target_value(&ev)) placeholder="mx1.example.com"/></label>
                    <label class="field"><span class="field-label">"プライマリ ポート"</span>
                        <input class="input" type="number" prop:value=move || port.get() on:input=move |ev| port.set(event_target_value(&ev))/></label>
                    <label class="field field-inline"><input type="checkbox" prop:checked=move || enabled.get() on:change=move |ev| enabled.set(event_target_checked(&ev))/><span>"有効"</span></label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || save.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        <ConfirmDialog title=Signal::derive(|| "削除の確認".to_string()) body=confirm_body open=confirm_open on_confirm=on_confirm_delete/>
    }
}
