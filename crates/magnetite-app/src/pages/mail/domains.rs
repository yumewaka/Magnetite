//! Mail domain management (S-MAIL-03). Delete refused when accounts exist
//! (AC-16, surfaced as an error toast).

use super::nav::MailNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::mail::{list_mail_domains, DeleteMailDomain, SaveMailDomain};
use leptos::prelude::*;
use magnetite_core::domains::mail::model::MailDomain;

const MB: u64 = 1_048_576;

#[component]
pub fn DomainsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let domains = Resource::new(move || reload.get(), |_| list_mail_domains());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let enabled = RwSignal::new(true);
    let max_users = RwSignal::new(String::new());
    let quota_mb = RwSignal::new(String::new());

    let open_create = move |_| {
        edit_id.set(String::new());
        name.set(String::new());
        enabled.set(true);
        max_users.set(String::new());
        quota_mb.set(String::new());
        form_open.set(true);
    };
    let open_edit = move |d: MailDomain| {
        edit_id.set(d.id.clone());
        name.set(d.name.clone());
        enabled.set(d.enabled);
        max_users.set(d.max_users.map(|n| n.to_string()).unwrap_or_default());
        quota_mb.set(
            d.default_quota_bytes
                .map(|b| (b / MB).to_string())
                .unwrap_or_default(),
        );
        form_open.set(true);
    };

    let save = ServerAction::<SaveMailDomain>::new();
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
        let domain = MailDomain {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            name: name.get(),
            enabled: enabled.get(),
            max_users: max_users.get().trim().parse::<u32>().ok(),
            default_quota_bytes: quota_mb.get().trim().parse::<u64>().ok().map(|mb| mb * MB),
        };
        save.dispatch(SaveMailDomain { domain });
    };

    let delete = ServerAction::<DeleteMailDomain>::new();
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
        Some((_, n)) => format!("ドメイン「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, name)) = delete_target.get() {
            delete.dispatch(DeleteMailDomain { id, name });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "メールドメイン".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <MailNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                domains.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "ドメインがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|d| {
                            let d_edit = d.clone();
                            let dn = d.name.clone();
                            let did = d.id.clone();
                            let health = if d.enabled { "healthy" } else { "unknown" };
                            let max = d.max_users.map(|n| n.to_string()).unwrap_or_else(|| "無制限".into());
                            let quota = d.default_quota_bytes.map(|b| format!("{} MB", b / MB)).unwrap_or_else(|| "-".into());
                            view! {
                                <tr>
                                    <td>{d.name.clone()}</td>
                                    <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                    <td>{max}</td>
                                    <td>{quota}</td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="編集" on:click=move |_| open_edit(d_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((did.clone(), dn.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"ドメイン名"</th><th>"状態"</th><th>"最大ユーザ"</th><th>"既定クォータ"</th><th>"操作"</th></tr></thead>
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
                    <h2 class="slideover-title">{move || if edit_id.get().is_empty() { "ドメインの作成" } else { "ドメインの編集" }}</h2>
                    <label class="field"><span class="field-label">"ドメイン名"</span>
                        <input class="input" prop:value=move || name.get() prop:disabled=move || !edit_id.get().is_empty()
                            on:input=move |ev| name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"最大ユーザ数（任意）"</span>
                        <input class="input" type="number" prop:value=move || max_users.get() on:input=move |ev| max_users.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"既定クォータ MB（任意）"</span>
                        <input class="input" type="number" prop:value=move || quota_mb.get() on:input=move |ev| quota_mb.set(event_target_value(&ev))/></label>
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
