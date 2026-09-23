//! Mail user management (S-MAIL-02): list, create, enable/disable, delete.

use super::nav::MailNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::mail::{
    list_mail_domains, list_mail_users, CreateMailUser, DeleteMailUser, ResetMailUserPassword,
    ToggleMailUser,
};
use leptos::prelude::*;
use magnetite_core::domains::mail::model::MailUser;

const MB: u64 = 1_048_576;

#[component]
pub fn MailUsersPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let users = Resource::new(move || reload.get(), |_| list_mail_users());
    let domains = Resource::new(|| (), |_| list_mail_domains());

    let form_open = RwSignal::new(false);
    let local_part = RwSignal::new(String::new());
    let domain = RwSignal::new(String::new());
    let display_name = RwSignal::new(String::new());
    let quota_mb = RwSignal::new("0".to_string());
    let password = RwSignal::new(String::new());

    let open_create = move |_| {
        local_part.set(String::new());
        display_name.set(String::new());
        quota_mb.set("0".to_string());
        password.set(String::new());
        form_open.set(true);
    };

    let create = ServerAction::<CreateMailUser>::new();
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
        create.dispatch(CreateMailUser {
            local_part: local_part.get(),
            domain: domain.get(),
            display_name: display_name.get(),
            quota_mb: quota_mb.get().trim().parse::<u64>().unwrap_or(0),
            password: password.get(),
        });
    };

    let toggle = ServerAction::<ToggleMailUser>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = toggle.value().get() {
            toast.success("保存しました。");
            reload.update(|n| *n += 1);
        }
    });

    // Password reset (admin sets a mail user's login password).
    let reset = ServerAction::<ResetMailUserPassword>::new();
    let reset_open = RwSignal::new(false);
    let reset_id = RwSignal::new(String::new());
    let reset_email = RwSignal::new(String::new());
    let reset_pw = RwSignal::new(String::new());
    let reset_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = reset.value().get() {
            match result {
                Ok(()) => {
                    reset_error.set(None);
                    reset_open.set(false);
                    toast.success("パスワードをリセットしました。");
                }
                Err(e) => reset_error.set(Some(e.to_string())),
            }
        }
    });
    let submit_reset = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        reset.dispatch(ResetMailUserPassword {
            id: reset_id.get(),
            password: reset_pw.get(),
        });
    };

    let delete = ServerAction::<DeleteMailUser>::new();
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
        Some((_, e)) => format!("メールユーザ「{e}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = delete_target.get() {
            delete.dispatch(DeleteMailUser { id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "メールユーザ".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <MailNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                users.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "メールユーザがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|u: MailUser| {
                            let health = if u.enabled { "healthy" } else { "error" };
                            let id_t = u.id.clone();
                            let id_d = u.id.clone();
                            let email_d = u.email.clone();
                            let id_r = u.id.clone();
                            let email_r = u.email.clone();
                            let enabled = u.enabled;
                            let quota = if u.quota_bytes == 0 { "無制限".to_string() } else { format!("{} / {} MB", u.used_bytes / MB, u.quota_bytes / MB) };
                            view! {
                                <tr>
                                    <td class="mono">{u.email.clone()}</td>
                                    <td>{u.display_name.clone().unwrap_or_default()}</td>
                                    <td>{quota}</td>
                                    <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" on:click=move |_| { toggle.dispatch(ToggleMailUser { id: id_t.clone(), enabled: !enabled }); }>
                                            {if enabled { "無効化" } else { "有効化" }}
                                        </button>
                                        <button class="btn btn-secondary btn-sm"
                                            on:click=move |_| { reset_id.set(id_r.clone()); reset_email.set(email_r.clone()); reset_pw.set(String::new()); reset_error.set(None); reset_open.set(true); }>"PWリセット"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_d.clone(), email_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"メールアドレス"</th><th>"表示名"</th><th>"クォータ"</th><th>"状態"</th><th>"操作"</th></tr></thead>
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
                    <h2 class="slideover-title">"メールユーザの作成"</h2>
                    <label class="field"><span class="field-label">"ユーザ名（ローカルパート）"</span>
                        <input class="input" prop:value=move || local_part.get() on:input=move |ev| local_part.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"所属ドメイン"</span>
                        <select class="input" on:change=move |ev| domain.set(event_target_value(&ev)) prop:value=move || domain.get()>
                            <option value="">"（選択）"</option>
                            <Suspense fallback=|| ()>
                                {move || domains.get().map(|res| res.unwrap_or_default().into_iter().map(|d| { let n = d.name.clone(); view! { <option value=d.name>{n}</option> } }).collect_view())}
                            </Suspense>
                        </select>
                    </label>
                    <label class="field"><span class="field-label">"表示名（任意）"</span>
                        <input class="input" prop:value=move || display_name.get() on:input=move |ev| display_name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"クォータ MB（0=無制限）"</span>
                        <input class="input" type="number" prop:value=move || quota_mb.get() on:input=move |ev| quota_mb.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"初期パスワード"</span>
                        <input class="input" type="password" prop:value=move || password.get() on:input=move |ev| password.set(event_target_value(&ev))/></label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || create.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        <Show when=move || reset_open.get() fallback=|| ()>
            <div class="modal-overlay" on:click=move |_| reset_open.set(false)>
                <form class="modal" on:click=|ev| ev.stop_propagation() on:submit=submit_reset>
                    <h2 class="modal-title">"パスワードのリセット"</h2>
                    <p class="mono">{move || reset_email.get()}</p>
                    <label class="field">
                        <span class="field-label">"新しいパスワード"</span>
                        <input class="input" type="password" prop:value=move || reset_pw.get()
                            on:input=move |ev| reset_pw.set(event_target_value(&ev))/>
                    </label>
                    {move || reset_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="modal-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| reset_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || reset.pending().get()>"リセット"</button>
                    </div>
                </form>
            </div>
        </Show>

        <ConfirmDialog title=Signal::derive(|| "削除の確認".to_string()) body=confirm_body open=confirm_open on_confirm=on_confirm_delete/>
    }
}
