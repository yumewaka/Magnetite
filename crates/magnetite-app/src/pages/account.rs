//! Account / session management (S-Account, Admin only). Two tabs: local login
//! accounts (CRUD + role/enable/password) and active sessions (revoke).

use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::account::{
    list_active_sessions, list_local_accounts, CreateLocalAccount, DeleteLocalAccount,
    ResetAccountPassword, RevokePortalSessions, SetAccountEnabled, SetAccountRole,
};
use leptos::prelude::*;
use magnetite_core::i18n::use_i18n;
use magnetite_core::models::{LocalAccountInfo, SessionInfo};

#[component]
pub fn AccountPage() -> impl IntoView {
    let tab = RwSignal::new("accounts");
    view! {
        <PageHeader title=Signal::derive(|| "アカウント / セッション".to_string())/>
        <nav class="sub-nav">
            <button class="sub-nav-link" class:active=move || tab.get() == "accounts" on:click=move |_| tab.set("accounts")>"アカウント"</button>
            <button class="sub-nav-link" class:active=move || tab.get() == "sessions" on:click=move |_| tab.set("sessions")>"セッション"</button>
        </nav>
        <Show when=move || tab.get() == "accounts" fallback=move || view! { <SessionsTab/> }>
            <AccountsTab/>
        </Show>
    }
}

#[component]
fn AccountsTab() -> impl IntoView {
    let i18n = use_i18n();
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let accounts = Resource::new(move || reload.get(), |_| list_local_accounts());

    // Create form.
    let form_open = RwSignal::new(false);
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let role = RwSignal::new("viewer".to_string());
    let create = ServerAction::<CreateLocalAccount>::new();
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
        username.set(String::new());
        password.set(String::new());
        role.set("viewer".into());
        save_error.set(None);
        form_open.set(true);
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateLocalAccount {
            username: username.get(),
            password: password.get(),
            role: role.get(),
        });
    };

    // Role / enable / delete / reset actions.
    let set_role = ServerAction::<SetAccountRole>::new();
    let set_enabled = ServerAction::<SetAccountEnabled>::new();
    let delete = ServerAction::<DeleteLocalAccount>::new();
    let reset = ServerAction::<ResetAccountPassword>::new();
    Effect::new(move |_| {
        if let Some(result) = set_role.value().get() {
            match result {
                Ok(()) => {
                    toast.success("更新しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });
    Effect::new(move |_| {
        if let Some(result) = set_enabled.value().get() {
            match result {
                Ok(()) => {
                    toast.success("更新しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });

    // Delete confirm.
    let confirm_open = RwSignal::new(false);
    let delete_target = RwSignal::new(Option::<String>::None);
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
        Some(u) => format!("アカウント「{u}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some(username) = delete_target.get() {
            delete.dispatch(DeleteLocalAccount { username });
        }
    });

    // Password reset modal.
    let reset_open = RwSignal::new(false);
    let reset_user = RwSignal::new(String::new());
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
        reset.dispatch(ResetAccountPassword {
            username: reset_user.get(),
            new_password: reset_pw.get(),
        });
    };

    view! {
        <div class="tab-actions">
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </div>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                accounts.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "アカウントがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|a: LocalAccountInfo| {
                            let u_role = a.username.clone();
                            let u_en = a.username.clone();
                            let u_reset = a.username.clone();
                            let u_del = a.username.clone();
                            let enabled = a.enabled;
                            let last = a.last_login_at.map(|d| d.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "-".into());
                            view! {
                                <tr>
                                    <td>{a.username.clone()}</td>
                                    <td>
                                        <select class="input role-select" prop:value=a.role.as_str()
                                            on:change=move |ev| { set_role.dispatch(SetAccountRole { username: u_role.clone(), role: event_target_value(&ev) }); }>
                                            <option value="viewer">{i18n.t("rbac.viewer")}</option>
                                            <option value="operator">{i18n.t("rbac.operator")}</option>
                                            <option value="admin">{i18n.t("rbac.admin")}</option>
                                        </select>
                                    </td>
                                    <td>{if enabled { "有効" } else { "無効" }}</td>
                                    <td class="mono">{last}</td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" on:click=move |_| { set_enabled.dispatch(SetAccountEnabled { username: u_en.clone(), enabled: !enabled }); }>{if enabled { "無効化" } else { "有効化" }}</button>
                                        <button class="btn btn-secondary btn-sm" on:click=move |_| { reset_user.set(u_reset.clone()); reset_pw.set(String::new()); reset_error.set(None); reset_open.set(true); }>"PWリセット"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some(u_del.clone())); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"ユーザ名"</th><th>"ロール"</th><th>"状態"</th><th>"最終ログイン"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">"アカウントの作成"</h2>
                    <label class="field"><span class="field-label">"ユーザ名"</span><input class="input" prop:value=move || username.get() on:input=move |ev| username.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"初期パスワード"</span><input class="input" type="password" prop:value=move || password.get() on:input=move |ev| password.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"ロール"</span>
                        <select class="input" prop:value=move || role.get() on:change=move |ev| role.set(event_target_value(&ev))>
                            <option value="viewer">{i18n.t("rbac.viewer")}</option>
                            <option value="operator">{i18n.t("rbac.operator")}</option>
                            <option value="admin">{i18n.t("rbac.admin")}</option>
                        </select></label>
                    <p class="field-hint">{move || i18n.t("setup.password_policy")}</p>
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
                    <p class="mono">{move || reset_user.get()}</p>
                    <label class="field"><span class="field-label">"新しいパスワード"</span><input class="input" type="password" prop:value=move || reset_pw.get() on:input=move |ev| reset_pw.set(event_target_value(&ev))/></label>
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

#[component]
fn SessionsTab() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let sessions = Resource::new(move || reload.get(), |_| list_active_sessions());
    let selected = RwSignal::new(Vec::<String>::new());

    let revoke = ServerAction::<RevokePortalSessions>::new();
    let confirm_open = RwSignal::new(false);
    let pending = RwSignal::new(Vec::<String>::new());
    Effect::new(move |_| {
        if let Some(Ok(())) = revoke.value().get() {
            toast.success("失効しました。");
            selected.set(Vec::new());
            reload.update(|n| *n += 1);
        }
    });
    Effect::new(move |_| {
        if !confirm_open.get() {
            pending.set(Vec::new());
        }
    });
    let confirm_body = Signal::derive(move || {
        let n = pending.get().len();
        if n <= 1 {
            "このセッションを失効します。よろしいですか？".to_string()
        } else {
            format!("選択した {n} 件のセッションを失効します。よろしいですか？")
        }
    });
    let on_confirm = Callback::new(move |_| {
        let ids = pending.get();
        if !ids.is_empty() {
            revoke.dispatch(RevokePortalSessions { session_ids: ids });
        }
    });

    view! {
        <div class="tab-actions">
            <button class="btn btn-danger btn-sm" prop:disabled=move || selected.get().is_empty()
                on:click=move |_| { pending.set(selected.get()); confirm_open.set(true); }>"選択を失効"</button>
        </div>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                sessions.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "アクティブなセッションはありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|s: SessionInfo| {
                            let id_sel = s.session_id.clone();
                            let id_rev = s.session_id.clone();
                            let created = s.created_at.format("%Y-%m-%d %H:%M").to_string();
                            let checked = { let id = s.session_id.clone(); move || selected.get().contains(&id) };
                            view! {
                                <tr>
                                    <td><input type="checkbox" prop:checked=checked on:change=move |ev| {
                                        let on = event_target_checked(&ev);
                                        selected.update(|v| { if on { if !v.contains(&id_sel) { v.push(id_sel.clone()); } } else { v.retain(|x| x != &id_sel); } });
                                    }/></td>
                                    <td>{s.subject.clone()}</td>
                                    <td class="mono">{s.login_ip.clone()}</td>
                                    <td class="mono">{created}</td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" on:click=move |_| { pending.set(vec![id_rev.clone()]); confirm_open.set(true); }>"失効"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th></th><th>"実行者"</th><th>"ログイン元"</th><th>"開始"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <ConfirmDialog title=Signal::derive(|| "失効の確認".to_string()) body=confirm_body open=confirm_open on_confirm=on_confirm/>
    }
}
