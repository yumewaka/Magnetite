//! LDAP user management (S-LDAP-03): list, create, enable/disable, delete and
//! the Admin-only password reset.

use super::nav::LdapNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::auth::get_current_user;
use crate::server_fns::ldap::{
    list_parents, list_users, CreateUser, DeleteEntry, ResetPassword, ToggleUser,
};
use leptos::prelude::*;
use magnetite_core::authz::Role;
use magnetite_core::domains::ldap::model::LdapUser;

#[component]
pub fn UsersPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let users = Resource::new(move || reload.get(), |_| list_users());
    let parents = Resource::new(|| (), |_| list_parents());
    let me = Resource::new(|| (), |_| get_current_user());
    let is_admin = move || matches!(me.get(), Some(Ok(Some(u))) if u.role == Role::Admin);

    // Create form.
    let form_open = RwSignal::new(false);
    let parent_dn = RwSignal::new(String::new());
    let uid = RwSignal::new(String::new());
    let cn = RwSignal::new(String::new());
    let sn = RwSignal::new(String::new());
    let mail = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    // Optional migration inputs: an explicit RID (inherit the old domain's exact SID) and
    // an NT hash to import when the plaintext password is unknown.
    let rid = RwSignal::new(String::new());
    let nt_hash = RwSignal::new(String::new());
    let kerberos_key = RwSignal::new(String::new());
    let create = ServerAction::<CreateUser>::new();
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
        uid.set(String::new());
        cn.set(String::new());
        sn.set(String::new());
        mail.set(String::new());
        password.set(String::new());
        rid.set(String::new());
        nt_hash.set(String::new());
        kerberos_key.set(String::new());
        save_error.set(None);
        form_open.set(true);
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateUser {
            parent_dn: parent_dn.get(),
            uid: uid.get(),
            cn: cn.get(),
            sn: sn.get(),
            mail: mail.get(),
            password: password.get(),
            rid: rid.get().trim().parse::<u32>().ok(),
            nt_hash: nt_hash.get(),
            kerberos_key: kerberos_key.get(),
        });
    };

    // Toggle enabled.
    let toggle = ServerAction::<ToggleUser>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = toggle.value().get() {
            toast.success("更新しました。");
            reload.update(|n| *n += 1);
        }
    });

    // Delete.
    let delete = ServerAction::<DeleteEntry>::new();
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
        Some((_, uid)) => format!("ユーザ「{uid}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((dn, _)) = delete_target.get() {
            delete.dispatch(DeleteEntry { dn });
        }
    });

    // Password reset modal (Admin).
    let reset = ServerAction::<ResetPassword>::new();
    let reset_open = RwSignal::new(false);
    let reset_dn = RwSignal::new(String::new());
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
        reset.dispatch(ResetPassword {
            dn: reset_dn.get(),
            new_password: reset_pw.get(),
        });
    };

    view! {
        <PageHeader title=Signal::derive(|| "LDAP ユーザ".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <LdapNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                users.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "ユーザがありません。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let admin = is_admin();
                        let rows = list.into_iter().map(|u: LdapUser| {
                            let health = if u.enabled { "healthy" } else { "error" };
                            let dn_t = u.dn.clone();
                            let uid_t = u.uid.clone();
                            let dn_r = u.dn.clone();
                            let dn_reset = u.dn.clone();
                            let enabled = u.enabled;
                            view! {
                                <tr>
                                    <td class="mono">{u.uid.clone()}</td>
                                    <td>{u.cn.clone()}</td>
                                    <td>{u.mail.clone().unwrap_or_default()}</td>
                                    <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm"
                                            on:click=move |_| { toggle.dispatch(ToggleUser { dn: dn_t.clone(), enabled: !enabled }); }>
                                            {if enabled { "無効化" } else { "有効化" }}
                                        </button>
                                        <Show when=move || admin fallback=|| ()>
                                            <button class="btn btn-secondary btn-sm"
                                                on:click={
                                                    let dn = dn_reset.clone();
                                                    move |_| { reset_dn.set(dn.clone()); reset_pw.set(String::new()); reset_error.set(None); reset_open.set(true); }
                                                }>"PWリセット"</button>
                                        </Show>
                                        <button class="icon-button" title="削除"
                                            on:click=move |_| {
                                                delete_target.set(Some((dn_r.clone(), uid_t.clone())));
                                                confirm_open.set(true);
                                            }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"uid"</th><th>"CN"</th><th>"メール"</th><th>"状態"</th><th>"操作"</th></tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                        }.into_any()
                    }
                })
            }}
        </Suspense>

        // Create slide-over.
        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">"ユーザの作成"</h2>
                    <label class="field">
                        <span class="field-label">"親 DN"</span>
                        <select class="input" on:change=move |ev| parent_dn.set(event_target_value(&ev)) prop:value=move || parent_dn.get()>
                            <Suspense fallback=|| ()>
                                {move || parents.get().map(|res| res.unwrap_or_default().into_iter().map(|dn| {
                                    let label = dn.clone();
                                    view! { <option value=dn>{label}</option> }
                                }).collect_view())}
                            </Suspense>
                        </select>
                    </label>
                    {field("uid", uid)}
                    {field("CN", cn)}
                    {field("姓 (sn)", sn)}
                    {field("メール（任意）", mail)}
                    <label class="field">
                        <span class="field-label">"パスワード（Windows ログオン用）"</span>
                        <input class="input" type="password" autocomplete="new-password"
                            prop:value=move || password.get() on:input=move |ev| password.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">"RID（任意・旧ドメイン SID 引継ぎ）"</span>
                        <input class="input" inputmode="numeric" placeholder="自動採番"
                            prop:value=move || rid.get() on:input=move |ev| rid.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">"NT ハッシュ（任意・16進32文字で取り込み）"</span>
                        <input class="input" autocomplete="off" placeholder="平文不明の移行アカウント用"
                            prop:value=move || nt_hash.get() on:input=move |ev| nt_hash.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">"Kerberos 鍵（任意・AES256 16進64文字）"</span>
                        <input class="input" autocomplete="off" placeholder="旧ADからDCSyncした鍵（NTハッシュと併用）"
                            prop:value=move || kerberos_key.get() on:input=move |ev| kerberos_key.set(event_target_value(&ev))/>
                    </label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || create.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        // Password reset modal.
        <Show when=move || reset_open.get() fallback=|| ()>
            <div class="modal-overlay" on:click=move |_| reset_open.set(false)>
                <form class="modal" on:click=|ev| ev.stop_propagation() on:submit=submit_reset>
                    <h2 class="modal-title">"パスワードのリセット"</h2>
                    <p class="mono">{move || reset_dn.get()}</p>
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

        <ConfirmDialog
            title=Signal::derive(|| "削除の確認".to_string())
            body=confirm_body
            open=confirm_open
            on_confirm=on_confirm_delete
        />
    }
}

fn field(label: &'static str, sig: RwSignal<String>) -> impl IntoView {
    view! {
        <label class="field">
            <span class="field-label">{label}</span>
            <input class="input" prop:value=move || sig.get()
                on:input=move |ev| sig.set(event_target_value(&ev))/>
        </label>
    }
}
