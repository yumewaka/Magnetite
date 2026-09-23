//! Forward-proxy management: source/destination access rules (allow/deny,
//! priority-ordered) and client credentials (HTTP proxy Basic auth). The forward
//! proxy listens on its own port (`domains.proxy.server.forward_listen`); these
//! screens configure who may use it and where it may connect.

use super::nav::ProxyNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::proxy::{
    list_forward_rules, list_forward_users, CreateForwardUser, DeleteForwardRule,
    DeleteForwardUser, SaveForwardRule, ToggleForwardRule, ToggleForwardUser,
};
use leptos::prelude::*;
use magnetite_core::domains::proxy::model::{AclAction, ForwardRule, ForwardRuleKind, ForwardUser};

#[component]
pub fn ForwardPage() -> impl IntoView {
    view! {
        <PageHeader title=Signal::derive(|| "フォワードプロキシ".to_string())/>
        <ProxyNav/>
        <p class="page-intro">
            "フォワードプロキシは専用ポート（"<code>"forward_listen"</code>"）で待ち受け、"
            "送信元ルールで利用できるクライアントを、宛先ルールで接続先を制限します。"
            "クライアント認証ユーザを1つ以上登録すると、"<code>"Proxy-Authorization"</code>
            " による Basic 認証が必須になります。"
        </p>
        <ForwardRulesSection/>
        <ForwardUsersSection/>
    }
}

#[component]
fn ForwardRulesSection() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let rules = Resource::new(move || reload.get(), |_| list_forward_rules());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let kind = RwSignal::new("source".to_string());
    let matcher = RwSignal::new(String::new());
    let action = RwSignal::new("allow".to_string());
    let priority = RwSignal::new("0".to_string());
    let enabled = RwSignal::new(true);
    let description = RwSignal::new(String::new());

    let open_create = move |_| {
        edit_id.set(String::new());
        kind.set("source".into());
        matcher.set(String::new());
        action.set("allow".into());
        priority.set("0".into());
        enabled.set(true);
        description.set(String::new());
        form_open.set(true);
    };
    let open_edit = move |r: ForwardRule| {
        edit_id.set(r.id.clone());
        kind.set(r.kind.as_str().into());
        matcher.set(r.matcher.clone());
        action.set(r.action.as_str().into());
        priority.set(r.priority.to_string());
        enabled.set(r.enabled);
        description.set(r.description.clone().unwrap_or_default());
        form_open.set(true);
    };

    let save = ServerAction::<SaveForwardRule>::new();
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
        let rule = ForwardRule {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            kind: ForwardRuleKind::from_str(&kind.get()),
            matcher: matcher.get(),
            action: AclAction::from_str(&action.get()),
            priority: priority.get().trim().parse::<i32>().unwrap_or(0),
            enabled: enabled.get(),
            description: {
                let d = description.get();
                (!d.trim().is_empty()).then_some(d)
            },
        };
        save.dispatch(SaveForwardRule { rule });
    };

    let toggle = ServerAction::<ToggleForwardRule>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = toggle.value().get() {
            toast.success("保存しました。");
            reload.update(|n| *n += 1);
        }
    });

    let delete = ServerAction::<DeleteForwardRule>::new();
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
        Some((_, m)) => format!("ルール「{m}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = delete_target.get() {
            delete.dispatch(DeleteForwardRule { id });
        }
    });

    view! {
        <div class="section-head">
            <h2 class="panel-title">"アクセスルール"</h2>
            <button class="btn btn-primary" on:click=open_create>"＋ ルール作成"</button>
        </div>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                rules.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "ルールがありません（既定は全て許可）。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|r: ForwardRule| {
                            let r_edit = r.clone();
                            let id_tog = r.id.clone();
                            let id_del = r.id.clone();
                            let matcher_del = r.matcher.clone();
                            let en = r.enabled;
                            let (acls, alabel) = if r.action == AclAction::Deny { ("badge badge-danger", "Deny") } else { ("badge badge-success", "Allow") };
                            let kind_label = if r.kind == ForwardRuleKind::Source { "送信元" } else { "宛先" };
                            view! {
                                <tr>
                                    <td>{kind_label}</td>
                                    <td class="mono">{r.matcher.clone()}</td>
                                    <td><span class=acls>{alabel}</span></td>
                                    <td>{r.priority}</td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" on:click=move |_| { toggle.dispatch(ToggleForwardRule { id: id_tog.clone(), enabled: !en }); }>{if en { "無効化" } else { "有効化" }}</button>
                                        <button class="icon-button" title="編集" on:click=move |_| open_edit(r_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_del.clone(), matcher_del.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"種別"</th><th>"マッチャ"</th><th>"アクション"</th><th>"優先度"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">{move || if edit_id.get().is_empty() { "ルールの作成" } else { "ルールの編集" }}</h2>
                    <label class="field"><span class="field-label">"種別"</span><select class="input" prop:value=move || kind.get() on:change=move |ev| kind.set(event_target_value(&ev))><option value="source">"送信元 (クライアント IP / CIDR)"</option><option value="destination">"宛先 (ホスト / .ドメイン / *)"</option></select></label>
                    <label class="field"><span class="field-label">{move || if kind.get() == "source" { "CIDR（例: 10.0.0.0/8）" } else { "ホスト（例: .example.com, *）" }}</span><input class="input" prop:value=move || matcher.get() on:input=move |ev| matcher.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"アクション"</span><select class="input" prop:value=move || action.get() on:change=move |ev| action.set(event_target_value(&ev))><option value="allow">"Allow"</option><option value="deny">"Deny"</option></select></label>
                    <label class="field"><span class="field-label">"優先度（小さいほど先に評価）"</span><input class="input" type="number" prop:value=move || priority.get() on:input=move |ev| priority.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"説明（任意）"</span><input class="input" prop:value=move || description.get() on:input=move |ev| description.set(event_target_value(&ev))/></label>
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

#[component]
fn ForwardUsersSection() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let users = Resource::new(move || reload.get(), |_| list_forward_users());

    let form_open = RwSignal::new(false);
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());

    let create = ServerAction::<CreateForwardUser>::new();
    let save_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = create.value().get() {
            match result {
                Ok(()) => {
                    save_error.set(None);
                    form_open.set(false);
                    toast.success("作成しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => save_error.set(Some(e.to_string())),
            }
        }
    });
    let open_create = move |_| {
        username.set(String::new());
        password.set(String::new());
        description.set(String::new());
        save_error.set(None);
        form_open.set(true);
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateForwardUser {
            username: username.get(),
            password: password.get(),
            description: description.get(),
        });
    };

    let toggle = ServerAction::<ToggleForwardUser>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = toggle.value().get() {
            toast.success("保存しました。");
            reload.update(|n| *n += 1);
        }
    });

    let delete = ServerAction::<DeleteForwardUser>::new();
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
        Some((_, u)) => format!("ユーザ「{u}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = delete_target.get() {
            delete.dispatch(DeleteForwardUser { id });
        }
    });

    view! {
        <div class="section-head">
            <h2 class="panel-title">"クライアント認証ユーザ"</h2>
            <button class="btn btn-primary" on:click=open_create>"＋ ユーザ作成"</button>
        </div>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                users.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "ユーザがありません（認証は無効）。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|u: ForwardUser| {
                            let id_tog = u.id.clone();
                            let id_del = u.id.clone();
                            let name_del = u.username.clone();
                            let en = u.enabled;
                            let (badge, blabel) = if en { ("badge badge-success", "有効") } else { ("badge badge-unknown", "無効") };
                            view! {
                                <tr>
                                    <td class="mono">{u.username.clone()}</td>
                                    <td>{u.description.clone().unwrap_or_default()}</td>
                                    <td><span class=badge>{blabel}</span></td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" on:click=move |_| { toggle.dispatch(ToggleForwardUser { id: id_tog.clone(), enabled: !en }); }>{if en { "無効化" } else { "有効化" }}</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_del.clone(), name_del.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"ユーザ名"</th><th>"説明"</th><th>"状態"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">"認証ユーザの作成"</h2>
                    <label class="field"><span class="field-label">"ユーザ名"</span><input class="input" prop:value=move || username.get() on:input=move |ev| username.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"パスワード"</span><input class="input" type="password" prop:value=move || password.get() on:input=move |ev| password.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"説明（任意）"</span><input class="input" prop:value=move || description.get() on:input=move |ev| description.set(event_target_value(&ev))/></label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || create.pending().get()>"作成"</button>
                    </div>
                </form>
            </div>
        </Show>

        <ConfirmDialog title=Signal::derive(|| "削除の確認".to_string()) body=confirm_body open=confirm_open on_confirm=on_confirm_delete/>
    }
}
