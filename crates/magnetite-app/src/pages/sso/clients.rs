//! SSO OIDC client management (S-SSO-03/04). Includes one-time secret display
//! on regeneration (E-S05).

use super::nav::SsoNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::sso::{
    list_oidc_clients, DeleteOidcClient, RegenerateClientSecret, SaveOidcClient,
};
use leptos::prelude::*;
use magnetite_core::domains::sso::model::OidcClient;

const GRANTS: [&str; 3] = ["authorization_code", "refresh_token", "client_credentials"];

#[component]
pub fn ClientsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let clients = Resource::new(move || reload.get(), |_| list_oidc_clients());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let client_name = RwSignal::new(String::new());
    let client_type = RwSignal::new("confidential".to_string());
    let grant_types = RwSignal::new(vec!["authorization_code".to_string()]);
    let redirect_uris = RwSignal::new(String::new());
    let scopes = RwSignal::new("openid".to_string());
    let auth_method = RwSignal::new("client_secret_basic".to_string());
    let enabled = RwSignal::new(true);

    let open_create = move |_| {
        edit_id.set(String::new());
        client_name.set(String::new());
        client_type.set("confidential".into());
        grant_types.set(vec!["authorization_code".into()]);
        redirect_uris.set(String::new());
        scopes.set("openid".into());
        auth_method.set("client_secret_basic".into());
        enabled.set(true);
        form_open.set(true);
    };
    let open_edit = move |c: OidcClient| {
        edit_id.set(c.id.clone());
        client_name.set(c.client_name.clone());
        client_type.set(c.client_type.clone());
        grant_types.set(c.grant_types.clone());
        redirect_uris.set(c.redirect_uris.join(", "));
        scopes.set(c.scopes.join(", "));
        auth_method.set(c.token_endpoint_auth_method.clone());
        enabled.set(c.enabled);
        form_open.set(true);
    };

    let save = ServerAction::<SaveOidcClient>::new();
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
        let uris: Vec<String> = redirect_uris
            .get()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let scope_list: Vec<String> = scopes
            .get()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let client = OidcClient {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            client_name: client_name.get(),
            client_id: String::new(),
            has_secret: false,
            client_type: client_type.get(),
            grant_types: grant_types.get(),
            response_types: vec!["code".into()],
            redirect_uris: uris,
            scopes: scope_list,
            token_endpoint_auth_method: auth_method.get(),
            provider_ref: None,
            enabled: enabled.get(),
        };
        save.dispatch(SaveOidcClient { client });
    };

    // Secret regeneration (Admin), shown once.
    let regen = ServerAction::<RegenerateClientSecret>::new();
    let new_secret = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = regen.value().get() {
            match result {
                Ok(secret) => {
                    new_secret.set(Some(secret));
                    reload.update(|n| *n += 1);
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });

    // Delete.
    let delete = ServerAction::<DeleteOidcClient>::new();
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
        Some((_, n)) => format!("クライアント「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, client_id)) = delete_target.get() {
            delete.dispatch(DeleteOidcClient { id, client_id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "OIDCクライアント".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 登録"</button>
        </PageHeader>
        <SsoNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                clients.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "クライアントがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|c: OidcClient| {
                            let c_edit = c.clone();
                            let id_regen = c.id.clone();
                            let id_del = c.id.clone();
                            let cid_del = c.client_id.clone();
                            let health = if c.enabled { "healthy" } else { "unknown" };
                            view! {
                                <tr>
                                    <td>{c.client_name.clone()}</td>
                                    <td class="mono">{c.client_id.clone()}</td>
                                    <td>{c.client_type.clone()}</td>
                                    <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" on:click=move |_| { regen.dispatch(RegenerateClientSecret { id: id_regen.clone() }); }>"再発行"</button>
                                        <button class="icon-button" title="編集" on:click=move |_| open_edit(c_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_del.clone(), cid_del.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"クライアント名"</th><th>"クライアントID"</th><th>"種別"</th><th>"状態"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">{move || if edit_id.get().is_empty() { "クライアントの登録" } else { "クライアントの編集" }}</h2>
                    <label class="field"><span class="field-label">"クライアント名"</span><input class="input" prop:value=move || client_name.get() on:input=move |ev| client_name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"種別"</span>
                        <select class="input" prop:value=move || client_type.get() on:change=move |ev| client_type.set(event_target_value(&ev))>
                            <option value="confidential">"機密 (confidential)"</option><option value="public">"公開 (public)"</option>
                        </select></label>
                    <span class="field-label">"グラント種別"</span>
                    <div class="grant-picker">
                        {GRANTS.into_iter().map(|g| {
                            let gs = g.to_string();
                            let checked = move || grant_types.get().iter().any(|x| x == g);
                            view! {
                                <label class="host-check">
                                    <input type="checkbox" prop:checked=checked on:change=move |ev| {
                                        let on = event_target_checked(&ev);
                                        grant_types.update(|v| { if on { if !v.contains(&gs) { v.push(gs.clone()); } } else { v.retain(|x| x != &gs); } });
                                    }/>
                                    <span class="mono">{g}</span>
                                </label>
                            }
                        }).collect_view()}
                    </div>
                    <label class="field"><span class="field-label">"リダイレクトURI（カンマ区切り）"</span><input class="input" prop:value=move || redirect_uris.get() on:input=move |ev| redirect_uris.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"スコープ（カンマ区切り）"</span><input class="input" prop:value=move || scopes.get() on:input=move |ev| scopes.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"トークンEP認証方式"</span>
                        <select class="input" prop:value=move || auth_method.get() on:change=move |ev| auth_method.set(event_target_value(&ev))>
                            <option value="client_secret_basic">"client_secret_basic"</option><option value="client_secret_post">"client_secret_post"</option><option value="none">"none"</option>
                        </select></label>
                    <label class="field field-inline"><input type="checkbox" prop:checked=move || enabled.get() on:change=move |ev| enabled.set(event_target_checked(&ev))/><span>"有効"</span></label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || save.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        // One-time secret display.
        <Show when=move || new_secret.get().is_some() fallback=|| ()>
            <div class="modal-overlay" on:click=move |_| new_secret.set(None)>
                <div class="modal" on:click=|ev| ev.stop_propagation()>
                    <h2 class="modal-title">"新しいクライアントシークレット"</h2>
                    <p>"この値は一度だけ表示されます。安全に保管してください。"</p>
                    <p class="mono secret-value">{move || new_secret.get().unwrap_or_default()}</p>
                    <div class="modal-actions">
                        <button type="button" class="btn btn-primary" on:click=move |_| new_secret.set(None)>"閉じる"</button>
                    </div>
                </div>
            </div>
        </Show>

        <ConfirmDialog title=Signal::derive(|| "削除の確認".to_string()) body=confirm_body open=confirm_open on_confirm=on_confirm_delete/>
    }
}
