//! SSO federated provider management (S-SSO-01/02).

use super::nav::SsoNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::sso::{list_sso_providers, DeleteProvider, SaveProvider};
use leptos::prelude::*;
use magnetite_core::domains::sso::model::Provider;

#[component]
pub fn ProvidersPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let providers = Resource::new(move || reload.get(), |_| list_sso_providers());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let ptype = RwSignal::new("google".to_string());
    let issuer = RwSignal::new(String::new());
    let client_id = RwSignal::new(String::new());
    let secret = RwSignal::new(String::new());
    let authorize_url = RwSignal::new(String::new());
    let token_url = RwSignal::new(String::new());
    let userinfo_url = RwSignal::new(String::new());
    let scopes = RwSignal::new("openid, profile, email".to_string());
    let redirect_uri = RwSignal::new(String::new());
    let auto_provision = RwSignal::new(false);
    let enabled = RwSignal::new(true);

    let open_create = move |_| {
        edit_id.set(String::new());
        name.set(String::new());
        ptype.set("google".into());
        issuer.set(String::new());
        client_id.set(String::new());
        secret.set(String::new());
        authorize_url.set(String::new());
        token_url.set(String::new());
        userinfo_url.set(String::new());
        scopes.set("openid, profile, email".into());
        redirect_uri.set(String::new());
        auto_provision.set(false);
        enabled.set(true);
        form_open.set(true);
    };
    let open_edit = move |p: Provider| {
        edit_id.set(p.id.clone());
        name.set(p.name.clone());
        ptype.set(p.provider_type.clone());
        issuer.set(p.issuer.clone().unwrap_or_default());
        client_id.set(p.client_id.clone());
        secret.set(String::new());
        authorize_url.set(p.authorize_url.clone().unwrap_or_default());
        token_url.set(p.token_url.clone().unwrap_or_default());
        userinfo_url.set(p.userinfo_url.clone().unwrap_or_default());
        scopes.set(p.scopes.join(", "));
        redirect_uri.set(p.redirect_uri.clone());
        auto_provision.set(p.auto_provision);
        enabled.set(p.enabled);
        form_open.set(true);
    };

    let save = ServerAction::<SaveProvider>::new();
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
    let opt = |s: String| {
        let t = s.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let now = chrono::Utc::now();
        let scope_list: Vec<String> = scopes
            .get()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let provider = Provider {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            name: name.get(),
            provider_type: ptype.get(),
            issuer: opt(issuer.get()),
            client_id: client_id.get(),
            has_secret: false,
            authorize_url: opt(authorize_url.get()),
            token_url: opt(token_url.get()),
            userinfo_url: opt(userinfo_url.get()),
            scopes: scope_list,
            redirect_uri: redirect_uri.get(),
            auto_provision: auto_provision.get(),
            enabled: enabled.get(),
        };
        save.dispatch(SaveProvider {
            provider,
            secret: secret.get(),
        });
    };

    let delete = ServerAction::<DeleteProvider>::new();
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
        Some((_, n)) => format!("プロバイダ「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, name)) = delete_target.get() {
            delete.dispatch(DeleteProvider { id, name });
        }
    });

    let is_custom = move || matches!(ptype.get().as_str(), "custom" | "oidc");

    view! {
        <PageHeader title=Signal::derive(|| "連携プロバイダ".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <SsoNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                providers.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "連携プロバイダが登録されていません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|p: Provider| {
                            let p_edit = p.clone();
                            let id_d = p.id.clone();
                            let name_d = p.name.clone();
                            let health = if p.enabled { "healthy" } else { "unknown" };
                            view! {
                                <tr>
                                    <td>{p.name.clone()}</td>
                                    <td>{p.provider_type.clone()}</td>
                                    <td class="mono">{p.client_id.clone()}</td>
                                    <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="編集" on:click=move |_| open_edit(p_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_d.clone(), name_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"表示名"</th><th>"種別"</th><th>"クライアントID"</th><th>"状態"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">{move || if edit_id.get().is_empty() { "プロバイダの作成" } else { "プロバイダの編集" }}</h2>
                    <label class="field"><span class="field-label">"表示名"</span><input class="input" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"種別"</span>
                        <select class="input" prop:value=move || ptype.get() on:change=move |ev| ptype.set(event_target_value(&ev))>
                            <option value="google">"Google"</option><option value="github">"GitHub"</option><option value="azure">"Azure"</option><option value="oidc">"OIDC"</option><option value="custom">"OIDCカスタム"</option>
                        </select></label>
                    <label class="field"><span class="field-label">"クライアントID"</span><input class="input" prop:value=move || client_id.get() on:input=move |ev| client_id.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"クライアントシークレット（編集時は空で据置）"</span><input class="input" type="password" prop:value=move || secret.get() on:input=move |ev| secret.set(event_target_value(&ev))/></label>
                    <Show when=is_custom fallback=|| ()>
                        <label class="field"><span class="field-label">"Issuer"</span><input class="input" prop:value=move || issuer.get() on:input=move |ev| issuer.set(event_target_value(&ev))/></label>
                        <label class="field"><span class="field-label">"認可URL"</span><input class="input" prop:value=move || authorize_url.get() on:input=move |ev| authorize_url.set(event_target_value(&ev))/></label>
                        <label class="field"><span class="field-label">"トークンURL"</span><input class="input" prop:value=move || token_url.get() on:input=move |ev| token_url.set(event_target_value(&ev))/></label>
                        <label class="field"><span class="field-label">"ユーザ情報URL"</span><input class="input" prop:value=move || userinfo_url.get() on:input=move |ev| userinfo_url.set(event_target_value(&ev))/></label>
                    </Show>
                    <label class="field"><span class="field-label">"スコープ（カンマ区切り）"</span><input class="input" prop:value=move || scopes.get() on:input=move |ev| scopes.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"リダイレクトURI"</span><input class="input" prop:value=move || redirect_uri.get() on:input=move |ev| redirect_uri.set(event_target_value(&ev))/></label>
                    <label class="field field-inline"><input type="checkbox" prop:checked=move || auto_provision.get() on:change=move |ev| auto_provision.set(event_target_checked(&ev))/><span>"自動プロビジョニング"</span></label>
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
