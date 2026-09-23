//! SSO active session management (S-SSO-05): list + single/bulk revoke (Admin).

use super::nav::SsoNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::sso::{list_sso_sessions, RevokeSsoSessions};
use leptos::prelude::*;
use magnetite_core::domains::sso::model::SsoSession;

#[component]
pub fn SessionsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let sessions = Resource::new(move || reload.get(), |_| list_sso_sessions());
    let selected = RwSignal::new(Vec::<String>::new());

    let revoke = ServerAction::<RevokeSsoSessions>::new();
    let confirm_open = RwSignal::new(false);
    // Pending set of ids to revoke on confirm.
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
            "このセッションを失効します。対象ユーザは再ログインが必要になります。よろしいですか？"
                .to_string()
        } else {
            format!("選択した {n} 件のセッションを失効します。よろしいですか？")
        }
    });
    let on_confirm = Callback::new(move |_| {
        let ids = pending.get();
        if !ids.is_empty() {
            revoke.dispatch(RevokeSsoSessions { ids });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "アクティブセッション".to_string())>
            <button class="btn btn-danger btn-sm" prop:disabled=move || selected.get().is_empty()
                on:click=move |_| { pending.set(selected.get()); confirm_open.set(true); }>"選択を失効"</button>
        </PageHeader>
        <SsoNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                sessions.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "アクティブなセッションはありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|s: SsoSession| {
                            let id_sel = s.id.clone();
                            let id_rev = s.id.clone();
                            let issued = s.issued_at.format("%Y-%m-%d %H:%M").to_string();
                            let expires = s.expires_at.format("%Y-%m-%d %H:%M").to_string();
                            let checked = {
                                let id = s.id.clone();
                                move || selected.get().contains(&id)
                            };
                            view! {
                                <tr>
                                    <td><input type="checkbox" prop:checked=checked on:change=move |ev| {
                                        let on = event_target_checked(&ev);
                                        selected.update(|v| { if on { if !v.contains(&id_sel) { v.push(id_sel.clone()); } } else { v.retain(|x| x != &id_sel); } });
                                    }/></td>
                                    <td>{s.subject.clone()}</td>
                                    <td class="mono">{s.ip_address.clone().unwrap_or_default()}</td>
                                    <td class="mono">{issued}</td>
                                    <td class="mono">{expires}</td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" on:click=move |_| { pending.set(vec![id_rev.clone()]); confirm_open.set(true); }>"失効"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th></th><th>"ユーザ"</th><th>"IP"</th><th>"発行"</th><th>"期限"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <ConfirmDialog title=Signal::derive(|| "失効の確認".to_string()) body=confirm_body open=confirm_open on_confirm=on_confirm/>
    }
}
