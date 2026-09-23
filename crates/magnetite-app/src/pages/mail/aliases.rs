//! Mail alias management (S-MAIL-04). Destinations must be existing mail users
//! (AC-16, checked server-side).

use super::nav::MailNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::mail::{list_aliases, list_mail_domains, DeleteAlias, SaveAlias};
use leptos::prelude::*;
use magnetite_core::domains::mail::model::Alias;

#[component]
pub fn AliasesPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let aliases = Resource::new(move || reload.get(), |_| list_aliases());
    let domains = Resource::new(|| (), |_| list_mail_domains());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let source = RwSignal::new(String::new());
    let domain = RwSignal::new(String::new());
    let destinations = RwSignal::new(String::new());
    let enabled = RwSignal::new(true);

    let open_create = move |_| {
        edit_id.set(String::new());
        source.set(String::new());
        destinations.set(String::new());
        enabled.set(true);
        form_open.set(true);
    };
    let open_edit = move |a: Alias| {
        edit_id.set(a.id.clone());
        source.set(a.source_address.clone());
        domain.set(a.domain_ref.clone());
        destinations.set(a.destination_addresses.join(", "));
        enabled.set(a.enabled);
        form_open.set(true);
    };

    let save = ServerAction::<SaveAlias>::new();
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
        let dests: Vec<String> = destinations
            .get()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let now = chrono::Utc::now();
        let alias = Alias {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            source_address: source.get(),
            domain_ref: domain.get(),
            destination_addresses: dests,
            enabled: enabled.get(),
        };
        save.dispatch(SaveAlias { alias });
    };

    let delete = ServerAction::<DeleteAlias>::new();
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
        Some((_, s)) => format!("エイリアス「{s}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = delete_target.get() {
            delete.dispatch(DeleteAlias { id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "エイリアス".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <MailNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                aliases.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "エイリアスがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|a| {
                            let a_edit = a.clone();
                            let src = a.source_address.clone();
                            let id = a.id.clone();
                            let dests = a.destination_addresses.join(", ");
                            view! {
                                <tr>
                                    <td class="mono">{a.source_address.clone()}</td>
                                    <td class="mono">{dests}</td>
                                    <td>{a.domain_ref.clone()}</td>
                                    <td>{if a.enabled { "有効" } else { "無効" }}</td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="編集" on:click=move |_| open_edit(a_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id.clone(), src.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"転送元"</th><th>"転送先"</th><th>"ドメイン"</th><th>"状態"</th><th>"操作"</th></tr></thead>
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
                    <h2 class="slideover-title">{move || if edit_id.get().is_empty() { "エイリアスの作成" } else { "エイリアスの編集" }}</h2>
                    <label class="field"><span class="field-label">"転送元アドレス"</span>
                        <input class="input" prop:value=move || source.get() on:input=move |ev| source.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"ドメイン"</span>
                        <select class="input" on:change=move |ev| domain.set(event_target_value(&ev)) prop:value=move || domain.get()>
                            <option value="">"（選択）"</option>
                            <Suspense fallback=|| ()>
                                {move || domains.get().map(|res| res.unwrap_or_default().into_iter().map(|d| { let n = d.name.clone(); view! { <option value=d.name>{n}</option> } }).collect_view())}
                            </Suspense>
                        </select>
                    </label>
                    <label class="field"><span class="field-label">"転送先（カンマ区切り）"</span>
                        <input class="input" prop:value=move || destinations.get() on:input=move |ev| destinations.set(event_target_value(&ev))/></label>
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
