//! Logon-script management: list, create/replace (name + text content) and delete.
//! Scripts are stored in the replicated SYSVOL store and served over the NETLOGON
//! share; a user runs one by naming it in its `scriptPath` attribute.

use super::nav::AddcNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::addc::{
    list_logon_scripts, CreateLogonScript, DeleteLogonScript, LogonScript,
};
use leptos::prelude::*;

#[component]
pub fn LogonScriptsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let scripts = Resource::new(move || reload.get(), |_| list_logon_scripts());

    // Create/replace form.
    let form_open = RwSignal::new(false);
    let name = RwSignal::new(String::new());
    let content = RwSignal::new(String::new());
    let create = ServerAction::<CreateLogonScript>::new();
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
        name.set(String::new());
        content.set(String::new());
        save_error.set(None);
        form_open.set(true);
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateLogonScript {
            name: name.get(),
            content: content.get(),
        });
    };

    // Delete.
    let delete = ServerAction::<DeleteLogonScript>::new();
    let confirm_open = RwSignal::new(false);
    let delete_target = RwSignal::new(Option::<String>::None);
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
        Some(name) => format!("スクリプト「{name}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some(name) = delete_target.get() {
            delete.dispatch(DeleteLogonScript { name });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "ログオンスクリプト".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <AddcNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                scripts.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "ログオンスクリプトがありません。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|s: LogonScript| {
                            let name_d = s.name.clone();
                            view! {
                                <tr>
                                    <td class="mono">{s.name.clone()}</td>
                                    <td>{s.size}" bytes"</td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="削除"
                                            on:click=move |_| { delete_target.set(Some(name_d.clone())); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"名前"</th><th>"サイズ"</th><th>"操作"</th></tr></thead>
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
                    <h2 class="slideover-title">"ログオンスクリプトの作成"</h2>
                    <label class="field"><span class="field-label">"ファイル名（例: logon.bat）"</span>
                        <input class="input" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"内容"</span>
                        <textarea class="input" rows="10" prop:value=move || content.get() on:input=move |ev| content.set(event_target_value(&ev))/></label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || create.pending().get()>"保存"</button>
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
