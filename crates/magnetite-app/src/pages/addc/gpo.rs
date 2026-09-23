//! Group Policy (GPO) management: list, create (with machine registry settings)
//! and delete. Provisions the GPC (LDAP) + GPT (SYSVOL) halves via the AD DC
//! control-plane server functions.

use super::nav::AddcNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::addc::{list_gpos, CreateGpo, DeleteGpo, GpoSummary};
use leptos::prelude::*;
use magnetite_core::domains::addc::model::{GpoRegKind, GpoSettingInput};

/// Parse the settings textarea: one setting per non-empty line, fields separated
/// by `|` as `key | valueName | dword|sz | data`. Malformed lines are skipped.
fn parse_settings(text: &str) -> Vec<GpoSettingInput> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let parts: Vec<&str> = line.split('|').map(str::trim).collect();
            if parts.len() != 4 {
                return None;
            }
            let kind = match parts[2].to_lowercase().as_str() {
                "dword" => GpoRegKind::Dword,
                "sz" => GpoRegKind::Sz,
                _ => return None,
            };
            Some(GpoSettingInput {
                key: parts[0].to_string(),
                value_name: parts[1].to_string(),
                kind,
                data: parts[3].to_string(),
            })
        })
        .collect()
}

#[component]
pub fn GpoPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let gpos = Resource::new(move || reload.get(), |_| list_gpos());

    // Create form.
    let form_open = RwSignal::new(false);
    let display_name = RwSignal::new(String::new());
    let settings_text = RwSignal::new(String::new());
    let create = ServerAction::<CreateGpo>::new();
    let save_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = create.value().get() {
            match result {
                Ok(_) => {
                    save_error.set(None);
                    form_open.set(false);
                    toast.success("GPO を作成しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => save_error.set(Some(e.to_string())),
            }
        }
    });
    let open_create = move |_| {
        display_name.set(String::new());
        settings_text.set(String::new());
        save_error.set(None);
        form_open.set(true);
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateGpo {
            display_name: display_name.get(),
            settings: parse_settings(&settings_text.get()),
        });
    };

    // Delete.
    let delete = ServerAction::<DeleteGpo>::new();
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
        Some((_, name)) => format!("GPO「{name}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((guid, _)) = delete_target.get() {
            delete.dispatch(DeleteGpo { guid });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "グループポリシー".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <AddcNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                gpos.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "GPO がありません。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|g: GpoSummary| {
                            let guid_d = g.guid.clone();
                            let name_d = g.display_name.clone();
                            view! {
                                <tr>
                                    <td>{g.display_name.clone()}</td>
                                    <td class="mono">{g.guid.clone()}</td>
                                    <td>{g.version}</td>
                                    <td class="mono">{g.gpc_path.clone()}</td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="削除"
                                            on:click=move |_| { delete_target.set(Some((guid_d.clone(), name_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"名前"</th><th>"GUID"</th><th>"バージョン"</th><th>"SYSVOL パス"</th><th>"操作"</th></tr></thead>
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
                    <h2 class="slideover-title">"GPO の作成"</h2>
                    <label class="field"><span class="field-label">"表示名"</span>
                        <input class="input" prop:value=move || display_name.get() on:input=move |ev| display_name.set(event_target_value(&ev))/></label>
                    <label class="field">
                        <span class="field-label">"マシン設定（任意・1行1件）"</span>
                        <textarea class="input" rows="6" prop:value=move || settings_text.get() on:input=move |ev| settings_text.set(event_target_value(&ev))/>
                    </label>
                    <p class="field-hint">"形式: レジストリキー | 値名 | dword|sz | データ"</p>
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
