//! Cross-cutting backup / restore (S-Backup / F-06, Admin for mutations). List
//! is visible to everyone; create / restore / delete are Admin-only and go
//! through a confirm dialog. Restore is destructive.

use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::auth::get_current_user;
use crate::server_fns::backup::{list_backups, CreateBackup, DeleteBackup, RestoreBackup};
use leptos::prelude::*;
use magnetite_core::authz::Role;
use magnetite_core::domain::DomainKey;
use magnetite_core::i18n::use_i18n;
use magnetite_core::models::common::BackupKind;
use magnetite_core::models::Backup;

fn human_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn domain_label(key: DomainKey, i18n: magnetite_core::i18n::I18nContext) -> String {
    if key == DomainKey::Portal {
        "全ドメイン".to_string()
    } else {
        i18n.t(key.label_key()).to_string()
    }
}

#[component]
pub fn BackupPage() -> impl IntoView {
    let i18n = use_i18n();
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let filter = RwSignal::new(String::new());
    let me = Resource::new(|| (), |_| get_current_user());
    let is_admin = move || matches!(me.get(), Some(Ok(Some(u))) if u.role == Role::Admin);

    let backups = Resource::new(
        move || (reload.get(), filter.get()),
        |(_, domain)| list_backups(domain),
    );

    // Create.
    let form_open = RwSignal::new(false);
    let create_domain = RwSignal::new("portal".to_string());
    let create = ServerAction::<CreateBackup>::new();
    Effect::new(move |_| {
        if let Some(result) = create.value().get() {
            match result {
                Ok(()) => {
                    form_open.set(false);
                    toast.success("バックアップを作成しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });
    let submit_create = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateBackup {
            domain: create_domain.get(),
        });
    };

    // Restore.
    let restore = ServerAction::<RestoreBackup>::new();
    let restore_open = RwSignal::new(false);
    let restore_target = RwSignal::new(Option::<(String, String)>::None);
    Effect::new(move |_| {
        if let Some(result) = restore.value().get() {
            match result {
                Ok(()) => {
                    toast.success("リストアしました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });
    Effect::new(move |_| {
        if !restore_open.get() {
            restore_target.set(None);
        }
    });
    let restore_body = Signal::derive(move || match restore_target.get() {
        Some((_, label)) => label,
        None => String::new(),
    });
    let on_confirm_restore = Callback::new(move |_| {
        if let Some((id, _)) = restore_target.get() {
            restore.dispatch(RestoreBackup { backup_id: id });
        }
    });

    // Delete.
    let delete = ServerAction::<DeleteBackup>::new();
    let delete_open = RwSignal::new(false);
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
        if !delete_open.get() {
            delete_target.set(None);
        }
    });
    let delete_body = Signal::derive(move || match delete_target.get() {
        Some(_) => "このバックアップを削除します。よろしいですか？".to_string(),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some(id) = delete_target.get() {
            delete.dispatch(DeleteBackup { backup_id: id });
        }
    });

    let domain_options = move || {
        DomainKey::DOMAINS
            .into_iter()
            .map(|d| {
                let value = d.as_str();
                let label = i18n.t(d.label_key());
                view! { <option value=value>{label}</option> }
            })
            .collect_view()
    };

    view! {
        <PageHeader title=Signal::derive(|| "バックアップ / リストア".to_string())/>

        <div class="audit-filters">
            <label class="filter">
                <span class="filter-label">"ドメイン"</span>
                <select class="input" prop:value=move || filter.get()
                    on:change=move |ev| filter.set(event_target_value(&ev))>
                    <option value="">"全対象"</option>
                    <option value="portal">"全ドメイン"</option>
                    {domain_options}
                </select>
            </label>
            <div class="tab-actions bulk-actions">
                <button class="btn btn-primary" prop:disabled=move || !is_admin()
                    on:click=move |_| { create_domain.set("portal".into()); form_open.set(true); }>"＋ 作成"</button>
            </div>
        </div>

        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                let admin = is_admin();
                backups.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "バックアップがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|b: Backup| {
                            let id_restore = b.meta.id.clone();
                            let id_delete = b.meta.id.clone();
                            let at = b.meta.created_at.format("%Y-%m-%d %H:%M").to_string();
                            let at_confirm = at.clone();
                            let target = domain_label(b.domain, i18n);
                            let target_confirm = target.clone();
                            let size = human_size(b.size_bytes);
                            let kind = match b.kind { BackupKind::Manual => "手動", BackupKind::Auto => "自動" };
                            view! {
                                <tr>
                                    <td class="mono">{at}</td>
                                    <td>{target}</td>
                                    <td class="mono">{size}</td>
                                    <td>{kind}</td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" prop:disabled=move || !admin title="リストア"
                                            on:click=move |_| {
                                                let msg = format!("{target_confirm}を {at_confirm} の状態にリストアします。現在の設定は上書きされます。よろしいですか？");
                                                restore_target.set(Some((id_restore.clone(), msg)));
                                                restore_open.set(true);
                                            }>"\u{27F2} リストア"</button>
                                        <button class="icon-button" prop:disabled=move || !admin title="削除"
                                            on:click=move |_| { delete_target.set(Some(id_delete.clone())); delete_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr><th>"作成日時"</th><th>"対象"</th><th>"サイズ"</th><th>"種別"</th><th>"操作"</th></tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                        }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit_create>
                    <h2 class="slideover-title">"バックアップの作成"</h2>
                    <label class="field">
                        <span class="field-label">"対象"</span>
                        <select class="input" prop:value=move || create_domain.get() on:change=move |ev| create_domain.set(event_target_value(&ev))>
                            <option value="portal">"全ドメイン"</option>
                            {domain_options}
                        </select>
                    </label>
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || create.pending().get()>"作成"</button>
                    </div>
                </form>
            </div>
        </Show>

        <ConfirmDialog title=Signal::derive(|| "リストアの確認".to_string()) body=restore_body open=restore_open on_confirm=on_confirm_restore/>
        <ConfirmDialog title=Signal::derive(|| "削除の確認".to_string()) body=delete_body open=delete_open on_confirm=on_confirm_delete/>
    }
}
