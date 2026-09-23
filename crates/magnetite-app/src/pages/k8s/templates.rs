//! K8s manifest template management (S-K8S-06). YAML editor with a light
//! structural check.

use super::nav::K8sNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::k8s::{list_k8s_templates, DeleteK8sTemplate, SaveK8sTemplate};
use leptos::prelude::*;
use magnetite_core::domains::k8s::model::{K8sResourceKind, K8sTemplate};

#[component]
pub fn TemplatesPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let templates = Resource::new(move || reload.get(), |_| list_k8s_templates());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    let resource_kind = RwSignal::new("Deployment".to_string());
    let manifest_yaml = RwSignal::new(String::new());

    let open_create = move |_| {
        edit_id.set(String::new());
        name.set(String::new());
        description.set(String::new());
        resource_kind.set("Deployment".into());
        manifest_yaml.set(String::new());
        form_open.set(true);
    };
    let open_edit = move |t: K8sTemplate| {
        edit_id.set(t.id.clone());
        name.set(t.name.clone());
        description.set(t.description.clone().unwrap_or_default());
        resource_kind.set(t.resource_kind.as_str().into());
        manifest_yaml.set(t.manifest_yaml.clone());
        form_open.set(true);
    };

    let save = ServerAction::<SaveK8sTemplate>::new();
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
        let template = K8sTemplate {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            name: name.get(),
            description: {
                let d = description.get();
                if d.trim().is_empty() {
                    None
                } else {
                    Some(d)
                }
            },
            resource_kind: K8sResourceKind::from_str(&resource_kind.get()),
            manifest_yaml: manifest_yaml.get(),
        };
        save.dispatch(SaveK8sTemplate { template });
    };

    let delete = ServerAction::<DeleteK8sTemplate>::new();
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
        Some((_, n)) => format!("テンプレート「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = delete_target.get() {
            delete.dispatch(DeleteK8sTemplate { id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "マニフェストテンプレート".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <K8sNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                templates.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "テンプレートがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|t: K8sTemplate| {
                            let t_edit = t.clone();
                            let id_d = t.id.clone();
                            let name_d = t.name.clone();
                            view! {
                                <tr>
                                    <td>{t.name.clone()}</td>
                                    <td>{t.description.clone().unwrap_or_default()}</td>
                                    <td>{t.resource_kind.as_str()}</td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="編集" on:click=move |_| open_edit(t_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_d.clone(), name_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"名称"</th><th>"説明"</th><th>"リソース種別"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">{move || if edit_id.get().is_empty() { "テンプレートの作成" } else { "テンプレートの編集" }}</h2>
                    <label class="field"><span class="field-label">"名称"</span><input class="input" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"説明（任意）"</span><input class="input" prop:value=move || description.get() on:input=move |ev| description.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"リソース種別"</span>
                        <select class="input" prop:value=move || resource_kind.get() on:change=move |ev| resource_kind.set(event_target_value(&ev))>
                            <option value="Deployment">"Deployment"</option><option value="Service">"Service"</option><option value="ConfigMap">"ConfigMap"</option><option value="Job">"Job"</option>
                        </select></label>
                    <label class="field"><span class="field-label">"マニフェスト YAML"</span><textarea class="input mono" rows="12" prop:value=move || manifest_yaml.get() on:input=move |ev| manifest_yaml.set(event_target_value(&ev))></textarea></label>
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
