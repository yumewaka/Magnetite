//! Mail protocol settings (S-MAIL-06): the seven protocols' enabled/port, saved
//! as part of the server config.

use super::nav::MailNav;
use crate::components::toast::use_toast;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::mail::{get_mail_config, SaveMailConfig};
use leptos::prelude::*;
use magnetite_core::domains::mail::model::{MailProtocol, MailServerConfig, ProtocolConfig};
use std::collections::BTreeMap;

#[component]
pub fn ProtocolsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let config = Resource::new(move || reload.get(), |_| get_mail_config());

    // One (enabled, port) signal pair per protocol.
    let rows: Vec<(MailProtocol, RwSignal<bool>, RwSignal<String>)> = MailProtocol::ALL
        .into_iter()
        .map(|p| {
            (
                p,
                RwSignal::new(true),
                RwSignal::new(p.default_port().to_string()),
            )
        })
        .collect();
    let rows = StoredValue::new(rows);
    let loaded_cfg = RwSignal::new(Option::<MailServerConfig>::None);
    let populated = RwSignal::new(false);

    Effect::new(move |_| {
        if let Some(Ok(cfg)) = config.get() {
            if !populated.get() {
                for (p, en, port) in rows.get_value() {
                    if let Some(pc) = cfg.protocols.get(p.as_str()) {
                        en.set(pc.enabled);
                        port.set(pc.port.to_string());
                    }
                }
                loaded_cfg.set(Some(cfg));
                populated.set(true);
            }
        }
    });

    let save = ServerAction::<SaveMailConfig>::new();
    let save_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = save.value().get() {
            match result {
                Ok(()) => {
                    save_error.set(None);
                    toast.success("保存しました。");
                }
                Err(e) => save_error.set(Some(e.to_string())),
            }
        }
    });
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let Some(mut cfg) = loaded_cfg.get() else {
            return;
        };
        let mut protocols: BTreeMap<String, ProtocolConfig> = BTreeMap::new();
        for (p, en, port) in rows.get_value() {
            protocols.insert(
                p.as_str().to_string(),
                ProtocolConfig {
                    enabled: en.get(),
                    port: port.get().trim().parse::<u16>().unwrap_or(0),
                },
            );
        }
        cfg.protocols = protocols;
        save.dispatch(SaveMailConfig { config: cfg });
    };

    view! {
        <PageHeader title=Signal::derive(|| "プロトコル設定".to_string())/>
        <MailNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                config.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(_) => {
                        let protocol_rows = rows.get_value().into_iter().map(|(p, en, port)| {
                            view! {
                                <tr>
                                    <td>{p.label()}</td>
                                    <td><input type="checkbox" prop:checked=move || en.get() on:change=move |ev| en.set(event_target_checked(&ev))/></td>
                                    <td><input class="input port-input" type="number" prop:value=move || port.get() on:input=move |ev| port.set(event_target_value(&ev))/></td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <form on:submit=submit>
                                <table class="data-table">
                                    <thead><tr><th>"プロトコル"</th><th>"有効"</th><th>"ポート"</th></tr></thead>
                                    <tbody>{protocol_rows}</tbody>
                                </table>
                                {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                                <div class="slideover-actions">
                                    <button type="submit" class="btn btn-primary" prop:disabled=move || save.pending().get()>"保存"</button>
                                </div>
                            </form>
                        }.into_any()
                    }
                })
            }}
        </Suspense>
    }
}
