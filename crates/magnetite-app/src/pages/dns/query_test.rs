//! DNS query test (S-DNS query-test / AC-13). Resolves a name against
//! Magnetite's own authoritative data via the embedded resolver and shows the
//! response code, AA flag and answer records.

use super::nav::DnsNav;
use crate::components::ui::PageHeader;
use crate::server_fns::dns::{DnsQueryResult, DnsQueryTest};
use leptos::prelude::*;

const QTYPES: [&str; 11] = [
    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV", "CAA", "SOA", "ANY",
];

#[component]
pub fn QueryTestPage() -> impl IntoView {
    let name = RwSignal::new(String::new());
    let qtype = RwSignal::new("A".to_string());
    let action = ServerAction::<DnsQueryTest>::new();

    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        action.dispatch(DnsQueryTest {
            name: name.get(),
            qtype: qtype.get(),
        });
    };

    view! {
        <PageHeader title=Signal::derive(|| "DNS クエリテスト".to_string())/>
        <DnsNav/>

        <form class="query-test-form" on:submit=submit>
            <label class="field">
                <span class="field-label">"名前"</span>
                <input class="input" placeholder="www.example.com" prop:value=move || name.get()
                    on:input=move |ev| name.set(event_target_value(&ev))/>
            </label>
            <label class="field">
                <span class="field-label">"種別"</span>
                <select class="input" prop:value=move || qtype.get() on:change=move |ev| qtype.set(event_target_value(&ev))>
                    {QTYPES.iter().map(|t| view! { <option value=*t>{*t}</option> }).collect_view()}
                </select>
            </label>
            <button type="submit" class="btn btn-primary" prop:disabled=move || action.pending().get()>"テスト"</button>
        </form>

        {move || action.value().get().map(|res| match res {
            Err(e) => view! { <p class="field-error" role="alert">{e.to_string()}</p> }.into_any(),
            Ok(result) => view! { <QueryResult result=result/> }.into_any(),
        })}
    }
}

#[component]
fn QueryResult(result: DnsQueryResult) -> impl IntoView {
    let rcode = result.rcode.clone();
    let rcode_class = match rcode.as_str() {
        "NOERROR" => "badge badge-success",
        "NXDOMAIN" => "badge badge-warning",
        _ => "badge badge-danger",
    };
    let aa = if result.authoritative {
        "権威応答 (AA)"
    } else {
        "非権威"
    };
    let answers = result.answers.clone();
    let has_answers = !answers.is_empty();

    view! {
        <div class="query-result">
            <div class="query-result-status">
                <span class=rcode_class>{rcode}</span>
                <span class="query-result-aa">{aa}</span>
            </div>
            <Show
                when=move || has_answers
                fallback=|| view! { <p class="query-result-empty">"回答レコードはありません。"</p> }
            >
                <table class="data-table">
                    <thead><tr><th>"名前"</th><th>"TTL"</th><th>"種別"</th><th>"値"</th></tr></thead>
                    <tbody>
                        {answers.clone().into_iter().map(|a| view! {
                            <tr>
                                <td class="mono">{a.name}</td>
                                <td class="mono">{a.ttl}</td>
                                <td>{a.record_type}</td>
                                <td class="mono">{a.value}</td>
                            </tr>
                        }).collect_view()}
                    </tbody>
                </table>
            </Show>
        </div>
    }
}
