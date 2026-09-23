//! Toast notifications (10 §2.6). Success/error with a 4-second auto-dismiss.

use leptos::prelude::*;

/// A single toast message.
#[derive(Clone, Debug)]
pub struct Toast {
    pub message: String,
    pub kind: ToastKind,
}

/// Toast severity, mapped to the state colours (06 §2).
#[derive(Clone, Copy, Debug)]
pub enum ToastKind {
    Success,
    Error,
}

impl ToastKind {
    pub fn css_class(self) -> &'static str {
        match self {
            ToastKind::Success => "toast-success",
            ToastKind::Error => "toast-error",
        }
    }
}

/// Reactive toast slot (one visible at a time; newest replaces).
#[derive(Clone, Copy)]
pub struct ToastContext {
    pub current: RwSignal<Option<Toast>>,
}

/// Install the toast context.
pub fn provide_toast_context() {
    provide_context(ToastContext {
        current: RwSignal::new(None),
    });
}

/// Access the toast context.
pub fn use_toast() -> ToastContext {
    expect_context::<ToastContext>()
}

impl ToastContext {
    pub fn show(&self, message: impl Into<String>, kind: ToastKind) {
        self.current.set(Some(Toast {
            message: message.into(),
            kind,
        }));
    }

    pub fn success(&self, message: impl Into<String>) {
        self.show(message, ToastKind::Success);
    }

    pub fn error(&self, message: impl Into<String>) {
        self.show(message, ToastKind::Error);
    }
}

/// Renders the current toast and schedules its auto-dismiss.
#[component]
pub fn ToastContainer() -> impl IntoView {
    let ctx = use_toast();
    view! {
        <div class="toast-container">
            {move || ctx.current.get().map(|toast| {
                let slot = ctx.current;
                set_timeout(move || slot.set(None), std::time::Duration::from_secs(4));
                view! {
                    <div
                        class=format!("toast {}", toast.kind.css_class())
                        role="status"
                        on:click=move |_| ctx.current.set(None)
                    >
                        <span class="toast-message">{toast.message}</span>
                    </div>
                }
            })}
        </div>
    }
}
