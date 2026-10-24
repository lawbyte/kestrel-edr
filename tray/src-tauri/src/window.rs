//! Window lifecycle decisions, kept free of Tauri types so they are unit-tested.
//!
//! The flyout's WebView2 costs ~190 MB private memory in six `msedgewebview2.exe`
//! processes, so the tray never keeps a hidden window: it is built when the
//! employee opens it (or something must be shown, e.g. an IT consent prompt)
//! and destroyed when it is hidden. Everything that must work without a window
//! (tray icon and tooltip, toasts, the agent subscription, the consent queue)
//! lives in Rust; the agent's own desktop helper draws the always-on-top
//! remote-session banner, independent of this app.
//!
//! Requests aimed at the UI while it doesn't exist yet (open a tab, start a
//! quick check) wait in an [`IntentBox`] until the frontend says it is ready.

use serde::Serialize;

use crate::WindowMode;

/// What the flyout should do once it is loaded.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct UiIntent {
    /// Tab to open (`status` / `activity` / `help`).
    pub tab: Option<String>,
    /// Start a quick check.
    pub quick_check: bool,
}

impl UiIntent {
    pub fn tab(tab: &str) -> Self {
        Self {
            tab: Some(tab.to_string()),
            quick_check: false,
        }
    }

    pub fn quick_check() -> Self {
        Self {
            tab: None,
            quick_check: true,
        }
    }

    fn merge(&mut self, other: UiIntent) {
        // A quick check always opens the status tab, so it wins over a tab.
        if other.quick_check {
            self.quick_check = true;
            self.tab = None;
        } else if other.tab.is_some() && !self.quick_check {
            self.tab = other.tab;
        }
    }
}

/// Holds UI intents until the webview is listening.
#[derive(Debug, Default)]
pub struct IntentBox {
    ready: bool,
    pending: UiIntent,
}

impl IntentBox {
    /// Returns the intent when the UI is listening (send it as an event now);
    /// otherwise keeps it for [`IntentBox::ready`].
    pub fn deliver(&mut self, intent: UiIntent) -> Option<UiIntent> {
        if self.ready {
            Some(intent)
        } else {
            self.pending.merge(intent);
            None
        }
    }

    /// The UI has mounted and registered its listeners: hand over what was
    /// waiting (exactly once).
    pub fn ready(&mut self) -> UiIntent {
        self.ready = true;
        std::mem::take(&mut self.pending)
    }

    /// The window was destroyed: later intents wait for the next one.
    pub fn reset(&mut self) {
        self.ready = false;
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }
}

/// What to do when the window loses focus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlurAction {
    Keep,
    /// Close it like a Windows flyout (and free the webview).
    Destroy,
}

/// A flyout closes when it loses focus, except while an IT consent prompt is
/// waiting for an answer (it stays until answered or expired). A framed
/// window stays open.
pub fn blur_action(mode: WindowMode, visible: bool, consents_pending: bool) -> BlurAction {
    if mode == WindowMode::Flyout && visible && !consents_pending {
        BlurAction::Destroy
    } else {
        BlurAction::Keep
    }
}

/// Whether a window must exist. It never exists just in case: only while
/// the employee has it open or an IT consent prompt needs an answer.
pub fn window_needed(user_opened: bool, consents_pending: bool) -> bool {
    user_opened || consents_pending
}

/// WebView2 arguments for the flyout. Setting any replaces wry's defaults, so
/// they are repeated here (`wry` 0.57 `webview2/mod.rs`), then GPU use is
/// turned off: the flyout is static UI, and a GPU process costs memory and
/// wakeups for nothing.
pub const BROWSER_ARGS: &str = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --disable-gpu --disable-gpu-compositing";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intents_wait_until_ready_then_flow_directly() {
        let mut b = IntentBox::default();
        assert_eq!(b.deliver(UiIntent::tab("help")), None);
        assert_eq!(b.ready(), UiIntent::tab("help"));
        assert!(b.is_ready());
        // Handed over once.
        assert_eq!(b.ready(), UiIntent::default());
        // While ready, intents go out as events.
        assert_eq!(
            b.deliver(UiIntent::quick_check()),
            Some(UiIntent::quick_check())
        );
        // Destroyed window: wait again.
        b.reset();
        assert_eq!(b.deliver(UiIntent::tab("activity")), None);
        assert_eq!(b.ready(), UiIntent::tab("activity"));
    }

    #[test]
    fn quick_check_wins_over_tab() {
        let mut b = IntentBox::default();
        b.deliver(UiIntent::tab("help"));
        b.deliver(UiIntent::quick_check());
        b.deliver(UiIntent::tab("activity"));
        assert_eq!(b.ready(), UiIntent::quick_check());
    }

    #[test]
    fn later_tab_wins() {
        let mut b = IntentBox::default();
        b.deliver(UiIntent::tab("help"));
        b.deliver(UiIntent::tab("activity"));
        assert_eq!(b.ready(), UiIntent::tab("activity"));
    }

    #[test]
    fn blur_closes_only_an_unblocked_visible_flyout() {
        use BlurAction::*;
        assert_eq!(blur_action(WindowMode::Flyout, true, false), Destroy);
        assert_eq!(blur_action(WindowMode::Flyout, true, true), Keep);
        assert_eq!(blur_action(WindowMode::Flyout, false, false), Keep);
        assert_eq!(blur_action(WindowMode::Window, true, false), Keep);
    }

    #[test]
    fn window_only_when_needed() {
        assert!(!window_needed(false, false));
        assert!(window_needed(true, false));
        assert!(window_needed(false, true));
    }

    #[test]
    fn browser_args_keep_wry_defaults() {
        assert!(BROWSER_ARGS
            .starts_with("--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection"));
        assert!(BROWSER_ARGS.contains("--disable-gpu"));
    }
}
