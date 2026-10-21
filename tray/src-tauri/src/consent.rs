//! Pending IT consent requests (remote desktop / file access).
//!
//! The agent pushes `ConsentRequest`s to trays that subscribed with
//! `remote_consent`. Deny is the safe default: a request that reaches
//! `expires_at` without an answer is dropped here without sending anything,
//! and the agent treats the missing answer as a deny.

use crate::protocol::{ConsentRequest, RemoteKind, TimestampMs};

/// Upper bound on queued requests (a misbehaving agent can't grow this forever).
pub const MAX_PENDING: usize = 16;

/// Pending requests in arrival order (the UI answers the first one first).
#[derive(Default, Debug)]
pub struct ConsentQueue {
    items: Vec<ConsentRequest>,
}

impl ConsentQueue {
    /// Queue a request. Returns `false` (ignored) when it already expired, is a
    /// duplicate id (it then replaces the queued copy), or the queue is full.
    pub fn push(&mut self, req: ConsentRequest, now: TimestampMs) -> bool {
        self.prune(now);
        if req.expires_at <= now {
            return false;
        }
        if let Some(existing) = self
            .items
            .iter_mut()
            .find(|r| r.request_id == req.request_id)
        {
            *existing = req;
            return false;
        }
        if self.items.len() >= MAX_PENDING {
            return false;
        }
        self.items.push(req);
        true
    }

    /// Drop expired requests (no answer = deny).
    pub fn prune(&mut self, now: TimestampMs) {
        self.items.retain(|r| r.expires_at > now);
    }

    pub fn remove(&mut self, id: &uuid::Uuid) -> Option<ConsentRequest> {
        let i = self.items.iter().position(|r| &r.request_id == id)?;
        Some(self.items.remove(i))
    }

    pub fn pending(&mut self, now: TimestampMs) -> Vec<ConsentRequest> {
        self.prune(now);
        self.items.clone()
    }

    pub fn is_empty(&mut self, now: TimestampMs) -> bool {
        self.prune(now);
        self.items.is_empty()
    }
}

/// "… wants to see and control your screen" etc. (shared by toast and tests).
pub fn consent_ask(req: &ConsentRequest) -> String {
    let who = req.admin_name.trim();
    let who = if who.is_empty() { "Someone" } else { who };
    match (req.kind, req.view_only) {
        (RemoteKind::Files, _) => format!("{who} from IT wants to access files on this PC"),
        (RemoteKind::Desktop, true) => {
            format!("{who} from IT wants to see your screen (view only)")
        }
        (RemoteKind::Desktop, false) => {
            format!("{who} from IT wants to see and control your screen")
        }
    }
}

/// Toast body for a new request; the flyout with Allow / Deny opens with it.
pub fn consent_toast_body(req: &ConsentRequest) -> String {
    format!(
        "{}. Open Kestrel to allow or deny. If you don't answer within {} s, IT can't connect.",
        consent_ask(req),
        req.timeout_secs
    )
    .chars()
    .take(250)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn req(n: u128, expires_at: TimestampMs) -> ConsentRequest {
        ConsentRequest {
            request_id: Uuid::from_u128(n),
            kind: RemoteKind::Desktop,
            admin_name: "Rina".into(),
            view_only: false,
            reason: String::new(),
            timeout_secs: 60,
            expires_at,
        }
    }

    #[test]
    fn queues_in_order_and_expires_without_answer() {
        let mut q = ConsentQueue::default();
        assert!(q.push(req(1, 100), 0));
        assert!(q.push(req(2, 200), 0));
        assert!(!q.push(req(3, 50), 60), "already expired");
        assert!(!q.push(req(2, 300), 0), "duplicate id replaces");
        let p = q.pending(0);
        assert_eq!(
            p.iter().map(|r| r.request_id.as_u128()).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(p[1].expires_at, 300);
        // At t=100 the first one silently lapses (deny by default).
        assert_eq!(q.pending(100).len(), 1);
        assert!(q.remove(&Uuid::from_u128(2)).is_some());
        assert!(q.is_empty(100));
    }

    #[test]
    fn bounded() {
        let mut q = ConsentQueue::default();
        for i in 0..(MAX_PENDING as u128 + 5) {
            q.push(req(i, 1000), 0);
        }
        assert_eq!(q.pending(0).len(), MAX_PENDING);
    }

    #[test]
    fn wording() {
        let mut r = req(1, 10);
        assert_eq!(
            consent_ask(&r),
            "Rina from IT wants to see and control your screen"
        );
        r.view_only = true;
        assert!(consent_ask(&r).ends_with("see your screen (view only)"));
        r.kind = RemoteKind::Files;
        assert!(consent_ask(&r).ends_with("access files on this PC"));
        assert!(consent_toast_body(&r).contains("allow or deny"));
    }
}
