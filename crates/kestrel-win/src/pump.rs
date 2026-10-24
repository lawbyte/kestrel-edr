//! Sensor-pipeline plumbing that must behave the same on every platform
//! (Linux-testable): the translator's receive loop and how a failed hand-off
//! to it is accounted.
//!
//! Fresh-install lab finding 2026-10-21: the first heartbeat after install
//! reported `etw_events_lost: 3390` (buffers lost 0). Root cause: an
//! *internal* artefact, not kernel loss. A fresh agent starts its sensors
//! with the default policy, then restarts them when the server's first
//! policy arrives. On that restart the translator (the only receiver of
//! the raw channel) saw the shared stop flag and exited within 100 ms,
//! while the ETW sessions / event-log subscriptions kept delivering for up
//! to ~0.5 s more (the watchdog only stops them on its next tick). Every
//! one of those `try_send`s failed with *Disconnected* and was counted in
//! `raw_dropped`, which is part of the reported `events_lost`; the events
//! still queued in the channel were discarded silently.
//!
//! Now: the producers are stopped first, the translator keeps consuming
//! until it is told to drain ([`pump`]) and then empties the queue; a
//! hand-off that fails because the receiver is gone **after an orderly
//! shutdown began** is a [`SendFailure::ShutdownDiscard`] (logged, not a
//! loss), while a full queue is always a [`SendFailure::Dropped`] (health,
//! TP-05 / TP-SRV-EVENTS-LOST) — drops later in the agent's life are never
//! hidden.
//!
//! Owner-PC triage 2026-10-25 (`sensor_internal_dropped: 7403` on an idle
//! developer workstation, device shown Degraded): the owner's own telemetry
//! showed OneDrive opening `explorer.exe` with `PROCESS_DUP_HANDLE` 20,000 to
//! 29,000 times per second for four minutes (1.38 M identical
//! `process_access` events). Every queue treated those like a process start,
//! so whatever arrived while the queue was full was lost, whatever its value.
//! Now:
//! * identical successive handle opens are coalesced at the source
//!   ([`Coalescer`]: same actor, target and access within a short window;
//!   the first one always goes through, and a process start / stop of
//!   either pid ends the window);
//! * the raw queue sheds by value ([`Value`], [`shed_early`]): low-value
//!   records give way first so that process start / stop, DPAPI, handle
//!   opens and network connects still find room; only a completely full
//!   queue drops a high-value record, and that is counted separately
//!   (`high_value_dropped`) for health.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::time::Duration;

/// How much a sensor record is worth to detection when a queue is under
/// pressure. Ordered: `Low < Medium < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Value {
    /// Bookkeeping that never becomes an event on its own (TCP send byte
    /// accounting, connection close, first-read tracking).
    Low,
    /// Events that are useful but repeat a lot and are rarely the only
    /// signal (image loads that passed the source filter, DNS answers, UDP
    /// sends).
    Medium,
    /// Never shed early: process start / stop, command lines, handle opens,
    /// thread context, DPAPI, sensitive-file opens, network connects,
    /// registry, persistence, script blocks, file-activity summaries,
    /// tamper signals.
    High,
}

/// Should a record of `value` be shed *before* the queue is full, given
/// `queued` items in a queue of `capacity`? Low-value records stop at half
/// full, medium-value ones at 7/8; high-value records are only lost when
/// the queue is completely full (the `try_send` fails).
pub fn shed_early(value: Value, queued: usize, capacity: usize) -> bool {
    match value {
        Value::Low => queued >= capacity / 2,
        Value::Medium => queued >= capacity - capacity / 8,
        Value::High => false,
    }
}

/// Approximate number of items in a `std::sync::mpsc` queue (it exposes
/// none): producers call [`QueueGauge::sent`] *before* `try_send` (and
/// [`QueueGauge::received`] again if it fails), the consumer
/// [`QueueGauge::received`] per item, so the gauge never runs behind.
#[derive(Debug, Default)]
pub struct QueueGauge(AtomicUsize);

impl QueueGauge {
    pub fn sent(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    pub fn received(&self) {
        // Never wraps below zero.
        let mut cur = self.0.load(Ordering::Relaxed);
        while cur > 0 {
            match self
                .0
                .compare_exchange_weak(cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(v) => cur = v,
            }
        }
    }
    pub fn len(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Exact-duplicate suppression at the source: the first record for a key
/// passes, identical ones within `window_ms` of the first are counted and
/// suppressed. Bounded: at `max_keys` the map is cleared (everything passes
/// again; never a silent blind spot).
#[derive(Debug)]
pub struct Coalescer<K> {
    window_ms: i64,
    max_keys: usize,
    seen: HashMap<K, i64>,
    /// Records suppressed so far.
    pub suppressed: u64,
}

impl<K: Hash + Eq> Coalescer<K> {
    pub fn new(window_ms: i64, max_keys: usize) -> Self {
        Coalescer {
            window_ms,
            max_keys: max_keys.max(1),
            seen: HashMap::new(),
            suppressed: 0,
        }
    }

    /// True if the record must be forwarded. Timestamps going backwards
    /// (sessions flush independently) never suppress.
    pub fn admit(&mut self, key: K, ts: i64) -> bool {
        if let Some(first) = self.seen.get(&key) {
            if ts >= *first && ts - *first < self.window_ms {
                self.suppressed += 1;
                return false;
            }
        }
        if self.seen.len() >= self.max_keys {
            let w = self.window_ms;
            self.seen.retain(|_, t| ts - *t < w);
            if self.seen.len() >= self.max_keys {
                self.seen.clear();
            }
        }
        self.seen.insert(key, ts);
        true
    }

    /// Forget every key matching `f` (O(n): for rare events only; per-pid
    /// invalidation on the hot path uses generations in the key instead,
    /// see `win::etw::CoreCtx`).
    pub fn forget(&mut self, f: impl Fn(&K) -> bool) {
        self.seen.retain(|k, _| !f(k));
    }

    /// Forget everything.
    pub fn clear(&mut self) {
        self.seen.clear();
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Why a raw event could not be handed to the translator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendFailure {
    /// Lost telemetry: the queue was full, or the translator is gone while
    /// the sensors were supposed to be running. Counted as events lost.
    Dropped,
    /// A straggler delivered by a session that is being torn down after an
    /// orderly sensor stop / restart began: not a loss of the running
    /// sensors (counted separately for diagnostics).
    ShutdownDiscard,
}

/// Classify a failed `try_send`: `full` = the queue was full (otherwise the
/// receiver was disconnected); `closing` = this sensor instance's orderly
/// stop has begun.
pub fn classify_send_failure(full: bool, closing: bool) -> SendFailure {
    if full || !closing {
        SendFailure::Dropped
    } else {
        SendFailure::ShutdownDiscard
    }
}

/// Upper bound on items processed after `drain` was set (a producer that
/// never stops must not keep the translator alive forever).
pub const MAX_DRAIN_ITEMS: usize = 1 << 20;

/// Receive loop: hands every item to `on_item` and calls `on_tick` after
/// each wake-up (item or `poll` timeout). Runs until `drain` is set (the
/// producers have been stopped) or every sender is gone; then processes
/// what is still queued (at most [`MAX_DRAIN_ITEMS`]) and returns the
/// number of items handled during that final drain.
pub fn pump<T>(
    rx: &Receiver<T>,
    drain: &AtomicBool,
    poll: Duration,
    mut on_item: impl FnMut(T),
    mut on_tick: impl FnMut(),
) -> usize {
    loop {
        if drain.load(Ordering::SeqCst) {
            break;
        }
        match rx.recv_timeout(poll) {
            Ok(r) => on_item(r),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return 0,
        }
        on_tick();
    }
    let mut n = 0usize;
    while n < MAX_DRAIN_ITEMS {
        match rx.try_recv() {
            Ok(r) => {
                on_item(r);
                n += 1;
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
        }
    }
    on_tick();
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{sync_channel, TrySendError};
    use std::sync::Arc;

    #[test]
    fn classification() {
        assert_eq!(classify_send_failure(true, false), SendFailure::Dropped);
        // A full queue is a loss even while shutting down.
        assert_eq!(classify_send_failure(true, true), SendFailure::Dropped);
        // The receiver vanished while the sensors were supposed to run.
        assert_eq!(classify_send_failure(false, false), SendFailure::Dropped);
        assert_eq!(
            classify_send_failure(false, true),
            SendFailure::ShutdownDiscard
        );
    }

    /// Regression (fresh-install "degraded"): the consumer keeps running
    /// while producers are still delivering after the stop began, and
    /// everything queued is processed before it exits. Nothing a producer
    /// sent before it was stopped is lost or counted as dropped.
    #[test]
    fn consumer_outlives_producers_and_drains() {
        let (tx, rx) = sync_channel::<u32>(64);
        let drain = Arc::new(AtomicBool::new(false));
        let stop_producers = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let producer = {
            let (stop, dropped, sent) = (stop_producers.clone(), dropped.clone(), sent.clone());
            std::thread::spawn(move || {
                let mut i = 0u32;
                // Keeps producing for a while after the stop request
                // (an ETW session that is only stopped on the next
                // watchdog tick).
                let mut after_stop = 0;
                while after_stop < 2_000 {
                    if stop.load(Ordering::SeqCst) {
                        after_stop += 1;
                    }
                    let mut v = i;
                    loop {
                        match tx.try_send(v) {
                            Ok(()) => {
                                sent.fetch_add(1, Ordering::SeqCst);
                                break;
                            }
                            Err(TrySendError::Full(back)) => {
                                // Test producer: retry instead of dropping
                                // so the count is exact.
                                v = back;
                                std::thread::yield_now();
                            }
                            Err(TrySendError::Disconnected(_)) => {
                                dropped.fetch_add(1, Ordering::SeqCst);
                                break;
                            }
                        }
                    }
                    i += 1;
                }
            })
        };
        let consumer = {
            let drain = drain.clone();
            std::thread::spawn(move || {
                let mut got = 0u64;
                pump(&rx, &drain, Duration::from_millis(5), |_| got += 1, || {});
                got
            })
        };
        std::thread::sleep(Duration::from_millis(20));
        // Orderly stop: producers first, then the consumer drains.
        stop_producers.store(true, Ordering::SeqCst);
        producer.join().unwrap();
        drain.store(true, Ordering::SeqCst);
        let got = consumer.join().unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert_eq!(got, sent.load(Ordering::SeqCst));
    }

    #[test]
    fn exits_when_all_senders_are_gone() {
        let (tx, rx) = sync_channel::<u32>(4);
        tx.send(1).unwrap();
        drop(tx);
        let drain = AtomicBool::new(false);
        let mut got = vec![];
        pump(
            &rx,
            &drain,
            Duration::from_millis(5),
            |v| got.push(v),
            || {},
        );
        assert_eq!(got, [1]);
    }

    #[test]
    fn shed_policy_thresholds() {
        let cap = 1024;
        assert!(!shed_early(Value::Low, 511, cap));
        assert!(shed_early(Value::Low, 512, cap));
        assert!(!shed_early(Value::Medium, 895, cap));
        assert!(shed_early(Value::Medium, 896, cap));
        // High is never shed before the queue is actually full.
        assert!(!shed_early(Value::High, cap, cap));
        assert!(Value::Low < Value::Medium && Value::Medium < Value::High);
    }

    /// Burst simulation: a producer floods a bounded queue with a mix of
    /// values faster than the consumer drains it. With the value policy no
    /// high-value record is lost while low / medium ones are available to
    /// shed; without it (plain `try_send`) high-value records are lost.
    #[test]
    fn burst_sheds_low_value_first() {
        fn run(policy: bool) -> (u64, u64, u64) {
            const CAP: usize = 256;
            let (tx, rx) = sync_channel::<Value>(CAP);
            let gauge = Arc::new(QueueGauge::default());
            let (mut high_lost, mut low_shed, mut med_shed) = (0u64, 0u64, 0u64);
            let mut delivered_high = 0u64;
            // 20,000 records: 70 % low, 20 % medium, 10 % high; the
            // consumer takes one item per four produced (a slow translator).
            for i in 0..20_000u32 {
                let v = match i % 10 {
                    0 => Value::High,
                    1 | 2 => Value::Medium,
                    _ => Value::Low,
                };
                if policy && shed_early(v, gauge.len(), CAP) {
                    match v {
                        Value::Low => low_shed += 1,
                        Value::Medium => med_shed += 1,
                        Value::High => unreachable!(),
                    }
                } else {
                    gauge.sent();
                    match tx.try_send(v) {
                        Ok(()) => {}
                        Err(_) => {
                            gauge.received();
                            if v == Value::High {
                                high_lost += 1;
                            }
                        }
                    }
                }
                if i % 4 == 0 {
                    if let Ok(v) = rx.try_recv() {
                        gauge.received();
                        if v == Value::High {
                            delivered_high += 1;
                        }
                    }
                }
            }
            while let Ok(v) = rx.try_recv() {
                gauge.received();
                if v == Value::High {
                    delivered_high += 1;
                }
            }
            assert!(gauge.is_empty());
            assert_eq!(delivered_high + high_lost, 2_000);
            let _ = med_shed;
            (high_lost, low_shed, delivered_high)
        }
        let (lost_plain, _, _) = run(false);
        let (lost_policy, shed_low, delivered) = run(true);
        assert!(
            lost_plain > 0,
            "the plain queue must lose high-value records"
        );
        assert_eq!(lost_policy, 0, "no high-value record lost with the policy");
        assert_eq!(delivered, 2_000);
        assert!(shed_low > 0);
    }

    #[test]
    fn coalescer_suppresses_identical_records_within_the_window() {
        let mut c = Coalescer::new(2_000, 1024);
        // OneDrive -> explorer, PROCESS_DUP_HANDLE, 25,000 per second.
        let key = (4242u32, 1000u32, 0x40u32, 0u32);
        let mut passed = 0;
        for i in 0..25_000i64 {
            if c.admit(key, 1_000_000 + i / 25) {
                passed += 1;
            }
        }
        assert_eq!(passed, 1, "one second of identical opens = one record");
        assert_eq!(c.suppressed, 24_999);
        // After the window the next one passes again.
        assert!(c.admit(key, 1_000_000 + 2_000));
        // A different access mask / target / actor is never suppressed.
        assert!(c.admit((4242, 1000, 0x1410, 0), 1_000_001));
        assert!(c.admit((4242, 1001, 0x40, 0), 1_000_001));
        assert!(c.admit((4243, 1000, 0x40, 0), 1_000_001));
        // Timestamps going backwards never suppress.
        assert!(c.admit(key, 999_000));
    }

    #[test]
    fn coalescer_forgets_reused_pids_and_stays_bounded() {
        let mut c = Coalescer::new(10_000, 4);
        assert!(c.admit((1u32, 2u32), 0));
        assert!(!c.admit((1, 2), 1));
        // pid 1 exited: its successor's first open passes.
        c.forget(|k| k.0 == 1 || k.1 == 1);
        assert!(c.admit((1, 2), 2));
        for i in 10..100u32 {
            assert!(c.admit((i, i), 3));
            assert!(c.len() <= 4);
        }
    }

    #[test]
    fn drain_processes_backlog_then_returns() {
        let (tx, rx) = sync_channel::<u32>(16);
        for i in 0..10 {
            tx.send(i).unwrap();
        }
        let drain = AtomicBool::new(true);
        let mut got = vec![];
        let mut ticks = 0;
        let n = pump(
            &rx,
            &drain,
            Duration::from_millis(5),
            |v| got.push(v),
            || ticks += 1,
        );
        assert_eq!(n, 10);
        assert_eq!(got, (0..10).collect::<Vec<_>>());
        assert_eq!(ticks, 1);
    }
}
