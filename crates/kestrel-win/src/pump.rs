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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::time::Duration;

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
