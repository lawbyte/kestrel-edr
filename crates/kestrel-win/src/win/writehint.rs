//! Sensor side of the evidence write hints (staged-file candidates,
//! `docs/DECISIONS.md` 2026-10-25 decision 3): the cheap check in the
//! Kernel-File callback and the hand-off to the translator, which maps the
//! NT path, attributes the pid and `try_send`s a
//! `kestrel_platform::WriteHint` to `SensorConfig.write_tx`
//! ([`super::translate`]).
//!
//! Hints are low-value records: they give way first when the raw queue is
//! under pressure, and every hint that is shed or dropped is counted in
//! `Counters::write_hints_dropped`, never in the sensor loss counters
//! (`events_lost`): they never become events.

use super::etw::{Raw, Sink, RAW_QUEUE_CAPACITY};
use crate::evidence_plan::{hint_path_len_ok, write_op, WriteScope};
use crate::pump::{shed_early, Value};
use std::sync::atomic::Ordering;

/// Kernel-File CreateNewFile (30) of `pid` for `name` (NT path as
/// delivered) with `create_options`: queue a write hint when hints are
/// wanted (`scope` is `Some`), it created a file (never a directory), the
/// path is at most [`crate::evidence_plan::MAX_HINT_PATH_UNITS`] long and in
/// scope. Never the agent itself, the idle process or System. Create (12)
/// is never a hint (logged for failed opens too: [`write_op`]).
pub fn note_file_write(
    scope: Option<&WriteScope>,
    sink: &Sink,
    event_id: u16,
    ts: i64,
    pid: u32,
    name: &str,
    create_options: u32,
) {
    let Some(scope) = scope else {
        return;
    };
    if pid == sink.self_pid || pid == 0 || pid == 4 {
        return;
    }
    let Some(op) = write_op(event_id, create_options) else {
        return;
    };
    // Before anything is allocated (`in_scope` lower-cases a copy).
    if !hint_path_len_ok(name) {
        sink.counters
            .write_hints_dropped
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    if !scope.in_scope(name) {
        return;
    }
    send(
        sink,
        Raw::WriteHint {
            ts,
            pid,
            name_nt: name.to_string(),
            op,
        },
    );
}

fn send(sink: &Sink, r: Raw) {
    let c = &sink.counters;
    if shed_early(Value::Low, c.raw_queued.len(), RAW_QUEUE_CAPACITY) {
        c.write_hints_dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    c.raw_queued.sent();
    if sink.tx.try_send(r).is_err() {
        c.raw_queued.received();
        c.write_hints_dropped.fetch_add(1, Ordering::Relaxed);
    }
}
