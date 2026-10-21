//! ETW real-time sessions (ferrisetw) and their watchdog.
//!
//! Sessions:
//! * `Kestrel-Core` (flush 1 s): Kernel-Process (1,2,5), Kernel-Audit-API-Calls
//!   (2,4,5,6), Kernel-Registry (5 SetValueKey, 6 DeleteValueKey — writer
//!   attribution for the registry watcher), Crypto-DPAPI (16385).
//! * `Kestrel-IO` (flush 5 s): Kernel-Network (10,12,13,26,28,29,42,58),
//!   DNS-Client (3008), PowerShell (4104).
//! * `Kestrel-File` (flush 1 s): Kernel-File 12 Create [+15 Read] for the
//!   sensitive-path filter and, with `policy.sensors.file_activity`,
//!   26 DeletePath / 27 RenamePath / 30 CreateNewFile aggregated per process
//!   **in the callback** ([`crate::fileagg`]) into `FileActivity` summaries.
//! * `Kestrel-Persist` (flush 1 s, `policy.sensors.persistence`):
//!   TaskScheduler (106,140,141), Service Control Manager (7045), WMI-Activity
//!   (5861). Event-log subscriptions on the same channels are the fallback
//!   (see `evtsub`); the translator de-duplicates.
//! * `Kestrel-ProcCmd` (system-logger mode, optional): classic kernel process
//!   events, used only as a command-line source for processes that exit
//!   before the agent can query them.
//!
//! Buffers: 64 KB, Minimum = Maximum, no per-processor buffering (keeps
//! process start/stop ordered). Core uses a 1 s flush timer instead of the
//! 5-10 s research guideline because suspend-on-suspicion latency depends on
//! it; the high-volume IO session uses 5 s.
//!
//! Callbacks decode only the fields Kestrel uses into [`Raw`] and `try_send`
//! them; drops are counted. For ProcessStart the callback also reads the new
//! process's command line and token (two syscalls) because short-lived
//! processes are often gone by the time any later stage could ask.

use super::util::*;
use crate::consts::{self, eid, field, kw, provider};
use crate::etwparse::*;
use crate::evtxml::SysmonCross;
use crate::fileagg::{DecoyOpeners, FileAgg, FileScope};
use crate::persist::{record_from_fields, PersistRecord};
use crate::taskxml::TaskInfo;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{kernel_providers, EventFilter, Provider};
use ferrisetw::trace::{
    stop_trace_by_name, KernelTrace, LoggingMode, TraceProperties, TraceTrait, UserTrace,
};
use ferrisetw::{EventRecord, SchemaLocator};
use kestrel_common::{FileActivity, Integrity, RegistryOp, TamperKind};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Diagnostics::Etw::{
    ControlTraceW, EnumerateTraceGuidsEx, TraceGuidQueryInfo, CONTROLTRACE_HANDLE,
    EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_PROPERTIES, TRACE_ENABLE_INFO, TRACE_GUID_INFO,
    TRACE_PROVIDER_INSTANCE_INFO,
};
use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

/// Emit Kernel-File Read events (first read per handle) in addition to opens.
/// Off by default: Read is by far the highest-volume Kernel-File keyword and
/// every stealer rule keys on the open. Turn on only after load testing.
pub const FILE_READ_EVENTS: bool = false;

/// Raw, owned sensor record (decoded in the ETW callback).
#[derive(Debug, Clone)]
pub enum Raw {
    ProcStart {
        ts: i64,
        pid: u32,
        ppid: u32,
        /// EVENT_HEADER ProcessId of the start event: the process that really
        /// created this one. Differs from `ppid` under PPID spoofing (V-H1).
        creator_pid: u32,
        create_ft: u64,
        session: u32,
        label_sid: Option<String>,
        image_nt: String,
        cmdline: Option<String>,
        user_sid: Option<String>,
        token_integrity: Option<Integrity>,
    },
    ProcStop {
        ts: i64,
        pid: u32,
        create_ft: u64,
        exit_code: Option<u32>,
    },
    ImageLoad {
        ts: i64,
        pid: u32,
        image_nt: String,
    },
    FileCreate {
        ts: i64,
        pid: u32,
        file_object: u64,
        name_nt: String,
        create_options: u32,
    },
    FileRead {
        ts: i64,
        pid: u32,
        file_object: u64,
    },
    NetConnect {
        ts: i64,
        pid: u32,
        dst: IpAddr,
        dport: u16,
        sport: u16,
    },
    NetSend {
        ts: i64,
        pid: u32,
        tcp: bool,
        dst: IpAddr,
        dport: u16,
        sport: u16,
        size: u64,
    },
    NetClose {
        pid: u32,
        dst: IpAddr,
        dport: u16,
        sport: u16,
    },
    OpenProcess {
        ts: i64,
        pid: u32,
        target_pid: u32,
        access: u32,
        /// NTSTATUS; non-zero only for opens of lsass (failed attempts).
        return_code: u32,
    },
    OpenThread {
        ts: i64,
        pid: u32,
        target_pid: u32,
        access: u32,
    },
    SetContext {
        ts: i64,
        pid: u32,
    },
    Terminate {
        ts: i64,
        pid: u32,
        target_pid: u32,
    },
    /// Kernel-Registry 5 / 6. `key` is empty on current builds (measured);
    /// used for writer attribution, and emitted directly when it is not.
    RegEtw {
        ts: i64,
        pid: u32,
        key_object: u64,
        /// Normalised key, or "" when the event carries none.
        key: String,
        value_name: String,
        op: RegistryOp,
        ty: u32,
        data: Vec<u8>,
    },
    /// Change seen by the registry watcher (writer unknown yet).
    RegChange {
        ts: i64,
        key: String,
        value_name: String,
        op: RegistryOp,
        ty: u32,
        data: Option<Vec<u8>>,
        /// The watched key (re)appeared — created, or renamed into place —
        /// and its values are reported wholesale: only a KeyObject-exact
        /// join counts (V-H7).
        reopened: bool,
    },
    /// Ransomware sensor summary (paths are lower-cased NT paths).
    FileActivity {
        ts: i64,
        pid: u32,
        act: FileActivity,
    },
    /// Task / service / WMI persistence event (creator not yet attributed).
    Persist {
        ts: i64,
        /// Process that logged the event (Schedule svchost, services.exe, WMI host).
        logger_pid: u32,
        record: PersistRecord,
        task: Option<TaskInfo>,
    },
    Dns {
        ts: i64,
        pid: u32,
        qname: String,
        results: String,
    },
    Dpapi {
        ts: i64,
        caller_pid: u32,
        caller_create_ft: Option<u64>,
        description: String,
    },
    Script {
        ts: i64,
        pid: u32,
        text: String,
    },
    CmdLine {
        pid: u32,
        cmdline: String,
    },
    Sysmon(SysmonCross),
    Tamper {
        kind: TamperKind,
        detail: String,
    },
}

/// Shared counters (heartbeat stats).
#[derive(Default)]
pub struct Counters {
    pub raw_delivered: AtomicU64,
    pub raw_dropped: AtomicU64,
    pub emitted: AtomicU64,
    pub out_dropped: AtomicU64,
    pub etw_events_lost: AtomicU64,
    pub etw_buffers_lost: AtomicU64,
    pub sessions_ok: AtomicBool,
    pub sysmon_present: AtomicBool,
    /// Current lsass pid (0 = unknown); failed opens are reported only for it.
    pub lsass_pid: AtomicU32,
    /// File-activity operations dropped by the aggregator's memory caps.
    pub file_agg_dropped: AtomicU64,
    pub file_activity_emitted: AtomicU64,
    /// Registry watcher changes joined to an ETW writer / emitted with pid 0.
    pub reg_attributed: AtomicU64,
    pub reg_unattributed: AtomicU64,
    /// Watched registry keys currently open.
    pub reg_watch_keys: AtomicU64,
    /// Task / service / WMI events emitted (after de-duplication).
    pub persist_events: AtomicU64,
    /// Persistence records dropped because the enrichment queue was full
    /// (re-review V-M9).
    pub persist_dropped: AtomicU64,
}

/// Kernel-File callback state shared with the canary poller.
pub struct FileState {
    pub agg: FileAgg,
    /// Recent openers of each ransomware decoy (V-H9).
    pub openers: DecoyOpeners,
}

impl FileState {
    pub fn new(scope: FileScope) -> Self {
        FileState {
            agg: FileAgg::new(scope),
            openers: DecoyOpeners::default(),
        }
    }

    fn note_open(&mut self, nt: &str, pid: u32, ts: i64, create_options: u32) {
        if self.agg.is_canary(nt) {
            // Supersede / create / overwrite dispositions are write-capable;
            // the event has no DesiredAccess (see `DecoyOpeners`).
            let write =
                file_op_from_create_options(create_options) == kestrel_common::FileOp::Create;
            self.openers.note(nt, pid, ts, write);
        }
    }
}

#[derive(Clone)]
pub struct Sink {
    pub tx: SyncSender<Raw>,
    pub counters: Arc<Counters>,
    pub self_pid: u32,
}

impl Sink {
    pub fn send(&self, r: Raw) {
        match self.tx.try_send(r) {
            Ok(()) => {
                self.counters.raw_delivered.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.counters.raw_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ------------------------------------------------------------------ decoding

struct F<'s, 'r>(Parser<'s, 'r>);

impl F<'_, '_> {
    fn bytes(&self, n: &str) -> Option<Vec<u8>> {
        self.0.try_parse::<Vec<u8>>(n).ok()
    }
    fn u32(&self, n: &str) -> Option<u32> {
        le_u32(&self.bytes(n)?)
    }
    /// UInt64, FILETIME or pointer-sized value.
    fn u64(&self, n: &str) -> Option<u64> {
        let b = self.bytes(n)?;
        match b.len() {
            8 => le_u64(&b),
            4 => le_u32(&b).map(u64::from),
            _ => None,
        }
    }
    fn string(&self, n: &str) -> Option<String> {
        self.0.try_parse::<String>(n).ok()
    }
}

fn with_fields<R>(
    rec: &EventRecord,
    loc: &SchemaLocator,
    f: impl FnOnce(&F) -> Option<R>,
) -> Option<R> {
    let schema = loc.event_schema(rec).ok()?;
    let p = Parser::create(rec, &schema);
    f(&F(p))
}

fn ts_of(rec: &EventRecord) -> i64 {
    let t = filetime_to_ms(rec.raw_timestamp() as u64);
    if t == 0 {
        kestrel_common::now_ms()
    } else {
        t
    }
}

fn decode_process(rec: &EventRecord, loc: &SchemaLocator) -> Option<Raw> {
    let ts = ts_of(rec);
    match rec.event_id() {
        eid::PROC_START => {
            let creator_pid = rec.process_id();
            let r = with_fields(rec, loc, |f| {
                Some(Raw::ProcStart {
                    ts,
                    pid: f.u32(field::PROCESS_ID)?,
                    ppid: f.u32(field::PARENT_PROCESS_ID).unwrap_or(0),
                    creator_pid,
                    create_ft: f.u64(field::CREATE_TIME).unwrap_or(0),
                    session: f.u32(field::SESSION_ID).unwrap_or(0),
                    label_sid: f.string(field::MANDATORY_LABEL),
                    image_nt: f.string(field::IMAGE_NAME).unwrap_or_default(),
                    cmdline: None,
                    user_sid: None,
                    token_integrity: None,
                })
            })?;
            // Capture command line + token while the process is guaranteed young.
            if let Raw::ProcStart {
                pid,
                ts,
                ppid,
                creator_pid,
                create_ft,
                session,
                label_sid,
                image_nt,
                ..
            } = r
            {
                let (mut cmdline, mut user_sid, mut token_integrity) = (None, None, None);
                if let Some(h) = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
                    cmdline = process_cmdline(&h);
                    let (s, i) = process_token_info(&h);
                    user_sid = s;
                    token_integrity = i;
                }
                return Some(Raw::ProcStart {
                    ts,
                    pid,
                    ppid,
                    creator_pid,
                    create_ft,
                    session,
                    label_sid,
                    image_nt,
                    cmdline,
                    user_sid,
                    token_integrity,
                });
            }
            None
        }
        eid::PROC_STOP => with_fields(rec, loc, |f| {
            Some(Raw::ProcStop {
                ts,
                pid: f.u32(field::PROCESS_ID)?,
                create_ft: f.u64(field::CREATE_TIME).unwrap_or(0),
                exit_code: f.u32(field::EXIT_CODE),
            })
        }),
        eid::IMAGE_LOAD => with_fields(rec, loc, |f| {
            Some(Raw::ImageLoad {
                ts,
                pid: f.u32(field::PROCESS_ID)?,
                image_nt: f.string(field::IMAGE_NAME)?,
            })
        }),
        _ => None,
    }
}

/// Kernel-File decoder. Create (12) goes to the translator (sensitive-path
/// filter) and, like 26/27/30, feeds the per-process ransomware aggregator
/// right here in the callback thread; summaries are sent as
/// [`Raw::FileActivity`].
fn decode_file(
    rec: &EventRecord,
    loc: &SchemaLocator,
    sink: &Sink,
    state: Option<&Mutex<FileState>>,
) -> Option<Raw> {
    let ts = ts_of(rec);
    let pid = rec.process_id();
    // Aggregate everything but the agent itself. pid 4 (System: SMB server
    // writes from a remote client) is aggregated too; the translator emits
    // its summaries with `remote_writer` and no local actor (V-H9).
    let agg = state.filter(|_| pid != sink.self_pid && pid != 0);
    let emit = |e: Option<crate::fileagg::AggEmit>| {
        if let Some(e) = e {
            sink.counters
                .file_activity_emitted
                .fetch_add(1, Ordering::Relaxed);
            sink.send(Raw::FileActivity {
                ts: e.ts,
                pid: e.pid,
                act: e.activity,
            });
        }
    };
    let id = rec.event_id();
    match id {
        eid::FILE_CREATE => {
            let (fo, name, co) = with_fields(rec, loc, |f| {
                Some((
                    f.u64(field::FILE_OBJECT).unwrap_or(0),
                    f.string(field::FILE_NAME)?,
                    f.u32(field::CREATE_OPTIONS).unwrap_or(0),
                ))
            })?;
            if let Some(st) = agg {
                let nt = name.to_ascii_lowercase();
                if let Ok(mut st) = st.lock() {
                    st.note_open(&nt, pid, ts, co);
                    let before = st.agg.dropped;
                    let e = st
                        .agg
                        .on_create(ts, pid, fo, &nt, co >> 24, is_directory_open(co));
                    sink.counters
                        .file_agg_dropped
                        .fetch_add(st.agg.dropped - before, Ordering::Relaxed);
                    drop(st);
                    emit(e);
                }
            }
            Some(Raw::FileCreate {
                ts,
                pid,
                file_object: fo,
                name_nt: name,
                create_options: co,
            })
        }
        eid::FILE_CREATE_NEW => {
            // A file was really created: aggregate it, and report it to the
            // sensitive-path filter as a create (persistence drops written
            // with open-or-create dispositions, lab VM).
            let (fo, name) = with_fields(rec, loc, |f| {
                Some((
                    f.u64(field::FILE_OBJECT).unwrap_or(0),
                    f.string(field::FILE_NAME)?,
                ))
            })?;
            if let Some(st) = agg {
                let nt = name.to_ascii_lowercase();
                let e = st.lock().ok().and_then(|mut st| {
                    let before = st.agg.dropped;
                    let e = st.agg.on_create_new(ts, pid, fo, &nt);
                    sink.counters
                        .file_agg_dropped
                        .fetch_add(st.agg.dropped - before, Ordering::Relaxed);
                    e
                });
                emit(e);
            }
            Some(Raw::FileCreate {
                ts,
                pid,
                file_object: fo,
                name_nt: name,
                create_options: CREATE_OPTIONS_FILE_CREATE,
            })
        }
        eid::FILE_DELETE_PATH | eid::FILE_RENAME_PATH => {
            let st = agg?;
            let (fo, path) = with_fields(rec, loc, |f| {
                Some((
                    f.u64(field::FILE_OBJECT).unwrap_or(0),
                    f.string(field::FILE_PATH).unwrap_or_default(),
                ))
            })?;
            let nt = path.to_ascii_lowercase();
            let e = st.lock().ok().and_then(|mut st| {
                let before = st.agg.dropped;
                let e = match id {
                    eid::FILE_DELETE_PATH => st.agg.on_delete(ts, pid, fo, &nt),
                    _ => st.agg.on_rename(ts, pid, fo, &nt),
                };
                if ts % 64 == 0 {
                    st.agg.gc(ts);
                }
                sink.counters
                    .file_agg_dropped
                    .fetch_add(st.agg.dropped - before, Ordering::Relaxed);
                e
            });
            emit(e);
            None
        }
        eid::FILE_READ if FILE_READ_EVENTS => with_fields(rec, loc, |f| {
            Some(Raw::FileRead {
                ts,
                pid,
                file_object: f.u64(field::FILE_OBJECT)?,
            })
        }),
        _ => None,
    }
}

fn decode_network(rec: &EventRecord, loc: &SchemaLocator) -> Option<Raw> {
    let ts = ts_of(rec);
    let id = rec.event_id();
    with_fields(rec, loc, |f| {
        let pid = f.u32(field::NET_PID)?;
        let dst = net_addr(&f.bytes(field::NET_DADDR)?)?;
        let dport = net_port(&f.bytes(field::NET_DPORT)?)?;
        let sport = net_port(&f.bytes(field::NET_SPORT)?).unwrap_or(0);
        match id {
            eid::TCP4_CONNECT | eid::TCP6_CONNECT => Some(Raw::NetConnect {
                ts,
                pid,
                dst,
                dport,
                sport,
            }),
            eid::TCP4_SEND | eid::TCP6_SEND => Some(Raw::NetSend {
                ts,
                pid,
                tcp: true,
                dst,
                dport,
                sport,
                size: f.u32(field::NET_SIZE).unwrap_or(0) as u64,
            }),
            eid::UDP4_SEND | eid::UDP6_SEND => Some(Raw::NetSend {
                ts,
                pid,
                tcp: false,
                dst,
                dport,
                sport,
                size: f.u32(field::NET_SIZE).unwrap_or(0) as u64,
            }),
            eid::TCP4_DISCONNECT | eid::TCP6_DISCONNECT => Some(Raw::NetClose {
                pid,
                dst,
                dport,
                sport,
            }),
            _ => None,
        }
    })
}

/// Kernel-Audit-API-Calls. `lsass_pid` (0 = unknown) and `failed_lsass`
/// (policy `sensors.credential_access`) select the failed opens that are
/// kept: only attempts on lsass (e.g. blocked by LSA protection).
fn decode_audit_api(
    rec: &EventRecord,
    loc: &SchemaLocator,
    lsass_pid: u32,
    failed_lsass: bool,
) -> Option<Raw> {
    let ts = ts_of(rec);
    let pid = rec.process_id();
    match rec.event_id() {
        eid::API_OPEN_PROCESS => with_fields(rec, loc, |f| {
            let return_code = f.u32(field::RETURN_CODE).unwrap_or(0);
            let target_pid = f.u32(field::TARGET_PROCESS_ID)?;
            // 0xFFFFFFFF: sentinel for an unresolved target.
            if target_pid == u32::MAX || target_pid == pid {
                return None;
            }
            if return_code != 0 && !(failed_lsass && lsass_pid != 0 && target_pid == lsass_pid) {
                return None;
            }
            let access = f.u32(field::DESIRED_ACCESS)?;
            if !is_interesting_process_access(access) {
                return None;
            }
            Some(Raw::OpenProcess {
                ts,
                pid,
                target_pid,
                access,
                return_code,
            })
        }),
        eid::API_OPEN_THREAD => with_fields(rec, loc, |f| {
            if f.u32(field::RETURN_CODE).unwrap_or(0) != 0 {
                return None;
            }
            let target_pid = f.u32(field::TARGET_PROCESS_ID)?;
            let access = f.u32(field::DESIRED_ACCESS)?;
            if target_pid == pid || !is_interesting_thread_access(access) {
                return None;
            }
            Some(Raw::OpenThread {
                ts,
                pid,
                target_pid,
                access,
            })
        }),
        eid::API_SET_CONTEXT_THREAD => with_fields(rec, loc, |f| {
            if f.u32(field::RETURN_CODE).unwrap_or(0) == 0 {
                Some(Raw::SetContext { ts, pid })
            } else {
                None
            }
        }),
        eid::API_TERMINATE_PROCESS => with_fields(rec, loc, |f| {
            let target_pid = f.u32(field::TARGET_PROCESS_ID)?;
            if target_pid == pid || target_pid == 0 || f.u32(field::RETURN_CODE).unwrap_or(0) != 0 {
                return None;
            }
            Some(Raw::Terminate {
                ts,
                pid,
                target_pid,
            })
        }),
        _ => None,
    }
}

/// Kernel-Registry SetValueKey (5) / DeleteValueKey (6). On build 26200
/// `KeyName` and `CapturedData` are empty, so these mostly serve writer
/// attribution for the registry watcher (pid, KeyObject, ValueName). Events
/// whose `KeyName` is present but outside the curated set are dropped.
fn decode_registry(rec: &EventRecord, loc: &SchemaLocator) -> Option<Raw> {
    let id = rec.event_id();
    if id != eid::REG_SET_VALUE && id != eid::REG_DELETE_VALUE {
        return None;
    }
    let ts = ts_of(rec);
    let pid = rec.process_id();
    with_fields(rec, loc, |f| {
        if f.u32(field::STATUS).unwrap_or(0) != 0 {
            return None;
        }
        let raw_key = f.string(field::KEY_NAME).unwrap_or_default();
        let key = if raw_key.is_empty() {
            String::new()
        } else {
            let k = normalize_reg_key(&raw_key);
            if !is_interesting_reg_key(&k) {
                return None;
            }
            k
        };
        let set = id == eid::REG_SET_VALUE;
        Some(Raw::RegEtw {
            ts,
            pid,
            key_object: f.u64(field::KEY_OBJECT).unwrap_or(0),
            key,
            value_name: f.string(field::VALUE_NAME).unwrap_or_default(),
            op: if set {
                RegistryOp::Set
            } else {
                RegistryOp::DeleteValue
            },
            ty: if set {
                f.u32(field::REG_TYPE).unwrap_or(0)
            } else {
                0
            },
            data: if set {
                f.bytes(field::CAPTURED_DATA).unwrap_or_default()
            } else {
                Vec::new()
            },
        })
    })
}

/// TaskScheduler 106/140/141, SCM 7045, WMI-Activity 5861 (field names from
/// the manifests on build 26200; see [`crate::persist`]). The task XML /
/// service key is read by the enrichment worker, never in this callback
/// (V-M9); the record is queued there and nothing is returned.
fn decode_persist(rec: &EventRecord, loc: &SchemaLocator, sink: &Sink) -> Option<Raw> {
    use crate::persist::eid as p;
    let id = rec.event_id();
    let names: &[&str] = match id {
        p::TASK_REGISTERED => &["TaskName", "UserContext"],
        p::TASK_UPDATED | p::TASK_DELETED => &["TaskName", "UserName"],
        p::SCM_SERVICE_INSTALLED => &[
            "ServiceName",
            "ImagePath",
            "ServiceType",
            "StartType",
            "AccountName",
        ],
        p::WMI_ESS_TO_CONSUMER_BINDING => &["Namespace", "ESS", "CONSUMER", "PossibleCause"],
        _ => return None,
    };
    let fields: HashMap<String, String> = with_fields(rec, loc, |f| {
        Some(
            names
                .iter()
                .filter_map(|n| f.string(n).map(|v| (n.to_string(), v)))
                .collect(),
        )
    })?;
    let record = record_from_fields(id, &fields)?;
    super::persist::submit(sink, ts_of(rec), rec.process_id(), record);
    None
}

fn decode_dns(rec: &EventRecord, loc: &SchemaLocator) -> Option<Raw> {
    if rec.event_id() != eid::DNS_QUERY_COMPLETED {
        return None;
    }
    let ts = ts_of(rec);
    let pid = rec.process_id();
    with_fields(rec, loc, |f| {
        // 0 = answered; 9003 (DNS_ERROR_RCODE_NAME_ERROR, NXDOMAIN) and 9501
        // (DNS_INFO_NO_RECORDS) are kept with no answers: failed lookups are
        // signal (DGA, dead C2), and seen on real hosts as 3008 events.
        let status = f.u32(field::QUERY_STATUS).unwrap_or(1);
        if !crate::etwparse::dns_status_is_reportable(status) {
            return None;
        }
        let results = f.string(field::QUERY_RESULTS).unwrap_or_default();
        if status == 0 && results.is_empty() {
            return None;
        }
        Some(Raw::Dns {
            ts,
            pid,
            qname: f.string(field::QUERY_NAME)?,
            results,
        })
    })
}

fn decode_dpapi(rec: &EventRecord, loc: &SchemaLocator) -> Option<Raw> {
    if rec.event_id() != eid::DPAPI_DEF_INFORMATION {
        return None;
    }
    let ts = ts_of(rec);
    with_fields(rec, loc, |f| {
        let op = f.string(field::OPERATION_TYPE)?;
        if !op.eq_ignore_ascii_case("SPCryptUnprotect") {
            return None;
        }
        Some(Raw::Dpapi {
            ts,
            caller_pid: f.u32(field::CALLER_PROCESS_ID)?,
            caller_create_ft: f.u64(field::CALLER_PROCESS_CREATION_TIME),
            description: f.string(field::DATA_DESCRIPTION).unwrap_or_default(),
        })
    })
}

fn decode_powershell(rec: &EventRecord, loc: &SchemaLocator) -> Option<Raw> {
    if rec.event_id() != eid::PS_SCRIPT_BLOCK {
        return None;
    }
    let ts = ts_of(rec);
    let pid = rec.process_id();
    with_fields(rec, loc, |f| {
        Some(Raw::Script {
            ts,
            pid,
            text: f.string(field::SCRIPT_BLOCK_TEXT)?,
        })
    })
}

fn decode_mof_process(rec: &EventRecord, loc: &SchemaLocator) -> Option<Raw> {
    // Classic kernel process events: opcode 1 = Start.
    if rec.opcode() != 1 {
        return None;
    }
    with_fields(rec, loc, |f| {
        Some(Raw::CmdLine {
            pid: f.u32(field::MOF_PROCESS_ID)?,
            cmdline: f.string(field::MOF_COMMAND_LINE)?,
        })
    })
}

// ------------------------------------------------------------------ sessions

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    Core,
    Io,
    File,
    Persist,
    ProcCmd,
}

impl SessionKind {
    pub fn name(&self) -> &'static str {
        match self {
            SessionKind::Core => consts::SESSION_CORE,
            SessionKind::Io => consts::SESSION_IO,
            SessionKind::File => consts::SESSION_FILE,
            SessionKind::Persist => consts::SESSION_PERSIST,
            SessionKind::ProcCmd => consts::SESSION_PROC_CMDLINE,
        }
    }
    /// Sessions the watchdog keeps alive for this configuration.
    pub fn required(opts: &SensorOpts) -> Vec<SessionKind> {
        let mut v = vec![SessionKind::Core, SessionKind::Io, SessionKind::File];
        if opts.persistence {
            v.push(SessionKind::Persist);
        }
        v
    }
    fn providers(&self, opts: &SensorOpts) -> Vec<&'static str> {
        match self {
            SessionKind::Core => vec![
                provider::KERNEL_PROCESS,
                provider::KERNEL_AUDIT_API,
                provider::KERNEL_REGISTRY,
                provider::CRYPTO_DPAPI,
            ],
            SessionKind::File => vec![provider::KERNEL_FILE],
            SessionKind::Persist => vec![
                provider::TASK_SCHEDULER,
                provider::SCM,
                provider::WMI_ACTIVITY,
            ],
            SessionKind::Io => {
                let mut v = vec![provider::KERNEL_NETWORK];
                if opts.dns {
                    v.push(provider::DNS_CLIENT);
                }
                if opts.script_content {
                    v.push(provider::POWERSHELL);
                }
                v
            }
            SessionKind::ProcCmd => vec![],
        }
    }
}

#[derive(Clone)]
pub struct SensorOpts {
    pub dns: bool,
    pub script_content: bool,
    /// `policy.sensors.file_activity`: Kernel-File 26/27/30 + aggregation.
    pub file_activity: bool,
    /// `policy.sensors.persistence`: Kestrel-Persist session.
    pub persistence: bool,
    /// `policy.sensors.credential_access`: failed lsass opens.
    pub credential_access: bool,
    /// Aggregator state (shared with the canary poller).
    pub file_state: Arc<Mutex<FileState>>,
}

fn props(flush_secs: u64, buffers: u32) -> TraceProperties {
    TraceProperties {
        buffer_size: 64,
        min_buffer: buffers,
        max_buffer: buffers,
        flush_timer: Duration::from_secs(flush_secs),
        log_file_mode: LoggingMode::EVENT_TRACE_REAL_TIME_MODE
            | LoggingMode::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
    }
}

fn prov(
    guid: &str,
    any: u64,
    level: u8,
    ids: Vec<u16>,
    sink: &Sink,
    dec: impl Fn(&EventRecord, &SchemaLocator) -> Option<Raw> + Send + Sync + 'static,
) -> Provider {
    let s = sink.clone();
    Provider::by_guid(guid)
        .any(any)
        .level(level)
        .add_filter(EventFilter::ByEventIds(ids))
        .add_callback(move |rec: &EventRecord, loc: &SchemaLocator| {
            // A panic must never unwind into ETW (it would kill the session).
            if let Ok(Some(r)) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dec(rec, loc)))
            {
                s.send(r);
            }
        })
        .build()
}

pub enum Running {
    User(UserTrace),
    Kernel(KernelTrace),
}

pub struct Session {
    pub kind: SessionKind,
    pub trace: Option<Running>,
    pub alive: Arc<AtomicBool>,
    pub started: Instant,
    /// Loss counters at last poll (session counters reset on restart).
    pub last_lost: (u64, u64),
}

pub fn start_session(kind: SessionKind, sink: &Sink, opts: &SensorOpts) -> anyhow::Result<Session> {
    let name = kind.name().to_string();
    // Stale session from a previous agent instance (crash, update).
    let _ = stop_trace_by_name(&name);
    let alive = Arc::new(AtomicBool::new(true));
    let a2 = alive.clone();
    let trace = match kind {
        SessionKind::Core => {
            let b = UserTrace::new()
                .named(name.clone())
                .set_trace_properties(props(1, 32))
                .enable(prov(
                    provider::KERNEL_PROCESS,
                    kw::PROC_PROCESS | kw::PROC_IMAGE,
                    5,
                    vec![eid::PROC_START, eid::PROC_STOP, eid::IMAGE_LOAD],
                    sink,
                    decode_process,
                ))
                .enable({
                    let counters = sink.counters.clone();
                    let failed_lsass = opts.credential_access;
                    prov(
                        provider::KERNEL_AUDIT_API,
                        kw::ALL,
                        5,
                        vec![
                            eid::API_TERMINATE_PROCESS,
                            eid::API_SET_CONTEXT_THREAD,
                            eid::API_OPEN_PROCESS,
                            eid::API_OPEN_THREAD,
                        ],
                        sink,
                        move |rec, loc| {
                            let lsass = counters.lsass_pid.load(Ordering::Relaxed);
                            decode_audit_api(rec, loc, lsass, failed_lsass)
                        },
                    )
                })
                .enable(prov(
                    provider::KERNEL_REGISTRY,
                    kw::REG_SET_VALUE | kw::REG_DELETE_VALUE,
                    5,
                    vec![eid::REG_SET_VALUE, eid::REG_DELETE_VALUE],
                    sink,
                    decode_registry,
                ))
                .enable(prov(
                    provider::CRYPTO_DPAPI,
                    kw::ALL,
                    5,
                    vec![eid::DPAPI_DEF_INFORMATION],
                    sink,
                    decode_dpapi,
                ));
            let (t, h) = b
                .start()
                .map_err(|e| anyhow::anyhow!("start {name}: {e:?}"))?;
            std::thread::Builder::new()
                .name(format!("etw-{name}"))
                .spawn(move || {
                    let _ = UserTrace::process_from_handle(h);
                    a2.store(false, Ordering::SeqCst);
                })?;
            Running::User(t)
        }
        SessionKind::File => {
            // CreateNewFile (30) always: it is the only reliable "a file was
            // created" signal (open-or-create dispositions say nothing) and
            // new files are far rarer than opens.
            let mut file_kw = kw::FILE_CREATE | kw::FILE_CREATE_NEW_FILE;
            let mut file_ids = vec![eid::FILE_CREATE, eid::FILE_CREATE_NEW];
            if FILE_READ_EVENTS {
                file_kw |= kw::FILE_READ;
                file_ids.push(eid::FILE_READ);
            }
            if opts.file_activity {
                // Never 0x20 (all I/O) or 0x200 (Write): volume.
                file_kw |= kw::FILE_DELETE_PATH | kw::FILE_RENAME_SETLINK_PATH;
                file_ids.extend([eid::FILE_DELETE_PATH, eid::FILE_RENAME_PATH]);
            }
            let state = opts.file_activity.then(|| opts.file_state.clone());
            let s2 = sink.clone();
            let (t, h) = UserTrace::new()
                .named(name.clone())
                .set_trace_properties(props(1, 128))
                .enable(prov(
                    provider::KERNEL_FILE,
                    file_kw,
                    5,
                    file_ids,
                    sink,
                    move |rec, loc| decode_file(rec, loc, &s2, state.as_deref()),
                ))
                .start()
                .map_err(|e| anyhow::anyhow!("start {name}: {e:?}"))?;
            std::thread::Builder::new()
                .name(format!("etw-{name}"))
                .spawn(move || {
                    let _ = UserTrace::process_from_handle(h);
                    a2.store(false, Ordering::SeqCst);
                })?;
            Running::User(t)
        }
        SessionKind::Persist => {
            use crate::persist::eid as p;
            let (s1, s2, s3) = (sink.clone(), sink.clone(), sink.clone());
            let (t, h) = UserTrace::new()
                .named(name.clone())
                .set_trace_properties(props(1, 8))
                .enable(prov(
                    provider::TASK_SCHEDULER,
                    kw::ALL,
                    5,
                    vec![p::TASK_REGISTERED, p::TASK_UPDATED, p::TASK_DELETED],
                    sink,
                    move |rec, loc| decode_persist(rec, loc, &s1),
                ))
                .enable(prov(
                    provider::WMI_ACTIVITY,
                    kw::ALL,
                    5,
                    vec![p::WMI_ESS_TO_CONSUMER_BINDING],
                    sink,
                    move |rec, loc| decode_persist(rec, loc, &s2),
                ))
                .enable(prov(
                    provider::SCM,
                    kw::ALL,
                    5,
                    vec![p::SCM_SERVICE_INSTALLED],
                    sink,
                    move |rec, loc| decode_persist(rec, loc, &s3),
                ))
                .start()
                .map_err(|e| anyhow::anyhow!("start {name}: {e:?}"))?;
            std::thread::Builder::new()
                .name(format!("etw-{name}"))
                .spawn(move || {
                    let _ = UserTrace::process_from_handle(h);
                    a2.store(false, Ordering::SeqCst);
                })?;
            Running::User(t)
        }
        SessionKind::Io => {
            let mut b = UserTrace::new()
                .named(name.clone())
                .set_trace_properties(props(5, 128))
                .enable(prov(
                    provider::KERNEL_NETWORK,
                    kw::NET_IPV4 | kw::NET_IPV6,
                    5,
                    vec![
                        eid::TCP4_SEND,
                        eid::TCP4_CONNECT,
                        eid::TCP4_DISCONNECT,
                        eid::TCP6_SEND,
                        eid::TCP6_CONNECT,
                        eid::TCP6_DISCONNECT,
                        eid::UDP4_SEND,
                        eid::UDP6_SEND,
                    ],
                    sink,
                    decode_network,
                ));
            if opts.dns {
                b = b.enable(prov(
                    provider::DNS_CLIENT,
                    kw::ALL,
                    5,
                    vec![eid::DNS_QUERY_COMPLETED],
                    sink,
                    decode_dns,
                ));
            }
            if opts.script_content {
                b = b.enable(prov(
                    provider::POWERSHELL,
                    kw::ALL,
                    5,
                    vec![eid::PS_SCRIPT_BLOCK],
                    sink,
                    decode_powershell,
                ));
            }
            let (t, h) = b
                .start()
                .map_err(|e| anyhow::anyhow!("start {name}: {e:?}"))?;
            std::thread::Builder::new()
                .name(format!("etw-{name}"))
                .spawn(move || {
                    let _ = UserTrace::process_from_handle(h);
                    a2.store(false, Ordering::SeqCst);
                })?;
            Running::User(t)
        }
        SessionKind::ProcCmd => {
            let s = sink.clone();
            let p = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
                .add_callback(move |rec: &EventRecord, loc: &SchemaLocator| {
                    if let Ok(Some(r)) =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            decode_mof_process(rec, loc)
                        }))
                    {
                        s.send(r);
                    }
                })
                .build();
            let (t, h) = KernelTrace::new()
                .named(name.clone())
                .set_trace_properties(props(1, 8))
                .enable(p)
                .start()
                .map_err(|e| anyhow::anyhow!("start {name}: {e:?}"))?;
            std::thread::Builder::new()
                .name(format!("etw-{name}"))
                .spawn(move || {
                    let _ = KernelTrace::process_from_handle(h);
                    a2.store(false, Ordering::SeqCst);
                })?;
            Running::Kernel(t)
        }
    };
    Ok(Session {
        kind,
        trace: Some(trace),
        alive,
        started: Instant::now(),
        last_lost: (0, 0),
    })
}

impl Session {
    pub fn stop(&mut self) {
        match self.trace.take() {
            Some(Running::User(t)) => {
                let _ = t.stop();
            }
            Some(Running::Kernel(t)) => {
                let _ = t.stop();
            }
            None => {}
        }
        let _ = stop_trace_by_name(self.kind.name());
    }
}

/// Session statistics from ControlTraceW(EVENT_TRACE_CONTROL_QUERY).
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionQuery {
    pub logger_id: u16,
    pub events_lost: u64,
    pub buffers_lost: u64,
}

pub fn query_session(name: &str) -> Option<SessionQuery> {
    // EVENT_TRACE_PROPERTIES followed by room for logger and log-file names.
    const NAME_BYTES: usize = 1024 * 2;
    let base = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total = base + 2 * NAME_BYTES;
    let mut buf = vec![0u64; total.div_ceil(8)];
    let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    let w = wide(name);
    unsafe {
        (*p).Wnode.BufferSize = total as u32;
        (*p).LoggerNameOffset = base as u32;
        (*p).LogFileNameOffset = (base + NAME_BYTES) as u32;
        let rc = ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            w.as_ptr(),
            p,
            EVENT_TRACE_CONTROL_QUERY,
        );
        if rc != ERROR_SUCCESS {
            return None;
        }
        Some(SessionQuery {
            logger_id: ((*p).Wnode.Anonymous1.HistoricalContext & 0xFFFF) as u16,
            events_lost: (*p).EventsLost as u64,
            buffers_lost: (*p).RealTimeBuffersLost as u64 + (*p).LogBuffersLost as u64,
        })
    }
}

/// Some(false) if the provider has registered instances and none is enabled
/// for `logger_id` (someone disabled it on our session); None when the
/// provider currently has no registered instance (e.g. PowerShell not
/// running) or the query failed.
pub fn provider_enabled_for(guid_str: &str, logger_id: u16) -> Option<bool> {
    let g = windows_sys::core::GUID::from_u128(
        u128::from_str_radix(&guid_str.replace('-', ""), 16).ok()?,
    );
    let mut buf = vec![0u64; 2048];
    let mut ret = 0u32;
    let rc = unsafe {
        EnumerateTraceGuidsEx(
            TraceGuidQueryInfo,
            &g as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<windows_sys::core::GUID>() as u32,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            (buf.len() * 8) as u32,
            &mut ret,
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(buf.as_ptr() as *const u8, (ret as usize).min(buf.len() * 8))
    };
    if bytes.len() < std::mem::size_of::<TRACE_GUID_INFO>() {
        return None;
    }
    let info = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const TRACE_GUID_INFO) };
    if info.InstanceCount == 0 {
        return None;
    }
    let mut off = std::mem::size_of::<TRACE_GUID_INFO>();
    for _ in 0..info.InstanceCount {
        if off + std::mem::size_of::<TRACE_PROVIDER_INSTANCE_INFO>() > bytes.len() {
            break;
        }
        let inst = unsafe {
            std::ptr::read_unaligned(bytes.as_ptr().add(off) as *const TRACE_PROVIDER_INSTANCE_INFO)
        };
        let mut e_off = off + std::mem::size_of::<TRACE_PROVIDER_INSTANCE_INFO>();
        for _ in 0..inst.EnableCount {
            if e_off + std::mem::size_of::<TRACE_ENABLE_INFO>() > bytes.len() {
                break;
            }
            let ei = unsafe {
                std::ptr::read_unaligned(bytes.as_ptr().add(e_off) as *const TRACE_ENABLE_INFO)
            };
            if ei.IsEnabled != 0 && ei.LoggerId == logger_id {
                return Some(true);
            }
            e_off += std::mem::size_of::<TRACE_ENABLE_INFO>();
        }
        if inst.NextOffset == 0 {
            break;
        }
        off += inst.NextOffset as usize;
    }
    Some(false)
}

/// Providers whose disablement on our session is checked by the watchdog
/// (kernel providers are always registered, so absence is meaningful).
pub fn watched_providers(kind: SessionKind, opts: &SensorOpts) -> Vec<&'static str> {
    // Manifest providers that may be unregistered at times (PowerShell not
    // running, …) are not checked; neither are the persistence providers.
    kind.providers(opts)
        .into_iter()
        .filter(|p| {
            !matches!(
                *p,
                provider::POWERSHELL
                    | provider::DNS_CLIENT
                    | provider::CRYPTO_DPAPI
                    | provider::TASK_SCHEDULER
                    | provider::SCM
                    | provider::WMI_ACTIVITY
            )
        })
        .collect()
}
