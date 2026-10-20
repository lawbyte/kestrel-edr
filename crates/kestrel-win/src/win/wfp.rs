//! Windows Filtering Platform enforcement: host isolation, destination and
//! per-image blocks, hard permits for the agent's server.
//!
//! Objects: provider [`consts::wfp::PROVIDER_KEY`] and sublayer
//! [`consts::wfp::SUBLAYER_KEY`] (weight 0xFFFF), both persistent. Filters
//! are persistent + `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` (hard actions) with
//! agent-chosen keys recorded in `<state>\wfp_state.json`, so they survive
//! reboots (isolation stays in force even before the agent starts) and can be
//! removed / TTL-expired / repaired by key.

use super::util::*;
use crate::consts;
use crate::wfp_plan::{Action, BlockRecord, Cond, FilterSpec, Layer, WfpState};
use std::ffi::c_void;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

const RPC_C_AUTHN_WINNT: u32 = 10;
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;
const FWP_E_NOT_FOUND: u32 = 0x8032_0008;
const FWP_E_PROVIDER_NOT_FOUND: u32 = 0x8032_0005;
const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;

fn g(t: (u32, u16, u16, [u8; 8])) -> GUID {
    GUID {
        data1: t.0,
        data2: t.1,
        data3: t.2,
        data4: t.3,
    }
}

fn provider_key() -> GUID {
    g(consts::wfp::PROVIDER_KEY)
}
fn sublayer_key() -> GUID {
    g(consts::wfp::SUBLAYER_KEY)
}

fn guid_from_str(s: &str) -> Option<GUID> {
    uuid::Uuid::parse_str(s.trim_matches(|c| c == '{' || c == '}'))
        .ok()
        .map(|u| GUID::from_u128(u.as_u128()))
}

fn layer_guid(l: Layer) -> GUID {
    match l {
        Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::RecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::RecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}

fn err(op: &str, rc: u32) -> String {
    format!("{op} failed: 0x{rc:08X}")
}

/// Engine handle (non-dynamic session: persistent objects outlive it).
pub struct Engine(HANDLE);

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}

unsafe impl Send for Engine {}

impl Engine {
    pub fn open() -> Result<Engine, String> {
        let mut h: HANDLE = std::ptr::null_mut();
        let rc = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null(),
                std::ptr::null(),
                &mut h,
            )
        };
        if rc != 0 {
            return Err(err("FwpmEngineOpen0 (is the BFE service running?)", rc));
        }
        Ok(Engine(h))
    }

    fn txn<T>(&self, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let rc = unsafe { FwpmTransactionBegin0(self.0, 0) };
        if rc != 0 {
            return Err(err("FwpmTransactionBegin0", rc));
        }
        match f() {
            Ok(v) => {
                let rc = unsafe { FwpmTransactionCommit0(self.0) };
                if rc != 0 {
                    unsafe { FwpmTransactionAbort0(self.0) };
                    return Err(err("FwpmTransactionCommit0", rc));
                }
                Ok(v)
            }
            Err(e) => {
                unsafe { FwpmTransactionAbort0(self.0) };
                Err(e)
            }
        }
    }

    /// Create our provider + max-weight sublayer if missing.
    pub fn ensure_objects(&self) -> Result<(), String> {
        let mut pname = wide("Kestrel EDR");
        let mut pdesc = wide("Kestrel EDR containment filters");
        let mut sname = wide("Kestrel EDR sublayer");
        let mut sdesc = wide("Kestrel EDR isolation and blocking (max weight)");
        let mut pk = provider_key();
        self.txn(|| unsafe {
            let mut p: FWPM_PROVIDER0 = std::mem::zeroed();
            p.providerKey = provider_key();
            p.displayData.name = pname.as_mut_ptr();
            p.displayData.description = pdesc.as_mut_ptr();
            p.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
            let rc = FwpmProviderAdd0(self.0, &p, std::ptr::null_mut());
            if rc != 0 && rc != FWP_E_ALREADY_EXISTS {
                return Err(err("FwpmProviderAdd0", rc));
            }
            let mut s: FWPM_SUBLAYER0 = std::mem::zeroed();
            s.subLayerKey = sublayer_key();
            s.displayData.name = sname.as_mut_ptr();
            s.displayData.description = sdesc.as_mut_ptr();
            s.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
            s.providerKey = &mut pk;
            s.weight = consts::wfp::SUBLAYER_WEIGHT;
            let rc = FwpmSubLayerAdd0(self.0, &s, std::ptr::null_mut());
            if rc != 0 && rc != FWP_E_ALREADY_EXISTS {
                return Err(err("FwpmSubLayerAdd0", rc));
            }
            Ok(())
        })
    }

    /// Add filters atomically; returns their keys.
    pub fn add_filters(&self, specs: &[FilterSpec]) -> Result<Vec<String>, String> {
        self.ensure_objects()?;
        // Resolve app ids up front (they need freeing with FwpmFreeMemory0).
        let mut app_ids: Vec<(String, *mut FWP_BYTE_BLOB)> = Vec::new();
        for s in specs {
            for c in &s.conditions {
                if let Cond::AppPath(p) = c {
                    if app_ids.iter().any(|(q, _)| q.eq_ignore_ascii_case(p)) {
                        continue;
                    }
                    let w = wide(p);
                    let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
                    let rc = unsafe { FwpmGetAppIdFromFileName0(w.as_ptr(), &mut blob) };
                    if rc != 0 {
                        for (_, b) in &mut app_ids {
                            unsafe {
                                FwpmFreeMemory0(b as *mut *mut FWP_BYTE_BLOB as *mut *mut c_void)
                            };
                        }
                        return Err(format!("{} for {p}", err("FwpmGetAppIdFromFileName0", rc)));
                    }
                    app_ids.push((p.clone(), blob));
                }
            }
        }
        let result = self.txn(|| {
            let mut keys = Vec::new();
            for spec in specs {
                let key = uuid::Uuid::new_v4();
                self.add_one(spec, key, &app_ids)?;
                keys.push(key.to_string());
            }
            Ok(keys)
        });
        for (_, b) in &mut app_ids {
            unsafe { FwpmFreeMemory0(b as *mut *mut FWP_BYTE_BLOB as *mut *mut c_void) };
        }
        result
    }

    fn add_one(
        &self,
        spec: &FilterSpec,
        key: uuid::Uuid,
        app_ids: &[(String, *mut FWP_BYTE_BLOB)],
    ) -> Result<(), String> {
        // Storage that must outlive FwpmFilterAdd0.
        let mut name = wide(&spec.name);
        let mut desc = wide("Managed by Kestrel EDR");
        let mut pk = provider_key();
        let mut v6: Vec<Box<FWP_BYTE_ARRAY16>> = Vec::new();
        let mut conds: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
        for c in &spec.conditions {
            let mut fc: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
            fc.matchType = FWP_MATCH_EQUAL;
            match c {
                Cond::RemoteAddr(IpAddr::V4(a)) => {
                    fc.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    fc.conditionValue.r#type = FWP_UINT32;
                    fc.conditionValue.Anonymous.uint32 = u32::from(*a); // host byte order
                }
                Cond::RemoteAddr(IpAddr::V6(a)) => {
                    fc.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    let mut b = Box::new(FWP_BYTE_ARRAY16 {
                        byteArray16: a.octets(),
                    });
                    fc.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
                    fc.conditionValue.Anonymous.byteArray16 = &mut *b;
                    v6.push(b);
                }
                Cond::RemotePort(p) => {
                    fc.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                    fc.conditionValue.r#type = FWP_UINT16;
                    fc.conditionValue.Anonymous.uint16 = *p;
                }
                Cond::LocalPort(p) => {
                    fc.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
                    fc.conditionValue.r#type = FWP_UINT16;
                    fc.conditionValue.Anonymous.uint16 = *p;
                }
                Cond::Protocol(p) => {
                    fc.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                    fc.conditionValue.r#type = FWP_UINT8;
                    fc.conditionValue.Anonymous.uint8 = *p;
                }
                Cond::AppPath(p) => {
                    let blob = app_ids
                        .iter()
                        .find(|(q, _)| q.eq_ignore_ascii_case(p))
                        .map(|(_, b)| *b)
                        .ok_or("app id missing")?;
                    fc.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                    fc.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                    fc.conditionValue.Anonymous.byteBlob = blob;
                }
                Cond::Loopback => {
                    fc.fieldKey = FWPM_CONDITION_FLAGS;
                    fc.matchType = FWP_MATCH_FLAGS_ALL_SET;
                    fc.conditionValue.r#type = FWP_UINT32;
                    fc.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                }
            }
            conds.push(fc);
        }
        let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        f.filterKey = GUID::from_u128(key.as_u128());
        f.displayData.name = name.as_mut_ptr();
        f.displayData.description = desc.as_mut_ptr();
        f.flags = FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        f.providerKey = &mut pk;
        f.layerKey = layer_guid(spec.layer);
        f.subLayerKey = sublayer_key();
        f.weight.r#type = FWP_UINT8;
        f.weight.Anonymous.uint8 = spec.weight;
        f.numFilterConditions = conds.len() as u32;
        f.filterCondition = if conds.is_empty() {
            std::ptr::null_mut()
        } else {
            conds.as_mut_ptr()
        };
        f.action.r#type = match spec.action {
            Action::Permit => FWP_ACTION_PERMIT,
            Action::Block => FWP_ACTION_BLOCK,
        };
        let mut id = 0u64;
        let rc = unsafe { FwpmFilterAdd0(self.0, &f, std::ptr::null_mut(), &mut id) };
        drop(v6);
        if rc != 0 {
            return Err(format!("{} ('{}')", err("FwpmFilterAdd0", rc), spec.name));
        }
        Ok(())
    }

    /// Delete filters by key; missing ones are fine.
    pub fn delete_filters(&self, keys: &[String]) -> Result<usize, String> {
        self.txn(|| {
            let mut n = 0;
            for k in keys {
                let Some(gk) = guid_from_str(k) else { continue };
                let rc = unsafe { FwpmFilterDeleteByKey0(self.0, &gk) };
                if rc == 0 {
                    n += 1;
                } else if rc != FWP_E_FILTER_NOT_FOUND && rc != FWP_E_NOT_FOUND {
                    return Err(err("FwpmFilterDeleteByKey0", rc));
                }
            }
            Ok(n)
        })
    }

    pub fn filter_exists(&self, key: &str) -> bool {
        let Some(gk) = guid_from_str(key) else {
            return false;
        };
        let mut f: *mut FWPM_FILTER0 = std::ptr::null_mut();
        let rc = unsafe { FwpmFilterGetByKey0(self.0, &gk, &mut f) };
        if rc == 0 && !f.is_null() {
            unsafe { FwpmFreeMemory0(&mut f as *mut *mut FWPM_FILTER0 as *mut *mut c_void) };
            true
        } else {
            false
        }
    }

    /// Keys of every filter owned by our provider (for full cleanup).
    pub fn our_filter_keys(&self) -> Vec<GUID> {
        let mut out = Vec::new();
        unsafe {
            let mut pk = provider_key();
            let mut t: FWPM_FILTER_ENUM_TEMPLATE0 = std::mem::zeroed();
            t.providerKey = &mut pk;
            t.enumType = FWP_FILTER_ENUM_OVERLAPPING;
            t.actionMask = 0xFFFF_FFFF;
            for layer in Layer::ALL {
                t.layerKey = layer_guid(layer);
                let mut eh: HANDLE = std::ptr::null_mut();
                if FwpmFilterCreateEnumHandle0(self.0, &t, &mut eh) != 0 {
                    continue;
                }
                loop {
                    let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
                    let mut n = 0u32;
                    if FwpmFilterEnum0(self.0, eh, 256, &mut entries, &mut n) != 0 || n == 0 {
                        if !entries.is_null() {
                            FwpmFreeMemory0(
                                &mut entries as *mut *mut *mut FWPM_FILTER0 as *mut *mut c_void,
                            );
                        }
                        break;
                    }
                    for i in 0..n as usize {
                        let f = *entries.add(i);
                        if !f.is_null()
                            && !(*f).providerKey.is_null()
                            && guid_eq(&*(*f).providerKey, &pk)
                        {
                            out.push((*f).filterKey);
                        }
                    }
                    FwpmFreeMemory0(
                        &mut entries as *mut *mut *mut FWPM_FILTER0 as *mut *mut c_void,
                    );
                }
                FwpmFilterDestroyEnumHandle0(self.0, eh);
            }
        }
        out
    }
}

fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

/// Remove every Kestrel WFP object (used by uninstall). Isolation is lifted.
pub fn remove_all_wfp_objects() -> anyhow::Result<()> {
    let e = Engine::open().map_err(anyhow::Error::msg)?;
    let keys = e.our_filter_keys();
    e.txn(|| unsafe {
        for k in &keys {
            FwpmFilterDeleteByKey0(e.0, k);
        }
        let sk = sublayer_key();
        let rc = FwpmSubLayerDeleteByKey0(e.0, &sk);
        if rc != 0 && rc != FWP_E_SUBLAYER_NOT_FOUND && rc != FWP_E_NOT_FOUND {
            return Err(err("FwpmSubLayerDeleteByKey0", rc));
        }
        let pk = provider_key();
        let rc = FwpmProviderDeleteByKey0(e.0, &pk);
        if rc != 0 && rc != FWP_E_PROVIDER_NOT_FOUND && rc != FWP_E_NOT_FOUND {
            return Err(err("FwpmProviderDeleteByKey0", rc));
        }
        Ok(())
    })
    .map_err(anyhow::Error::msg)
}

/// (isolated_at, permitted servers, analyst allow-list, current plan).
pub type IsolationInputs = (Option<i64>, Vec<String>, Vec<String>, Vec<FilterSpec>);

fn clear_isolation(s: &mut WfpState) {
    s.isolated = false;
    s.isolated_at = None;
    s.isolation_filters.clear();
    s.isolation_specs.clear();
    s.isolation_allow.clear();
    s.isolation_servers.clear();
    s.isolation_allow_ips.clear();
}

/// Break-glass (H10): remove Kestrel's isolation filters without the
/// service (`kestrel-agent release-isolation`, administrators only, after the
/// uninstall token was verified). Also removes leftover isolation filters
/// the state file does not know about (by name), and records the release so
/// the running service does not re-apply them.
pub fn release_isolation_offline(state_dir: &Path) -> anyhow::Result<String> {
    let path = state_dir.join("wfp_state.json");
    let mut s: WfpState = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let e = Engine::open().map_err(anyhow::Error::msg)?;
    let n = if s.isolation_filters.is_empty() {
        0
    } else {
        e.delete_filters(&s.isolation_filters)
            .map_err(anyhow::Error::msg)?
    };
    let was = s.isolated;
    clear_isolation(&mut s);
    let b = serde_json::to_vec_pretty(&s)?;
    write_atomic(&path, &b)?;
    Ok(if was || n > 0 {
        format!("network isolation released locally ({n} WFP filters removed)")
    } else {
        "the host was not isolated".into()
    })
}

/// Stateful WFP manager owned by the platform.
pub struct Wfp {
    state_path: PathBuf,
    state: Mutex<WfpState>,
    pub isolated: AtomicBool,
    /// Our filter keys, shared with the Security-log tamper watcher.
    pub keys: Arc<RwLock<Vec<String>>>,
}

impl Wfp {
    pub fn load(state_dir: &Path) -> Wfp {
        let state_path = state_dir.join("wfp_state.json");
        let state: WfpState = std::fs::read(&state_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Wfp {
            state_path,
            isolated: AtomicBool::new(state.isolated),
            keys: Arc::new(RwLock::new(state.all_keys())),
            state: Mutex::new(state),
        }
    }

    fn persist(&self, s: &WfpState) {
        if let Ok(mut k) = self.keys.write() {
            *k = s.all_keys();
        }
        self.isolated.store(s.isolated, Ordering::SeqCst);
        if let Ok(b) = serde_json::to_vec_pretty(s) {
            if let Err(e) = write_atomic(&self.state_path, &b) {
                tracing::error!("cannot persist WFP state: {e}");
            }
        }
    }

    /// Isolate (or re-plan an existing isolation). `servers` / `allow_ips`
    /// are remembered so the plan can be refreshed when the server address
    /// or the adapters' DNS servers change (H10). `keep_since` keeps the
    /// original isolation start on a re-plan.
    pub fn isolate(
        &self,
        specs: Vec<FilterSpec>,
        allow_desc: Vec<String>,
        servers: Vec<String>,
        allow_ips: Vec<String>,
        keep_since: bool,
    ) -> Result<String, String> {
        let e = Engine::open()?;
        let mut s = self.state.lock().map_err(|_| "state lock poisoned")?;
        // Re-isolation replaces the previous set (allow-list may have changed).
        let new_keys = e.add_filters(&specs)?;
        let old = std::mem::take(&mut s.isolation_filters);
        if !old.is_empty() {
            let _ = e.delete_filters(&old);
        }
        let n = new_keys.len();
        if !(keep_since && s.isolated && s.isolated_at.is_some()) {
            s.isolated_at = Some(kestrel_common::now_ms());
        }
        s.isolated = true;
        s.isolation_filters = new_keys;
        s.isolation_specs = specs;
        s.isolation_allow = allow_desc.clone();
        s.isolation_servers = servers;
        s.isolation_allow_ips = allow_ips;
        self.persist(&s);
        Ok(format!(
            "host isolated ({n} WFP filters); reachable: loopback, DHCP, DNS resolvers, {}",
            allow_desc.join(", ")
        ))
    }

    /// Current isolation inputs: (isolated_at, servers, allow ips, specs).
    pub fn isolation_inputs(&self) -> Option<IsolationInputs> {
        let s = self.state.lock().ok()?;
        s.isolated.then(|| {
            (
                s.isolated_at,
                s.isolation_servers.clone(),
                s.isolation_allow_ips.clone(),
                s.isolation_specs.clone(),
            )
        })
    }

    pub fn isolated_since(&self) -> Option<i64> {
        let s = self.state.lock().ok()?;
        if s.isolated {
            // Older state files have no timestamp: count from now on.
            Some(s.isolated_at.unwrap_or_else(kestrel_common::now_ms))
        } else {
            None
        }
    }

    /// The break-glass CLI may have released isolation while the service
    /// ran: adopt the on-disk state instead of re-applying the filters.
    fn adopt_external_release(&self, s: &mut WfpState) -> Option<String> {
        if !s.isolated {
            return None;
        }
        let disk: WfpState = std::fs::read(&self.state_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())?;
        if disk.isolated {
            return None;
        }
        *s = disk;
        self.isolated.store(false, Ordering::SeqCst);
        if let Ok(mut k) = self.keys.write() {
            *k = s.all_keys();
        }
        Some("isolation was released locally (break-glass); not re-applying".into())
    }

    pub fn release(&self) -> Result<String, String> {
        let e = Engine::open()?;
        let mut s = self.state.lock().map_err(|_| "state lock poisoned")?;
        if !s.isolated && s.isolation_filters.is_empty() {
            return Ok("host was not isolated".into());
        }
        let n = e.delete_filters(&s.isolation_filters)?;
        clear_isolation(&mut s);
        self.persist(&s);
        Ok(format!("isolation released ({n} WFP filters removed)"))
    }

    pub fn block(
        &self,
        specs: Vec<FilterSpec>,
        description: String,
        ttl_secs: Option<u64>,
    ) -> Result<(String, String), String> {
        self.block_tagged(specs, description, ttl_secs, None)
    }

    /// [`Wfp::block`] remembering the Block IOC that caused it (M10).
    pub fn block_tagged(
        &self,
        specs: Vec<FilterSpec>,
        description: String,
        ttl_secs: Option<u64>,
        ioc_id: Option<String>,
    ) -> Result<(String, String), String> {
        let e = Engine::open()?;
        let keys = e.add_filters(&specs)?;
        let now = kestrel_common::now_ms();
        let id = uuid::Uuid::new_v4().to_string();
        let expires_at = ttl_secs.map(|t| now + (t as i64) * 1000);
        let mut s = self.state.lock().map_err(|_| "state lock poisoned")?;
        s.blocks.push(BlockRecord {
            id: id.clone(),
            description: description.clone(),
            filter_keys: keys,
            expires_at,
            created_at: now,
            ioc_id,
        });
        self.persist(&s);
        let detail = match ttl_secs {
            Some(t) => format!("{description} (block {id}, expires in {t}s)"),
            None => format!("{description} (block {id}, no expiry)"),
        };
        Ok((id, detail))
    }

    /// M10: remove the blocks created for IOC hits whose IOC is no longer a
    /// Block IOC in the applied policy. Returns descriptions removed; a block
    /// whose filters could not be deleted stays recorded (retried next time).
    pub fn lift_ioc_blocks(&self, block_iocs: &std::collections::BTreeSet<String>) -> Vec<String> {
        let Ok(mut s) = self.state.lock() else {
            return vec![];
        };
        let lifted = s.take_lifted_ioc_blocks(block_iocs);
        if lifted.is_empty() {
            return vec![];
        }
        let mut out = Vec::new();
        match Engine::open() {
            Ok(e) => {
                for b in &lifted {
                    if e.delete_filters(&b.filter_keys).is_ok() {
                        out.push(b.description.clone());
                    } else {
                        s.blocks.push(b.clone());
                    }
                }
            }
            Err(_) => s.blocks.extend(lifted),
        }
        self.persist(&s);
        out
    }

    /// Remove expired blocks. Returns descriptions removed.
    pub fn expire(&self) -> Vec<String> {
        let now = kestrel_common::now_ms();
        let Ok(mut s) = self.state.lock() else {
            return vec![];
        };
        let expired = s.take_expired(now);
        if expired.is_empty() {
            return vec![];
        }
        let mut out = Vec::new();
        match Engine::open() {
            Ok(e) => {
                for b in &expired {
                    if e.delete_filters(&b.filter_keys).is_ok() {
                        out.push(b.description.clone());
                    } else {
                        s.blocks.push(b.clone()); // retry next round
                    }
                }
            }
            Err(_) => s.blocks.extend(expired),
        }
        self.persist(&s);
        out
    }

    /// Ensure isolation filters still exist (re-add if someone removed them).
    pub fn repair(&self) -> Option<String> {
        let Ok(mut s) = self.state.lock() else {
            return None;
        };
        if let Some(note) = self.adopt_external_release(&mut s) {
            return Some(note);
        }
        if !s.isolated || s.isolation_specs.is_empty() {
            return None;
        }
        let e = Engine::open().ok()?;
        let missing = s
            .isolation_filters
            .iter()
            .filter(|k| !e.filter_exists(k))
            .count();
        if missing == 0 {
            return None;
        }
        let old = std::mem::take(&mut s.isolation_filters);
        let _ = e.delete_filters(&old);
        match e.add_filters(&s.isolation_specs) {
            Ok(keys) => {
                s.isolation_filters = keys;
                self.persist(&s);
                Some(format!(
                    "{missing} isolation filter(s) were missing and have been re-applied"
                ))
            }
            Err(er) => {
                s.isolation_filters = old;
                Some(format!(
                    "{missing} isolation filter(s) missing; re-apply failed: {er}"
                ))
            }
        }
    }

    /// Always-on hard permits for the agent's server connections.
    pub fn ensure_server_permits(&self, specs: Vec<FilterSpec>) -> Result<(), String> {
        if specs.is_empty() {
            return Ok(());
        }
        let e = Engine::open()?;
        let mut s = self.state.lock().map_err(|_| "state lock poisoned")?;
        let all_present = !s.server_permit_filters.is_empty()
            && s.server_permit_filters.len() == specs.len()
            && s.server_permit_filters.iter().all(|k| e.filter_exists(k));
        if all_present {
            return Ok(());
        }
        let old = std::mem::take(&mut s.server_permit_filters);
        let _ = e.delete_filters(&old);
        s.server_permit_filters = e.add_filters(&specs)?;
        self.persist(&s);
        Ok(())
    }
}
