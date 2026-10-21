import { describe, expect, it } from 'vitest'
import type { Alert, Group, KEvent, Policy, ResponseAction, UpdateRelease } from './types'
import { DATA_CATEGORIES, EVENT_KINDS, GROUP_UPDATE_RINGS, REMOTE_ERROR_CODES, SEVERITIES } from './types'
import type { DesktopServerMsg, EnrollmentToken, FileEntry, FileListResponse, RemoteAccessInfo } from './types'
import { REMOTE_ERROR_TEXT } from './remote'
import { normaliseProfile, presetOf, profileGuarded } from '@/lib/remote-profile'
import { DATA_CATEGORY_LABEL, DATA_CATEGORY_REMEDIATION, EVENT_KIND_LABEL, actionPrivilege, describeAction, unblockFor } from '@/lib/labels'
import { pathClassOf } from '@/lib/pathclass'
import { describeEvent } from '@/lib/events'
import { diffJson } from '@/lib/diff'

/**
 * JSON exactly as serde produces it from kestrel-common (flattened Event with
 * a `type` tag, `type`-tagged ResponseAction, snake_case enums). If these stop
 * compiling, the TS mirror has drifted from the Rust types.
 */
const eventJson = `{"ts":1,"pid":4,"guid":"abc","type":"file_access","path":"C:\\\\x","op":"read"}`
const alertJson = `{
  "id":"7f1c0000-0000-4000-8000-000000000001","ts":1760000000000,"rule_id":"ST-04","rule_name":"Steal-then-send",
  "rule_author":null,"severity":"critical","attack":["T1041"],"mode":"protect","summary":"x",
  "process":{"guid":"g1","pid":10,"ppid":4,"parent_guid":null,"image":"C:\\\\Users\\\\a\\\\Downloads\\\\s.exe","cmdline":"s.exe","user":null,"integrity":"medium","start_ts":1,"exit_ts":null,"signer":null,"signed":"unsigned","sha256":null,"motw_zone":3,"file_size":10,"path_class":"downloads"},
  "ancestry":[],"data_at_risk":["browser_passwords","crypto_wallet"],
  "evidence":[{"ts":2,"pid":10,"guid":"g1","type":"net_connect","proto":"tcp","dst_ip":"1.2.3.4","dst_port":443,"src_port":5000,"dst_host":null,"bytes_sent":2048}],
  "actions":[{"action":{"type":"kill_process","pid":10,"guid":"g1","tree":true},"ok":true,"detail":"","ts":3},{"action":{"type":"release_host"},"ok":true,"detail":"","ts":4}]
}`

describe('serde shape compatibility', () => {
  it('parses a flattened Event', () => {
    const e = JSON.parse(eventJson) as KEvent
    expect(e.type).toBe('file_access')
    if (e.type === 'file_access') expect(e.op).toBe('read')
  })
  it('parses an Alert with tagged evidence and actions', () => {
    const a = JSON.parse(alertJson) as Alert
    expect(a.process.path_class).toBe('downloads')
    expect(a.evidence?.[0].type).toBe('net_connect')
    expect(a.actions?.map((x) => x.action.type)).toEqual(['kill_process', 'release_host'])
  })
  it('covers every Rust enum variant with a label', () => {
    expect(SEVERITIES).toHaveLength(5)
    expect(DATA_CATEGORIES).toHaveLength(14)
    for (const c of DATA_CATEGORIES) {
      expect(DATA_CATEGORY_LABEL[c]).toBeTruthy()
      expect(DATA_CATEGORY_REMEDIATION[c]).toBeTruthy()
    }
    expect(EVENT_KINDS).toHaveLength(18)
    for (const k of EVENT_KINDS) expect(EVENT_KIND_LABEL[k]).toBeTruthy()
  })
  it('mirrors ResponseAction::privilege()', () => {
    const cases: [ResponseAction, string][] = [
      [{ type: 'kill_process', pid: 1 }, 'response.process'],
      [{ type: 'quarantine_file', path: 'x' }, 'response.file'],
      [{ type: 'isolate_host' }, 'response.network'],
      [{ type: 'release_host' }, 'response.network'],
      [{ type: 'unblock_network' }, 'response.network'],
      [{ type: 'collect_triage' }, 'response.collect'],
      [{ type: 'apply_hardening' }, 'response.collect'],
      [{ type: 'remove_autorun', kind: 'scheduled_task', location: '\\Updater' }, 'response.persistence'],
    ]
    for (const [a, p] of cases) expect(actionPrivilege(a)).toBe(p)
    expect(describeAction({ type: 'block_destination', ip: '1.2.3.4', port: 443 })).toBe('Block 1.2.3.4:443')
  })
  it('round-trips a Policy through JSON without loss', () => {
    const p: Policy = {
      id: 'p',
      name: 'Default',
      version: 1,
      rules: { 'ST-01': 'audit' },
      suspend_window_ms: 3000,
      exclusions: [{ id: 'e', kind: 'signer', value: 'X', rule_id: null, expires_at: null, reason: '' }],
      iocs: [{ id: 'i', kind: 'ip', value: '1.1.1.1', action: 'block', description: '' }],
      hardening: {
        mode: 'audit',
        block_mshta: true,
        block_user_path_exec: false,
        disable_run_dialog: false,
        terminal_paste_warning: true,
        script_block_logging: true,
        dpapi_debug_channel: true,
        asr_rules: true,
        browser_disable_remote_debugging: true,
        wdigest_off: true,
        asr_lsass: true,
        lsa_protection: false,
        report_vulnerable_driver_blocklist: true,
        task_scheduler_log: true,
      },
      sensors: { file_activity: true, ransomware_canaries: true, persistence: true, credential_access: false },
      privacy: { capture_cmdline: true, hash_usernames: false, redact_path_prefixes: [], capture_dns: true, capture_script_content: true },
      telemetry: { upload_events: true, event_kinds: [], max_outbox_mb: 1024 },
      canaries: true,
      branding: { org_name: 'o', it_contact: { name: '', email: '', phone: '', url: '' }, privacy_notice_md: '' },
      exfil_domains: ['api.telegram.org'],
      isolation_auto_release_hours: 72,
      ioc_block_ttl_secs: 86400,
      ioc_block_host_wide: false,
    }
    expect(diffJson(p, JSON.parse(JSON.stringify(p)))).toEqual([])
    expect(diffJson(p, { ...p, rules: { 'ST-01': 'protect' } })).toEqual([{ path: 'rules.ST-01', before: 'audit', after: 'protect' }])
  })
})

describe('PathClass::of port', () => {
  it('matches the Rust unit test cases', () => {
    expect(pathClassOf('C:\\Windows\\System32\\cmd.exe')).toBe('system')
    expect(pathClassOf('C:\\Users\\a\\AppData\\Local\\Temp\\x.exe')).toBe('temp')
    expect(pathClassOf('c:\\users\\a\\downloads\\setup.exe')).toBe('downloads')
    expect(pathClassOf('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe')).toBe('program_files')
    expect(pathClassOf('\\\\?\\C:\\Users\\a\\AppData\\Roaming\\z.exe')).toBe('user_writable')
    expect(pathClassOf('\\\\server\\share\\a.exe')).toBe('external')
  })
})

describe('describeEvent', () => {
  it('renders process access with hex mask', () => {
    const e: KEvent = { ts: 1, pid: 2, guid: 'g', type: 'process_access', target_pid: 9, target_image: 'C:\\x\\chrome.exe', granted_access: 0x143a }
    expect(describeEvent(e)).toBe('Opened chrome.exe (PID 9) with access 0x143a')
  })
  it('renders general-malware events readably', () => {
    const fa = JSON.parse(
      `{"ts":1,"pid":2,"guid":"g","type":"file_activity","window_ms":10000,"files_touched":430,"dirs":37,"renames":412,"ext_changes":400,"overwrites":0,"new_files":37,"deletes":0,"net_paths":0,"top_new_ext":"k3str","top_ext_pct":95,"note_name":"readme.txt","note_dirs":37,"canary_hits":[],"sample_paths":[]}`,
    ) as KEvent
    expect(describeEvent(fa)).toBe('Renamed 412 files in 37 folders within 10 s, new extension .k3str (95%); created readme.txt in 37 folders')
    const task = JSON.parse(
      `{"ts":1,"pid":2,"guid":"g","type":"task_registered","name":"\\\\Updater","op":"created","user":null,"actions":["\\"C:\\\\Users\\\\a\\\\u.exe\\" -s"],"hidden":true,"triggers":["logon"]}`,
    ) as KEvent
    expect(describeEvent(task)).toBe('Created task \\Updater (hidden, at logon) → "C:\\Users\\a\\u.exe" -s')
    const svc: KEvent = { ts: 1, pid: 2, guid: 'g', type: 'service_installed', name: 'svc', image_path: 'C:\\Users\\Public\\s.exe', start_type: 2 }
    expect(describeEvent(svc)).toBe('Installed service svc (auto start) → C:\\Users\\Public\\s.exe')
    const del: KEvent = { ts: 1, pid: 2, guid: 'g', type: 'registry_set', key: 'HKLM\\X', value_name: 'RunAsPPL', op: 'delete_value' }
    expect(describeEvent(del)).toBe('Deleted value HKLM\\X\\RunAsPPL')
    const lsass: KEvent = { ts: 1, pid: 2, guid: 'g', type: 'process_access', target_pid: 700, target_image: 'C:\\Windows\\System32\\lsass.exe', granted_access: 0x1fffff, return_code: 0xc0000022 }
    expect(describeEvent(lsass)).toBe('Opened lsass.exe (PID 700) with access 0x1fffff — refused by Windows (0xc0000022 access denied)')
    expect(describeAction({ type: 'remove_autorun', kind: 'registry_value', location: 'HKLM\\Run', value_name: 'x' })).toBe('Remove registry value HKLM\\Run\\x')
    expect(describeAction({ type: 'remove_autorun', kind: 'service', location: 'evil' })).toBe('Disable service evil')
  })
})

describe('agent update contract', () => {
  it('parses the update JSON shapes from the server', () => {
    const rel = JSON.parse(
      '{"id":"r1","version":"1.4.0","url":"https://x/a.msi","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signature":"s","notes":"","created_by":null,"created_by_name":null,"created_at":1,"state":"rolling","halted_at":null,"halted_by":null,"halted_by_name":null,"halt_reason":"","next_ring":"early","rings":[{"ring":"canary","enabled":true,"enabled_at":2,"enabled_by":"u","enabled_by_name":"Priya","devices":3,"on_target":2,"delivered":3,"succeeded":2,"failed":1,"pending":0,"offline_24h":0}],"recent_failures":[{"device_id":"d","hostname":"IT-LT-002","error":"hash mismatch","at":3}]}',
    ) as UpdateRelease
    expect(rel.next_ring).toBe('early')
    expect(rel.rings[0].pending).toBe(0)
    const g = JSON.parse('{"id":"g","name":"IT","description":"","policy_id":null,"device_count":3,"is_default":false,"update_ring":"pinned"}') as Group
    expect(GROUP_UPDATE_RINGS).toContain(g.update_ring)
  })
  it('accepts the agent-set ioc_id on block_destination', () => {
    const a = JSON.parse('{"type":"block_destination","ip":"1.2.3.4","port":443,"ioc_id":"ioc-1"}') as ResponseAction
    expect(a.type === 'block_destination' && a.ioc_id).toBe('ioc-1')
  })
  it('mirrors UnblockNetwork (serde defaults, labels, undo of a block)', () => {
    // `{"type":"unblock_network"}` is valid JSON from the Rust side (both fields default).
    const all = JSON.parse('{"type":"unblock_network"}') as ResponseAction
    expect(describeAction(all)).toBe('Lift every Kestrel network block')
    expect(describeAction({ type: 'unblock_network', image: 'C:\\Apps\\crm.exe' })).toBe('Lift network blocks for C:\\Apps\\crm.exe')
    expect(describeAction({ type: 'unblock_network', block_id: 'blk-1' })).toBe('Lift network block blk-1')
    const img = 'C:\\Apps\\crm.exe'
    expect(unblockFor({ type: 'block_image_network', image: img }, 'b-1')).toEqual({ type: 'unblock_network', image: img, block_id: null })
    expect(unblockFor({ type: 'block_destination', ip: '1.2.3.4', image: img }, 'b-2')).toEqual({ type: 'unblock_network', image: null, block_id: 'b-2' })
    expect(unblockFor({ type: 'block_destination', ip: '1.2.3.4', image: img }, null)).toEqual({ type: 'unblock_network', image: img, block_id: null })
    // An unscoped destination block without a block id cannot be targeted.
    expect(unblockFor({ type: 'block_destination', ip: '1.2.3.4' }, 'not a valid id!')).toBeNull()
    expect(unblockFor({ type: 'isolate_host' }, 'x')).toBeNull()
  })
})

describe('remote access shapes (kestrel_common::remote)', () => {
  it('parses FileEntry / FileListResponse as serde writes them', () => {
    const j = `{"path":"C:\\\\","parent":"","entries":[{"name":"C:\\\\","path":"C:\\\\","kind":"drive","size":0,"modified":null,"attributes":16,"hidden":false,"readonly":false,"reparse":false,"free_bytes":10,"total_bytes":20,"label":"Local Disk"},{"name":"Docs","path":"C:\\\\Docs","kind":"dir","size":0,"modified":1760000000000,"attributes":1040,"hidden":false,"readonly":false,"reparse":true,"free_bytes":null,"total_bytes":null,"label":null}],"truncated":false}`
    const r = JSON.parse(j) as FileListResponse
    expect(r.entries.map((e: FileEntry) => e.kind)).toEqual(['drive', 'dir'])
    expect(r.entries[1].reparse).toBe(true)
  })
  it('parses every DesktopServerMsg variant and the error codes', () => {
    const msgs = [
      '{"type":"starting","session_id":"s","view_only":true}',
      '{"type":"consent_pending","timeout_secs":60}',
      '{"type":"started","width":1920,"height":1080,"monitors":2,"session_id":1,"secure_desktop":false,"view_only":false}',
      '{"type":"info","width":1280,"height":720}',
      '{"type":"ended","reason":"idle","code":null}',
      '{"type":"error","message":"x"}',
      '{"type":"pong"}',
    ].map((s) => JSON.parse(s) as DesktopServerMsg)
    expect(msgs.map((m) => m.type)).toEqual(['starting', 'consent_pending', 'started', 'info', 'ended', 'error', 'pong'])
    expect(REMOTE_ERROR_CODES).toHaveLength(20)
    for (const c of REMOTE_ERROR_CODES) expect(REMOTE_ERROR_TEXT[c]).toBeTruthy()
  })
  it('round-trips profiles, device remote_access and enrollment tokens', () => {
    const g = profileGuarded()
    expect(JSON.parse(JSON.stringify(g))).toEqual(g)
    const ra = JSON.parse(
      `{"desktop":{"available":false,"reason":"not_permitted"},"files":{"available":true,"reason":null},"ceiling":${JSON.stringify(g)},"ceiling_summary":"x","policy":${JSON.stringify(g)},"effective":${JSON.stringify(g)},"effective_summary":"y","agent_reported_ceiling":null}`,
    ) as RemoteAccessInfo
    expect(ra.desktop.reason).toBe('not_permitted')
    expect(normaliseProfile(ra.effective)).toEqual(g)
    const t = JSON.parse('{"id":"t","group_id":"g","group_name":"G","token_prefix":"kse_","created_at":1,"expires_at":2,"max_uses":1,"uses":0,"revoked":false,"remote_profile":{"desktop":"off","files":"off"},"remote_summary":"No remote access","remote_preset":"none"}') as EnrollmentToken
    expect(presetOf(normaliseProfile(t.remote_profile))).toBe('none')
  })
})
