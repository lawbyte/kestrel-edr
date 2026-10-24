import { describe, expect, it } from 'vitest'
import type { KEvent, TreeNode } from '@/api/types'
import { describeEvent } from './events'
import { decodeAccessMask, matchExfilDomain } from './event-knowledge'
import { explainEvent, isOwnProfile } from './explain'

const T0 = Date.UTC(2026, 9, 24, 6, 0, 0)
const GUID = 'g-xeno'
const XENO = 'C:\\Users\\j.doe\\AppData\\Local\\Temp\\Xeno-v1.3.65.exe'

const start: KEvent = {
  ts: T0,
  pid: 47852,
  guid: GUID,
  type: 'process_start',
  ppid: 4312,
  image: XENO,
  cmdline: `"${XENO}"`,
  signed: 'unsigned',
}
const dpapi: KEvent = { ts: T0 + 5_000, pid: 47852, guid: GUID, type: 'dpapi_unprotect', description: 'Chromium' }
const own: KEvent = { ts: T0 + 4_200, pid: 47852, guid: GUID, type: 'file_access', op: 'read', path: 'C:\\Users\\j.doe\\AppData\\Roaming\\Xeno\\Local State' }
const chromeKey: KEvent = { ts: T0 + 4_500, pid: 47852, guid: GUID, type: 'file_access', op: 'read', path: 'C:\\Users\\j.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Local State' }

const allText = (x: ReturnType<typeof explainEvent>) => [...x.what, ...x.notes.map((n) => n.text), ...x.lists.flatMap((l) => [l.title, l.empty ?? '', ...l.items.map((i) => `${i.text} ${i.tag ?? ''}`)])].join('\n')

describe('explainEvent: DPAPI', () => {
  it('explains the Xeno "Chromium" decrypt and says when the key file is unknown', () => {
    const x = explainEvent(dpapi, { events: [start, dpapi] })
    expect(x.what[0]).toBe(
      'Xeno-v1.3.65.exe asked Windows (DPAPI) to decrypt a secret labelled "Chromium". Chrome, Edge, Brave and Electron apps use this label for the master key that encrypts saved passwords and cookies. Only the app that owns the key should decrypt it.',
    )
    const which = x.lists.find((l) => l.title === 'Which key?')
    expect(which?.items).toEqual([])
    expect(which?.empty).toMatch(/did not record which file the key came from/)
    expect(x.fields.find((f) => f.label === 'Process')?.value).toBe('Xeno-v1.3.65.exe (PID 47852)')
  })

  it('marks a Local State open in the app’s own AppData\\Roaming folder as its own profile', () => {
    const x = explainEvent(dpapi, { events: [start, own, dpapi] })
    const which = x.lists.find((l) => l.title === 'Which key?')!
    expect(which.items).toHaveLength(1)
    expect(which.items[0]).toMatchObject({ tag: 'the app’s own profile', tone: 'ok' })
    expect(x.notes.some((n) => n.tone === 'warn')).toBe(false)
  })

  it('uses --user-data-dir from the command line for own-profile detection', () => {
    const s2 = { ...start, cmdline: `"${XENO}" --user-data-dir="D:\\Portable\\XenoData"` } as KEvent
    const f: KEvent = { ...own, path: 'D:\\Portable\\XenoData\\Local State' } as KEvent
    const which = explainEvent(dpapi, { events: [s2, f, dpapi] }).lists[0]
    expect(which.items[0].tag).toBe('the app’s own profile')
  })

  it('flags a browser Local State read as a browser key store, and ignores opens older than 10 s or by other processes', () => {
    const old: KEvent = { ...chromeKey, ts: T0 - 20_000 } as KEvent
    const other: KEvent = { ...chromeKey, guid: 'g-other' } as KEvent
    const x = explainEvent(dpapi, { events: [start, old, other, own, chromeKey, dpapi] })
    const which = x.lists.find((l) => l.title === 'Which key?')!
    expect(which.items.map((i) => i.tag)).toEqual(['the app’s own profile', 'Chrome’s key store'])
    expect(x.notes.find((n) => n.tone === 'warn')?.text).toMatch(/browser’s key file/)
  })

  it('uses the process tree when there is no process_start event', () => {
    const node = { guid: GUID, image: XENO, cmdline: `"${XENO}"`, pid: 47852, signed: 'unsigned', signer: null, path_class: 'temp', parent_guid: null } as unknown as TreeNode
    const x = explainEvent(dpapi, { events: [own, dpapi], processes: new Map([[GUID, node]]) })
    expect(x.what[0]).toMatch(/^Xeno-v1\.3\.65\.exe asked/)
    expect(x.lists[0].items[0].tag).toBe('the app’s own profile')
  })

  it('gives generic text for an unknown label and maps Credential Manager', () => {
    const u = explainEvent({ ...dpapi, description: 'Acme secret' } as KEvent)
    expect(u.what.join(' ')).toMatch(/label is chosen by the program/)
    expect(u.lists).toEqual([])
    const c = explainEvent({ ...dpapi, description: 'Local Credential Data' } as KEvent)
    expect(c.what[0]).toMatch(/Credential Manager/)
  })

  it('one-line summary names the key', () => {
    expect(describeEvent(dpapi)).toBe('Decrypted the "Chromium" key (browser/Electron master key)')
    expect(describeEvent({ ...dpapi, description: 'Google Chrome' } as KEvent)).toBe('Decrypted the "Google Chrome" key (Chrome master key)')
  })
})

describe('explainEvent: network', () => {
  const quic: KEvent = { ts: T0 + 6_000, pid: 47852, guid: GUID, type: 'net_connect', proto: 'udp', dst_ip: '172.66.44.125', dst_port: 443, src_port: 51234, dst_host: null, bytes_sent: 1250 }

  it('describes a 1250-byte QUIC packet as a handshake, not an upload', () => {
    const x = explainEvent(quic, { events: [start] })
    const t = allText(x)
    expect(t).toMatch(/QUIC \(HTTP\/3, encrypted\)/)
    expect(t).toMatch(/172\.66\.44\.125 on port 443 \(no host name recorded\)/)
    expect(t).toMatch(/1\.2 KB \(1,250 bytes\)/)
    expect(t).toMatch(/about one QUIC handshake packet/i)
    expect(t).toMatch(/Kestrel records the connection, not its content; the traffic is encrypted\./)
    expect(t).not.toMatch(/Large upload/)
    expect(describeEvent(quic)).toBe('QUIC (UDP) → 172.66.44.125:443, 1.2 KB sent')
  })

  it('flags a large upload and does not add the QUIC note to TCP', () => {
    const up: KEvent = { ...quic, proto: 'tcp', dst_ip: '185.208.158.114', bytes_sent: 2_202_009 } as KEvent
    const x = explainEvent(up)
    expect(x.what[0]).toMatch(/HTTPS \(encrypted\)/)
    expect(x.notes.find((n) => n.tone === 'warn')?.text).toMatch(/^Large upload: 2\.1 MB/)
    expect(allText(x)).not.toMatch(/QUIC handshake/)
  })

  it('names a dead-drop host', () => {
    const tg: KEvent = { ...quic, proto: 'tcp', dst_host: 'api.telegram.org', dst_ip: '149.154.167.220', bytes_sent: 900 } as KEvent
    expect(explainEvent(tg).notes.some((n) => /dead-drop list/.test(n.text))).toBe(true)
  })
})

describe('explainEvent: DNS', () => {
  it('shows three answers and keeps the rest behind "+N more"', () => {
    const answers = Array.from({ length: 20 }, (_, i) => `104.20.${i}.1`)
    const e: KEvent = { ts: T0, pid: 47852, guid: GUID, type: 'dns_query', qname: 'pastebin.com', answers }
    const x = explainEvent(e, { events: [start] })
    expect(x.what[0]).toBe('Xeno-v1.3.65.exe looked up pastebin.com.')
    const l = x.lists.find((y) => y.title === 'Answers')!
    expect(l.items.map((i) => i.text)).toEqual(['104.20.0.1', '104.20.1.1', '104.20.2.1'])
    expect(l.more).toHaveLength(17)
    expect(x.notes.find((n) => n.tone === 'warn')?.text).toMatch(/Paste sites/)
    expect(describeEvent(e)).toBe('Resolved pastebin.com → 104.20.0.1, 104.20.1.1, 104.20.2.1 +17 more')
  })

  it('matches sub-domains and path entries by domain, not look-alikes', () => {
    expect(matchExfilDomain('pub-3f2c.r2.dev')?.entry).toBe('r2.dev')
    expect(matchExfilDomain('discord.com')?.entry).toBe('discord.com/api/webhooks')
    expect(matchExfilDomain('notpastebin.com')).toBeNull()
  })
})

describe('explainEvent: process access', () => {
  it('decodes an LSASS mask and the refusal', () => {
    const e: KEvent = { ts: T0, pid: 900, guid: 'g-hp', type: 'process_access', target_pid: 1004, target_guid: null, target_image: 'C:\\Windows\\System32\\lsass.exe', granted_access: 0x1410, return_code: 0xc0000022 }
    const x = explainEvent(e)
    expect(x.fields.find((f) => f.label === 'Rights')?.value).toBe('PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION')
    expect(x.what[0]).toMatch(/read its memory/)
    expect(x.what[1]).toMatch(/LSASS holds/)
    expect(x.notes[0]).toMatchObject({ tone: 'ok' })
    expect(x.notes[0].text).toMatch(/0xc0000022 access denied/)
  })

  it('decodes ALL_ACCESS and thread masks', () => {
    expect(decodeAccessMask(0x1fffff).names).toEqual(['PROCESS_ALL_ACCESS'])
    expect(decodeAccessMask(0x1a, 'thread').names).toEqual(['THREAD_SUSPEND_RESUME', 'THREAD_GET_CONTEXT', 'THREAD_SET_CONTEXT'])
    expect(decodeAccessMask(0x02000000).names).toEqual(['MAXIMUM_ALLOWED'])
  })
})

describe('explainEvent: other kinds and safety', () => {
  it('recognises credential stores in file_access', () => {
    const e: KEvent = { ts: T0, pid: 1, guid: GUID, type: 'file_access', op: 'read', path: 'C:\\Users\\a\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data' }
    const x = explainEvent(e, { events: [start] })
    expect(x.what[0]).toMatch(/Chrome’s saved passwords database/)
    expect(x.notes[0].text).toMatch(/only Chrome itself/)
  })

  it('does not treat a bare Temp folder as the app’s own data', () => {
    expect(isOwnProfile('C:\\Users\\j.doe\\AppData\\Local\\Temp\\chr_1\\Local State', { image: XENO })).toBe(false)
  })

  it('strips bidi overrides from endpoint strings', () => {
    const e: KEvent = { ts: T0, pid: 1, guid: 'x', type: 'file_access', op: 'create', path: 'C:\\Users\\a\\evil\u202etxt.exe' }
    expect(allText(explainEvent(e))).not.toMatch(/\u202e/)
  })

  it('explains every event kind without throwing', () => {
    const kinds: KEvent[] = [
      start,
      { ts: T0, pid: 1, guid: GUID, type: 'process_stop', exit_code: 0 },
      { ts: T0, pid: 1, guid: GUID, type: 'image_load', path: 'C:\\Windows\\System32\\dbghelp.dll', signed: 'valid', signer: 'Microsoft Windows' },
      { ts: T0, pid: 1, guid: GUID, type: 'registry_set', key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', value_name: 'x', data: 'y' },
      { ts: T0, pid: 1, guid: GUID, type: 'remote_thread', target_pid: 2, target_image: 'C:\\x.exe' },
      { ts: T0, pid: 1, guid: GUID, type: 'thread_context', target_pid: 2, target_image: 'C:\\x.exe', granted_access: 0x1a },
      { ts: T0, pid: 1, guid: GUID, type: 'debug_attach', target_pid: 2, target_image: 'C:\\x.exe', granted_access: 0x1fffff },
      { ts: T0, pid: 1, guid: GUID, type: 'script_block', engine: 'PowerShell', content: 'iex' },
      { ts: T0, pid: 1, guid: GUID, type: 'tamper', kind: 'events_lost', detail: '12 lost' },
      { ts: T0, pid: 1, guid: GUID, type: 'file_activity', window_ms: 10_000, files_touched: 40, dirs: 4, renames: 40, top_new_ext: 'k3str' },
      { ts: T0, pid: 1, guid: GUID, type: 'task_registered', name: '\\T', op: 'created', actions: ['a.exe'], triggers: ['logon'], hidden: true },
      { ts: T0, pid: 1, guid: GUID, type: 'service_installed', name: 's', image_path: 'C:\\s.exe', start_type: 2, service_type: 1 },
      { ts: T0, pid: 1, guid: GUID, type: 'wmi_subscription', namespace: 'root\\subscription', filter: 'f', consumer: 'CommandLineEventConsumer="x"' },
    ]
    for (const k of kinds) {
      const x = explainEvent(k, { events: [start] })
      expect(x.what.length, k.type).toBeGreaterThan(0)
      expect(x.fields[0].label).toBe('Time')
    }
  })
})
