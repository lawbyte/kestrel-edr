import { render } from '@testing-library/react'
import { afterAll, describe, expect, it } from 'vitest'
import type { ChecklistItem, DeviceEvent, IncidentDetail, KEvent, Page, Incident, ResponseAction, TreeNode } from '@/api/types'
import { describeEvent, eventProvenance, withAgentSpawned } from '@/lib/events'
import { safeDisplay } from '@/lib/format'
import { actionPrivilege, describeAction, isCanonicalDefault, PRIVILEGE_DESCRIPTION, PRIVILEGES, ROLE_PRIVILEGES } from '@/lib/labels'
import { referenceHref } from '@/lib/rules'
import { db, handleMock } from '@/mock/server'
import { ProvenanceBadges } from './badges'
import { approveDeniedReason, AutorunTarget, isSafeKillTarget } from './incident-parts'
import { Markdown } from './markdown'
import { TooltipProvider } from './ui/misc'

const RLO = '\u202e'

describe('safeDisplay (bidi / control stripping)', () => {
  it('strips U+202E and the other bidi controls', () => {
    const disguised = `\\Updater${RLO}fdp.exe`
    expect(safeDisplay(disguised)).toBe('\\Updaterfdp.exe')
    expect(safeDisplay('a\u200eb\u200fc\u202ad\u202be\u202cf\u202dg\u2066h\u2067i\u2068j\u2069k\u061cl')).toBe('abcdefghijkl')
  })
  it('strips C0/C1 controls and newlines but keeps normal text', () => {
    expect(safeDisplay('line1\r\nline2\ttab\u0000\u001b[31m\u0085\u009b')).toBe('line1line2tab[31m')
    expect(safeDisplay('C:\\Users\\Aisyah\\AppData\\Roaming\\pdfupd.exe')).toBe('C:\\Users\\Aisyah\\AppData\\Roaming\\pdfupd.exe')
    expect(safeDisplay('Ünïcødé 日本 ok')).toBe('Ünïcødé 日本 ok')
    expect(safeDisplay(null)).toBe('')
  })
  it('is applied by describeAction to endpoint-controlled names', () => {
    expect(describeAction({ type: 'remove_autorun', kind: 'scheduled_task', location: `\\Evil${RLO}gnp.exe` })).toBe('Remove scheduled task \\Evilgnp.exe')
    expect(describeAction({ type: 'remove_autorun', kind: 'service', location: `svc\n> approved` })).toBe('Disable service svc> approved')
    expect(describeAction({ type: 'quarantine_file', path: `C:\\x${RLO}txt.exe` })).toBe('Quarantine C:\\xtxt.exe')
    expect(describeAction({ type: 'remove_autorun', kind: 'registry_value', location: 'HKLM\\Run', value_name: `a${RLO}b` })).toBe('Remove registry value HKLM\\Run\\ab')
  })
  it('the remove_autorun confirm shows every field sanitised', () => {
    const { getByTestId } = render(
      <AutorunTarget action={{ type: 'remove_autorun', kind: 'registry_value', location: `HKU\\S-1\\Run${RLO}`, value_name: `x\ny`, restore_data: `C:\\a${RLO}.exe` }} />,
    )
    const text = getByTestId('autorun-target').textContent ?? ''
    expect(text).not.toContain(RLO)
    expect(text).not.toContain('\n')
    expect(text).toContain('HKU\\S-1\\Run')
    expect(text).toContain('xy')
  })
})

describe('V-H2: remove_autorun privilege and description', () => {
  const ra = (extra: Partial<Extract<ResponseAction, { type: 'remove_autorun' }>> = {}): ResponseAction => ({ type: 'remove_autorun', kind: 'registry_value', location: 'HKLM\\X', ...extra })
  it('needs response.persistence, which analysts lack', () => {
    expect(actionPrivilege(ra())).toBe('response.persistence')
    expect(PRIVILEGES).toContain('response.persistence')
    expect(PRIVILEGE_DESCRIPTION['response.persistence']).toMatch(/SYSTEM/)
    expect(ROLE_PRIVILEGES.analyst).not.toContain('response.persistence')
    expect(ROLE_PRIVILEGES.admin).toContain('*')
    expect(approveDeniedReason('response.persistence', true)).toContain('response.persistence')
    expect(approveDeniedReason('response.file', true)).toContain('response.file')
    expect(approveDeniedReason('response.persistence', false)).toContain('incidents.write')
  })
  it('says "Restore default" only for the exact canonical key/value/data', () => {
    const winlogon = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
    expect(describeAction(ra({ location: winlogon, value_name: 'Userinit', restore_data: 'C:\\Windows\\system32\\userinit.exe,' }))).toMatch(/^Restore default of /)
    expect(describeAction(ra({ location: winlogon.toUpperCase(), value_name: 'shell', restore_data: 'explorer.exe' }))).toMatch(/^Restore default of /)
    expect(describeAction(ra({ location: 'HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', value_name: 'Shell', restore_data: 'explorer.exe' }))).toMatch(/^Restore default/)
    expect(describeAction(ra({ location: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager', value_name: 'BootExecute', restore_data: 'autocheck autochk *' }))).toMatch(/^Restore default/)
    expect(describeAction(ra({ location: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest', value_name: 'UseLogonCredential', restore_data: 'dword:0' }))).toMatch(/^Restore default/)
    // Unusual writes are spelled out.
    expect(describeAction(ra({ location: winlogon, value_name: 'Userinit', restore_data: 'C:\\Windows\\system32\\userinit.exe,\\\\host\\s\\x.exe' }))).toBe(
      `Write C:\\Windows\\system32\\userinit.exe,\\\\host\\s\\x.exe to ${winlogon}\\Userinit`,
    )
    expect(describeAction(ra({ location: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest', value_name: 'UseLogonCredential', restore_data: 'dword:1' }))).toMatch(/^Write dword:1 to /)
    expect(describeAction(ra({ location: 'HKLM\\SOFTWARE\\Classes\\exefile\\shell\\open\\command', value_name: '', restore_data: 'explorer.exe' }))).toMatch(/^Write explorer\.exe to /)
    // Right data under the wrong value name is not a default either.
    expect(isCanonicalDefault(winlogon, 'Userinit', 'explorer.exe')).toBe(false)
    expect(isCanonicalDefault(`${winlogon}\\Sub`, 'Shell', 'explorer.exe')).toBe(false)
  })
  it('the mock enforces it on direct actions and checklist approvals', async () => {
    const prev = db.session
    const analyst = db.users.find((u) => u.role === 'analyst')!
    db.session = analyst
    try {
      const dev = db.devices[0]
      const r = await handleMock('POST', `/devices/${dev.id}/actions`, new URLSearchParams(), { action: { type: 'remove_autorun', kind: 'scheduled_task', location: '\\X' }, comment: 'test' })
      expect(r.status).toBe(403)
      const page = (await handleMock('GET', '/incidents', new URLSearchParams('limit=500'), undefined)).body as Page<Incident>
      let item: ChecklistItem | undefined
      let incId = ''
      for (const i of page.items) {
        const d = (await handleMock('GET', `/incidents/${i.id}`, new URLSearchParams(), undefined)).body as IncidentDetail
        item = d.checklist.find((c) => c.kind === 'approve' && !c.done && c.action?.type === 'remove_autorun')
        if (item) {
          incId = i.id
          break
        }
      }
      expect(item).toBeTruthy()
      const a = await handleMock('POST', `/incidents/${incId}/checklist/${item!.id}`, new URLSearchParams(), { done: true })
      expect(a.status).toBe(403)
      expect(item!.done).toBe(false)
    } finally {
      db.session = prev
    }
  })
  afterAll(() => {
    db.session = db.users[0]
  })
})

describe('V-M6: storyline markdown', () => {
  const phishRaw = 'x` [Kestrel: re-authenticate](https://evil.example/sso) `y'
  /** What the server now emits for an endpoint value inside a code span. */
  const serverCode = (v: string) => '`' + v.replace(/`/g, '\u02cb') + '`'
  /** What the server now emits for endpoint text outside code spans. */
  const serverEsc = (v: string) => v.replace(/[\\`*_[\]<>#|]/g, (c) => `\\${c}`)

  it('the phishing task action never becomes a link (server-escaped, code span)', () => {
    const { container } = render(<Markdown links="none" source={`Registered task with action ${serverCode(phishRaw)}.`} />)
    expect(container.querySelector('a')).toBeNull()
    expect(container.querySelector('code')?.textContent).toContain('[Kestrel: re-authenticate](https://evil.example/sso)')
  })
  it('the phishing text never becomes a link (server-escaped, plain text)', () => {
    for (const links of ['none', 'external'] as const) {
      const { container } = render(<Markdown links={links} source={`Action: ${serverEsc(phishRaw)}`} />)
      expect(container.querySelector('a')).toBeNull()
      expect(container.textContent).toContain('[Kestrel: re-authenticate](https://evil.example/sso)')
    }
  })
  it('raw text with links="none" renders no anchor', () => {
    const { container } = render(<Markdown links="none" source={`Task action \`${phishRaw}\` and [Kestrel: re-authenticate](https://evil.example/sso)`} />)
    expect(container.querySelector('a')).toBeNull()
    expect(container.textContent).toContain('[Kestrel: re-authenticate](https://evil.example/sso)')
  })
  it('an escaped "\\n> **Verified benign**" is not a blockquote or bold', () => {
    const { container } = render(<Markdown links="none" source={`Value data: ${serverEsc('x\n> **Verified benign by Kestrel**')}`} />)
    expect(container.querySelector('blockquote')).toBeNull()
    expect(container.querySelector('strong')).toBeNull()
    expect(container.textContent).toContain('> **Verified benign by Kestrel**')
  })
  it('an escaped heading is literal', () => {
    const { container } = render(<Markdown source={serverEsc('# Incident closed')} />)
    expect(container.querySelector('h1')).toBeNull()
    expect(container.textContent).toBe('# Incident closed')
  })
  it('backslash escapes: \\\\ renders one backslash, \\[ blocks a link at the same position', () => {
    const { container } = render(<Markdown source={'a\\\\b \\*c\\* \\[x](https://ok.example)'} />)
    expect(container.textContent).toBe('a\\b *c* [x](https://ok.example)')
    expect(container.querySelector('a')).toBeNull()
    expect(container.querySelector('em')).toBeNull()
  })
  it('code spans keep backslashes literally', () => {
    const { container } = render(<Markdown source={'Ran `C:\\Users\\x\\*.exe` then `\\\\srv\\s`'} />)
    const codes = container.querySelectorAll('code')
    expect(codes[0].textContent).toBe('C:\\Users\\x\\*.exe')
    expect(codes[1].textContent).toBe('\\\\srv\\s')
  })
  it('links="external" links only https', () => {
    const { container } = render(<Markdown source={'[a](https://ok.example/x) [b](http://plain.example) [c](mailto:x@y.z) [d](javascript:alert(1))'} />)
    const as = container.querySelectorAll('a')
    expect(as).toHaveLength(1)
    expect(as[0].getAttribute('href')).toBe('https://ok.example/x')
    expect(as[0].getAttribute('rel')).toBe('noreferrer noopener')
    expect(as[0].getAttribute('target')).toBe('_blank')
    expect(container.textContent).toContain('[b](http://plain.example)')
  })
  it('bold and em still work, including escapes inside', () => {
    const { container } = render(<Markdown source={'**bold \\* star** and *em*'} />)
    expect(container.querySelector('strong')?.textContent).toBe('bold * star')
    expect(container.querySelector('em')?.textContent).toBe('em')
  })
})

describe('rule references', () => {
  it('links only absolute http(s) URLs', () => {
    expect(referenceHref('https://attack.mitre.org/techniques/T1053/')).toBe('https://attack.mitre.org/techniques/T1053/')
    expect(referenceHref('http://example.com/a')).toBe('http://example.com/a')
    expect(referenceHref('javascript:alert(1)')).toBeNull()
    expect(referenceHref('JaVaScRiPt:alert(1)')).toBeNull()
    expect(referenceHref('data:text/html,<script>alert(1)</script>')).toBeNull()
    expect(referenceHref('//evil.example/x')).toBeNull()
    expect(referenceHref('Internal research notes')).toBeNull()
  })
})

describe('attribution display', () => {
  const base = { ts: 1, pid: 10, guid: 'g' }
  const kinds = (e: KEvent) => eventProvenance(e).map((p) => p.kind)
  it('maps attribution, remote_writer, canary_in_place and agent_spawned', () => {
    expect(kinds({ ...base, type: 'task_registered', name: '\\T', op: 'created', attribution: 'heuristic' })).toEqual(['writer_inferred'])
    expect(kinds({ ...base, type: 'service_installed', name: 's', image_path: 'x', attribution: 'none' })).toEqual(['writer_unknown'])
    expect(kinds({ ...base, type: 'wmi_subscription', namespace: 'n', filter: 'f', consumer: 'c', attribution: 'exact' })).toEqual([])
    expect(kinds({ ...base, type: 'registry_set', key: 'k', value_name: 'v' })).toEqual([])
    expect(kinds({ ...base, type: 'registry_set', key: 'k', value_name: 'v', attribution: 'heuristic' })).toEqual(['writer_inferred'])
    expect(kinds({ ...base, type: 'file_activity', window_ms: 1, files_touched: 1, dirs: 1, remote_writer: true })).toEqual(['remote_smb'])
    expect(kinds({ ...base, type: 'file_activity', window_ms: 1, files_touched: 1, dirs: 1, canary_hits: ['c'], canary_in_place: true })).toEqual(['canary_polled'])
    expect(kinds({ ...base, type: 'process_start', ppid: 1, image: 'p', cmdline: 'p', agent_spawned: true })).toEqual(['agent_spawned'])
    expect(kinds({ ...base, type: 'process_start', ppid: 1, image: 'p', cmdline: 'p' })).toEqual([])
  })
  it('describes remote and polled file activity', () => {
    const fa: KEvent = { ...base, type: 'file_activity', window_ms: 10_000, files_touched: 5, dirs: 1, overwrites: 5, canary_hits: ['c'], canary_in_place: true, remote_writer: true }
    const s = describeEvent(fa)
    expect(s).toContain('found by polling, writer inferred')
    expect(s).toContain('remote client over SMB')
  })
  it('renders badges with icon + label', () => {
    const e: DeviceEvent = { ...base, device_id: 'd', type: 'task_registered', name: '\\T', op: 'created', attribution: 'heuristic' }
    const { container } = render(
      <TooltipProvider>
        <ProvenanceBadges event={e} />
      </TooltipProvider>,
    )
    const chip = container.querySelector('[data-provenance="writer_inferred"]')
    expect(chip?.textContent).toBe('writer inferred')
    expect(chip?.querySelector('svg')).not.toBeNull()
    const none = render(
      <TooltipProvider>
        <ProvenanceBadges event={{ ...base, type: 'registry_set', key: 'k', value_name: 'v', attribution: 'exact' }} />
      </TooltipProvider>,
    )
    expect(none.container.textContent).toBe('')
  })
  it('derives agent_spawned for tree nodes and never offers them as kill targets', () => {
    const node: TreeNode = { guid: 'g', parent_guid: null, pid: 1, image: 'C:\\Users\\x\\AppData\\Local\\Temp\\k.exe', cmdline: '', user: null, start_ts: 0, exit_ts: null, signer: null, signed: 'valid', sha256: null, path_class: 'temp', alert_rule_ids: ['X'], is_root: true }
    expect(isSafeKillTarget(node)).toBe(true)
    const [marked] = withAgentSpawned([node], [{ ...base, type: 'process_start', ppid: 1, image: 'p', cmdline: 'p', agent_spawned: true }])
    expect(marked.agent_spawned).toBe(true)
    expect(isSafeKillTarget(marked)).toBe(false)
    const same = [node]
    expect(withAgentSpawned(same, [])).toBe(same)
  })
})
