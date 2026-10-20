import { describe, expect, it } from 'vitest'
import type { PathClass, TreeNode } from '@/api/types'
import { isSafeKillTarget, pickTarget } from './incident-parts'

let n = 0
function node(image: string, path_class: PathClass, parent: string | null, rules: string[] = [], guid = `g${++n}`): TreeNode {
  return { guid, parent_guid: parent, pid: 1000 + n, image, cmdline: image, user: 'CORP\\j.doe', start_ts: n, exit_ts: null, signer: null, signed: 'unknown', sha256: null, path_class, alert_rule_ids: rules, is_root: parent === null }
}

describe('pickTarget (L11: never offer shells or OS binaries)', () => {
  it('ClickFix: alert on explorer.exe → kills the payload it started, not explorer', () => {
    const explorer = node('C:\\Windows\\explorer.exe', 'windows', null, ['ST-10'], 'e')
    const ps = node('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'system', 'e', [], 'ps')
    const payload = node('C:\\Users\\jd\\AppData\\Local\\Temp\\vcredist_x64.exe', 'temp', 'ps', [], 'v')
    const t = pickTarget([explorer, ps, payload])
    expect(t?.guid).toBe('v')
  })

  it('prefers the alerted user-writable process', () => {
    const explorer = node('C:\\Windows\\explorer.exe', 'windows', null, [], 'e')
    const stealer = node('C:\\Users\\a\\Downloads\\setup_x64.exe', 'downloads', 'e', ['ST-01', 'ST-04'], 's')
    const cmd = node('C:\\Windows\\System32\\cmd.exe', 'system', 's', ['ST-11'], 'c')
    expect(pickTarget([explorer, stealer, cmd])?.guid).toBe('s')
  })

  it('never returns a shell or system process, even when it is the only one alerted', () => {
    const explorer = node('C:\\Windows\\explorer.exe', 'windows', null, ['ST-10'], 'e')
    const cmd = node('C:\\Windows\\System32\\cmd.exe', 'system', 'e', ['ST-11'], 'c')
    const svchost = node('C:\\Windows\\System32\\svchost.exe', 'system', null, ['ST-05'], 'sv')
    expect(pickTarget([explorer, cmd, svchost])).toBeNull()
  })

  it('shells in protected folders are unsafe; look-alikes in user folders are malware', () => {
    expect(isSafeKillTarget(node('C:\\Users\\a\\Downloads\\explorer.exe', 'downloads', null))).toBe(true)
    expect(isSafeKillTarget(node('C:\\Windows\\explorer.exe', 'windows', null))).toBe(false)
    expect(isSafeKillTarget(node('C:\\Program Files\\PowerShell\\7\\pwsh.exe', 'program_files', null))).toBe(false)
    expect(isSafeKillTarget(node('C:\\Users\\a\\Downloads\\tool.exe', 'downloads', null))).toBe(true)
  })
})
