/**
 * In-memory file system per device for the mock remote file manager. Mirrors
 * the agent's behaviour from docs/contracts.md: drives at the empty path,
 * Kestrel's own folders refused with `protected_path` (also renaming /
 * deleting / overwriting their ancestors), reparse points deleted as links,
 * folders need `recursive` unless empty.
 */
import type { FileEntry, FileKind, RemoteErrorCode } from '@/api/types'
import { fileNameOf, parentOf, pathIsWithin, validateRemotePath } from '@/lib/remote-path'

export class RemoteFsError extends Error {
  code: RemoteErrorCode
  constructor(code: RemoteErrorCode, message: string) {
    super(message)
    this.code = code
  }
}

export const PROTECTED_ROOTS = ['C:\\Program Files\\Kestrel', 'C:\\ProgramData\\Kestrel']
/** Pretend size of files without stored content (not materialised until downloaded). */
const MATERIALISE_MAX = 8 * 1024 * 1024

interface Node {
  name: string
  kind: FileKind
  size: number
  modified: number
  hidden?: boolean
  readonly?: boolean
  reparse?: boolean
  label?: string
  total?: number
  free?: number
  children?: Map<string, Node>
  content?: Blob
}

const DAY = 86_400_000
const key = (n: string) => n.toLowerCase()

function dir(name: string, children: Node[] = [], o: Partial<Node> = {}, age = 30): Node {
  return { name, kind: 'dir', size: 0, modified: Date.now() - age * DAY, children: new Map(children.map((c) => [key(c.name), c])), ...o }
}
function file(name: string, size: number, age = 5, o: Partial<Node> = {}): Node {
  return { name, kind: 'file', size, modified: Date.now() - age * DAY - (size % 3600) * 1000, ...o }
}
function text(name: string, body: string, age = 2): Node {
  const content = new Blob([body], { type: 'text/plain' })
  return { name, kind: 'file', size: content.size, modified: Date.now() - age * DAY, content }
}

function seed(user: string): Map<string, Node> {
  const home = dir(user, [
    dir('Desktop', [file('Shipping schedule Q4.xlsx', 48_213, 1), text('todo.txt', 'Call DHL about the Jakarta delay\nRenew SSL cert on the portal\n', 0)], {}, 3),
    dir(
      'Documents',
      [
        dir('Contracts', [file('MSA - Pacific Freight.pdf', 812_440, 40), file('NDA - Lumen Analytics.pdf', 201_982, 70)], {}, 40),
        dir('Reports', [file('Q3 board pack.pptx', 4_202_118, 20), file('Fleet utilisation 2026.xlsx', 96_120, 12)], {}, 12),
        file('Expense claim October.xlsx', 31_224, 3),
        text('meeting notes.txt', 'Ops weekly\n- port congestion in Tanjung Priok\n- new forklift vendor shortlist\n', 1),
        file('Passport scan.pdf', 1_302_440, 120, { readonly: true }),
      ],
      {},
      1,
    ),
    dir('Downloads', [file('Setup_x64.exe', 6_244_352, 0), file('invoice_10293.pdf', 99_310, 2), file('ubuntu-24.04.3-desktop-amd64.iso', 6_291_456_000, 30)], {}, 0),
    dir('Pictures', [file('team offsite.jpg', 2_843_112, 60)], {}, 60),
    dir('AppData', [dir('Local'), dir('Roaming')], { hidden: true }, 0),
    { name: 'Cloud Files', kind: 'link', size: 0, modified: Date.now() - 90 * DAY, reparse: true },
    text('NTUSER.DAT', 'registry hive', 0),
  ])
  home.children!.get('ntuser.dat')!.hidden = true
  const c: Node = dir(
    'C:\\',
    [
      dir(
        'Program Files',
        [
          dir('Kestrel', [file('kestrel-agent.exe', 52_428_800, 10), file('agent.toml', 1_204, 10)], {}, 10),
          dir('Google', [dir('Chrome', [dir('Application', [file('chrome.exe', 3_215_872, 7)])])]),
          dir('Microsoft Office', [dir('root')]),
          dir('7-Zip', [file('7z.exe', 589_312, 200), file('7z.dll', 1_850_880, 200)]),
        ],
        { readonly: true },
      ),
      dir('Program Files (x86)', [dir('Microsoft'), dir('Common Files')], { readonly: true }),
      dir('ProgramData', [dir('Kestrel', [dir('quarantine'), file('outbox.db', 3_145_728, 0)]), dir('Microsoft')], { hidden: true }),
      dir('Users', [dir('Public', [dir('Documents'), dir('Desktop')]), dir('Default', [], { hidden: true }), home]),
      dir('Windows', [dir('System32', [file('cmd.exe', 323_584, 300), file('notepad.exe', 360_448, 300), dir('drivers')]), dir('Temp', [text('setup.log', 'install ok\n', 0)])], {}, 2),
      dir('Documents and Settings', [], { hidden: true, reparse: true }, 900),
      file('pagefile.sys', 4_294_967_296, 0, { hidden: true }),
    ],
    { label: 'Local Disk', total: 511_000_000_000, free: 183_400_000_000, kind: 'drive' },
  )
  const d: Node = dir(
    'D:\\',
    [
      dir('Shared', [dir('Finance', [file('AP aging Oct 2026.xlsx', 220_418, 2), file('Vendor master.csv', 88_102, 9)]), dir('Operations', [file('Warehouse SOP v7.docx', 140_870, 30)])]),
      dir('Backups', [file('laptop-image-2026-09.vhdx', 5 * 1024 * 1024 * 1024 + 7, 40)], {}, 40),
    ],
    { label: 'Data', total: 1_000_000_000_000, free: 612_000_000_000, kind: 'drive' },
  )
  return new Map([
    ['c:', c],
    ['d:', d],
  ])
}

function entry(n: Node, path: string): FileEntry {
  const isDrive = n.kind === 'drive'
  let attributes = 0
  if (n.readonly) attributes |= 0x1
  if (n.hidden) attributes |= 0x2
  if (n.kind === 'dir' || isDrive) attributes |= 0x10
  if (n.kind === 'file') attributes |= 0x20
  if (n.reparse) attributes |= 0x400
  return {
    name: isDrive ? path : n.name,
    path,
    kind: n.kind,
    size: n.kind === 'file' ? n.size : 0,
    modified: isDrive ? null : n.modified,
    attributes,
    hidden: !!n.hidden,
    readonly: !!n.readonly,
    reparse: !!n.reparse,
    free_bytes: isDrive ? (n.free ?? null) : null,
    total_bytes: isDrive ? (n.total ?? null) : null,
    label: isDrive ? (n.label ?? null) : null,
  }
}

export class MockFs {
  private drives: Map<string, Node>
  constructor(user: string) {
    this.drives = seed(user)
  }

  private norm(p: string): string {
    const v = validateRemotePath(p)
    if (!v.ok) throw new RemoteFsError('invalid_path', v.error)
    return v.path
  }

  private isProtected(path: string) {
    return PROTECTED_ROOTS.some((r) => pathIsWithin(path, r))
  }
  /** Inside a protected folder, or an ancestor of one (rename / delete / overwrite). */
  private guardMutation(path: string) {
    if (this.isProtected(path) || PROTECTED_ROOTS.some((r) => pathIsWithin(r, path))) throw new RemoteFsError('protected_path', `${path} is protected`)
  }

  private lookup(path: string): Node | null {
    const drive = this.drives.get(key(path.slice(0, 2)))
    if (!drive) return null
    let cur: Node = drive
    for (const comp of path.slice(3).split('\\').filter(Boolean)) {
      const next = cur.children?.get(key(comp))
      if (!next) return null
      cur = next
    }
    return cur
  }
  private must(path: string): Node {
    const n = this.lookup(path)
    if (!n) throw new RemoteFsError('not_found', `${path} was not found`)
    return n
  }
  private parentDir(path: string): Node {
    const parent = parentOf(path)
    if (!parent) throw new RemoteFsError('invalid_operation', 'a drive root has no parent')
    const n = this.lookup(parent)
    if (!n) throw new RemoteFsError('not_found', `${parent} was not found`)
    if (!n.children) throw new RemoteFsError('invalid_operation', `${parent} is not a folder`)
    return n
  }

  list(p: string): { path: string; parent: string | null; entries: FileEntry[]; truncated: boolean } {
    if (!p) return { path: '', parent: null, entries: [...this.drives.values()].map((d) => entry(d, d.name)), truncated: false }
    const path = this.norm(p)
    if (this.isProtected(path)) throw new RemoteFsError('protected_path', `${path} is protected`)
    const n = this.must(path)
    if (!n.children) throw new RemoteFsError('invalid_operation', `${path} is not a folder`)
    if (n.kind === 'link') throw new RemoteFsError('invalid_operation', 'links are not followed')
    const entries = [...n.children.values()].map((c) => entry(c, path.endsWith('\\') ? path + c.name : `${path}\\${c.name}`))
    return { path, parent: path.length <= 3 ? '' : parentOf(path), entries, truncated: false }
  }

  stat(p: string): FileEntry {
    const path = this.norm(p)
    if (this.isProtected(path)) throw new RemoteFsError('protected_path', `${path} is protected`)
    const n = this.must(path)
    return entry(n, n.kind === 'drive' ? n.name : path)
  }

  read(p: string): { entry: FileEntry; blob: Blob } {
    const path = this.norm(p)
    if (this.isProtected(path)) throw new RemoteFsError('protected_path', `${path} is protected`)
    const n = this.must(path)
    if (n.kind !== 'file') throw new RemoteFsError('invalid_operation', `${path} is a folder`)
    if (n.size > 4 * 1024 * 1024 * 1024) throw new RemoteFsError('too_large', 'larger than 4 GiB')
    if (!n.content) {
      if (n.size > MATERIALISE_MAX) {
        // Big demo files: a small placeholder so the browser download works without allocating gigabytes.
        n.content = new Blob([`Kestrel mock: placeholder for ${n.name} (${n.size} bytes on the device)\n`])
      } else {
        const bytes = new Uint8Array(n.size)
        for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 31 + n.name.length) & 0xff
        n.content = new Blob([bytes])
      }
    }
    return { entry: entry(n, path), blob: n.content }
  }

  write(p: string, blob: Blob): { path: string; size: number } {
    const path = this.norm(p)
    if (path.length <= 3) throw new RemoteFsError('invalid_operation', 'cannot write to a drive root')
    this.guardMutation(path)
    const parent = this.parentDir(path)
    const name = fileNameOf(path)
    const existing = parent.children!.get(key(name))
    if (existing && existing.kind !== 'file') throw new RemoteFsError('invalid_operation', `${path} is a folder`)
    if (existing?.readonly) throw new RemoteFsError('access_denied', `${path} is read-only`)
    parent.children!.set(key(name), { name: existing?.name ?? name, kind: 'file', size: blob.size, modified: Date.now(), content: blob })
    parent.modified = Date.now()
    return { path, size: blob.size }
  }

  mkdir(p: string): { path: string } {
    const path = this.norm(p)
    this.guardMutation(path)
    const drive = this.drives.get(key(path.slice(0, 2)))
    if (!drive) throw new RemoteFsError('not_found', `drive ${path.slice(0, 2)} was not found`)
    let cur = drive
    for (const comp of path.slice(3).split('\\').filter(Boolean)) {
      let next = cur.children!.get(key(comp))
      if (!next) {
        next = dir(comp, [], {}, 0)
        cur.children!.set(key(comp), next)
        cur.modified = Date.now()
      } else if (!next.children) {
        throw new RemoteFsError('already_exists', `${comp} exists and is a file`)
      }
      cur = next
    }
    return { path }
  }

  rename(fromP: string, toP: string, overwrite = false): { from: string; to: string } {
    const from = this.norm(fromP)
    const to = this.norm(toP)
    if (from.length <= 3 || to.length <= 3) throw new RemoteFsError('invalid_operation', 'drive roots cannot be renamed')
    this.guardMutation(from)
    this.guardMutation(to)
    if (from.slice(0, 2).toLowerCase() !== to.slice(0, 2).toLowerCase()) throw new RemoteFsError('invalid_operation', 'cannot move between drives')
    if (pathIsWithin(to, from) && key(to) !== key(from)) throw new RemoteFsError('invalid_operation', 'cannot move a folder into itself')
    const n = this.must(from)
    const srcParent = this.parentDir(from)
    const dstParent = this.parentDir(to)
    const dstName = fileNameOf(to)
    const existing = dstParent.children!.get(key(dstName))
    if (existing && existing !== n) {
      if (!overwrite) throw new RemoteFsError('already_exists', `${to} already exists`)
      if (existing.kind !== 'file' || n.kind !== 'file') throw new RemoteFsError('invalid_operation', 'only a file can replace a file')
    }
    srcParent.children!.delete(key(n.name))
    n.name = dstName
    n.modified = Date.now()
    dstParent.children!.set(key(dstName), n)
    return { from, to }
  }

  remove(p: string, recursive = false): { path: string; removed: number } {
    const path = this.norm(p)
    if (path.length <= 3) throw new RemoteFsError('invalid_operation', 'drive roots cannot be deleted')
    this.guardMutation(path)
    const n = this.must(path)
    if (n.readonly && n.kind === 'file') throw new RemoteFsError('access_denied', `${path} is read-only`)
    // Reparse points are removed as links, never followed.
    if (!n.reparse && n.children && n.children.size > 0 && !recursive) throw new RemoteFsError('invalid_operation', `${path} is not empty`)
    const count = (x: Node): number => 1 + (x.reparse || !x.children ? 0 : [...x.children.values()].reduce((s, c) => s + count(c), 0))
    const removed = count(n)
    this.parentDir(path).children!.delete(key(n.name))
    return { path, removed }
  }
}

const perDevice = new Map<string, MockFs>()
export function fsFor(deviceId: string, loggedOnUser: string | null): MockFs {
  let fs = perDevice.get(deviceId)
  if (!fs) {
    const user = (loggedOnUser ?? 'Administrator').split('\\').pop() || 'Administrator'
    fs = new MockFs(user.toLowerCase())
    perDevice.set(deviceId, fs)
  }
  return fs
}
