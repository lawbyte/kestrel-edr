/**
 * Client-side mirror of `kestrel_common::remote::{validate_remote_path,
 * parent_of, file_name_of, path_is_within}`. The server and agent validate
 * again; this only gives the admin an immediate, plain-words error.
 */

export const PATH_MAX_CHARS = 32_000

export type PathResult = { ok: true; path: string } | { ok: false; error: string }

// Rust `char::is_control` = Unicode Cc: U+0000–U+001F and U+007F–U+009F.
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/
const BAD_CHARS = /[*?"<>|]/

/** Validate and normalise like the Rust `validate_remote_path`. */
export function validateRemotePath(p: string): PathResult {
  const err = (error: string): PathResult => ({ ok: false, error })
  if (p.length === 0) return err('path is empty')
  if ([...p].length > PATH_MAX_CHARS) return err('path is too long')
  if (CONTROL.test(p)) return err('path contains control characters')
  const s = p.replace(/\//g, '\\')
  if (s.length < 2 || !/^[A-Za-z]$/.test(s[0]) || s[1] !== ':') return err('path must be absolute and start with a drive letter (e.g. C:\\)')
  const drive = s[0].toUpperCase()
  if (s.length === 2) return { ok: true, path: `${drive}:\\` }
  if (s[2] !== '\\') return err('path must be absolute (X:\\…)')
  let out = `${drive}:`
  for (const comp of s.slice(3).split('\\')) {
    if (!comp) continue
    if (comp === '.' || comp === '..') return err("path must not contain '.' or '..' components")
    if (comp.includes(':')) return err("path must not contain ':' after the drive (alternate data streams)")
    if (BAD_CHARS.test(comp)) return err('path contains a character Windows does not allow in names')
    if (comp.endsWith('.') || comp.endsWith(' ')) return err('path components must not end with a dot or a space')
    out += '\\' + comp
  }
  if (out.length === 2) out += '\\'
  return { ok: true, path: out }
}

/** A single file / folder name typed by the admin (rename, new folder, upload). */
export function validateName(name: string): string | null {
  if (!name.trim()) return 'Enter a name.'
  if (/[\\/]/.test(name)) return 'A name cannot contain \\ or /.'
  if (name === '.' || name === '..') return 'That name is reserved.'
  if (name.includes(':')) return 'A name cannot contain a colon.'
  if (BAD_CHARS.test(name)) return 'A name cannot contain * ? " < > |'
  if (CONTROL.test(name)) return 'A name cannot contain control characters.'
  if (name.endsWith('.') || name.endsWith(' ')) return 'A name cannot end with a dot or a space.'
  return null
}

/** `parent_of`: parent folder of a normalised path, `null` for a drive root. */
export function parentOf(path: string): string | null {
  const t = path.replace(/\\+$/, '')
  const i = t.lastIndexOf('\\')
  if (i < 0) return null
  if (i <= 2) return `${t.slice(0, 2)}\\`
  return t.slice(0, i)
}

/** `file_name_of`: last component. */
export function fileNameOf(path: string): string {
  const t = path.replace(/[\\/]+$/, '')
  const parts = t.split(/[\\/]/)
  return parts[parts.length - 1] ?? t
}

/** Join a folder and a single name (folder is a normalised path or drive root). */
export function joinPath(folder: string, name: string): string {
  return folder.endsWith('\\') ? folder + name : `${folder}\\${name}`
}

/** `path_is_within`: equal to or inside `root` (case-insensitive, component-wise). */
export function pathIsWithin(path: string, root: string): boolean {
  const norm = (s: string) => s.replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase()
  const p = norm(path)
  const r = norm(root)
  if (!r) return false
  return p === r || p.startsWith(`${r}\\`)
}

/** Breadcrumb segments of a normalised path: `C:\a\b` → [C:\, C:\a, C:\a\b]. */
export function pathSegments(path: string): { label: string; path: string }[] {
  if (!path) return []
  const drive = path.slice(0, 2)
  const out = [{ label: drive, path: `${drive}\\` }]
  let cur = drive
  for (const comp of path.slice(3).split('\\')) {
    if (!comp) continue
    cur += '\\' + comp
    out.push({ label: comp, path: cur })
  }
  return out
}

export type SortKey = 'name' | 'size' | 'modified'
type Sortable = { name: string; kind: string; size: number; modified: number | null; free_bytes?: number | null }

/** Folders (and drives) first, then files; within each group by `key`; name breaks ties. */
export function sortEntries<T extends Sortable>(entries: T[], key: SortKey, desc = false): T[] {
  const rank = (e: T) => (e.kind === 'dir' || e.kind === 'drive' ? 0 : 1)
  const byName = (a: T, b: T) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' })
  const val = (e: T) => (key === 'size' ? (e.kind === 'drive' ? (e.free_bytes ?? 0) : e.size) : (e.modified ?? 0))
  return [...entries].sort((a, b) => {
    const r = rank(a) - rank(b)
    if (r) return r
    const c = key === 'name' ? byName(a, b) : val(a) - val(b) || byName(a, b)
    return desc ? -c : c
  })
}
