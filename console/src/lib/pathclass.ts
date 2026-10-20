import type { PathClass } from '@/api/types'

/** Port of `PathClass::of` from kestrel-common (case-insensitive, either separator). */
export function pathClassOf(path: string): PathClass {
  let p = path.replace(/\//g, '\\').toLowerCase()
  if (p.startsWith('\\\\?\\')) p = p.slice(4)
  if (p.startsWith('\\\\')) return 'external'
  const rest = p.length > 2 && p[1] === ':' ? p.slice(2) : p
  if (rest.startsWith('\\windows\\system32\\') || rest.startsWith('\\windows\\syswow64\\') || rest.startsWith('\\windows\\winsxs\\'))
    return 'system'
  if (rest.startsWith('\\windows\\')) return rest.startsWith('\\windows\\temp\\') ? 'temp' : 'windows'
  if (rest.startsWith('\\program files\\') || rest.startsWith('\\program files (x86)\\')) return 'program_files'
  if (rest.startsWith('\\users\\')) {
    if (rest.includes('\\appdata\\local\\temp\\')) return 'temp'
    if (rest.includes('\\downloads\\')) return 'downloads'
    return 'user_writable'
  }
  if (rest.startsWith('\\programdata\\') || rest.startsWith('\\temp\\') || rest.startsWith('\\tmp\\')) return 'user_writable'
  return 'other'
}
