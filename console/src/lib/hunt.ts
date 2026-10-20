/**
 * Client-side helper for the v1 hunt language (contracts.md → Hunt):
 *   field op value  joined by `and` / `or`
 *   ops: =  !=  ~ (contains, case-insensitive)  >  <  (numbers)
 * The server is the authority; this module gives the editor instant
 * validation, autocomplete and a local evaluator used by the mock API.
 */

export const HUNT_FIELDS = [
  'event_type',
  'image',
  'cmdline',
  'file_path',
  'dst_ip',
  'dst_port',
  'dns_qname',
  'signer',
  'sha256',
  'user',
  'hostname',
  'device_id',
] as const
export type HuntField = (typeof HUNT_FIELDS)[number]

export const HUNT_OPS = ['=', '!=', '~', '>', '<'] as const
export type HuntOp = (typeof HUNT_OPS)[number]

export const NUMERIC_FIELDS: ReadonlySet<HuntField> = new Set(['dst_port'])

export const FIELD_HELP: Record<HuntField, string> = {
  event_type: 'Event kind, e.g. process_start, file_access, net_connect, dns_query, dpapi_unprotect',
  image: 'Full path of the acting process image',
  cmdline: 'Process command line (process_start)',
  file_path: 'Path of a file_access or image_load event',
  dst_ip: 'Destination IP of a network connection',
  dst_port: 'Destination port (number; supports > and <)',
  dns_qname: 'Queried DNS name',
  signer: 'Authenticode signer subject',
  sha256: 'SHA-256 of the process image',
  user: 'User account that ran the process',
  hostname: 'Device hostname',
  device_id: 'Device UUID',
}

export interface Condition {
  field: HuntField
  op: HuntOp
  value: string
}
/** Disjunctive normal form: OR of AND-groups (`and` binds tighter than `or`). */
export type HuntAst = Condition[][]

export interface HuntError {
  message: string
  /** Character offset in the query where the problem starts. */
  pos: number
}

export type ParseResult = { ok: true; ast: HuntAst } | { ok: false; error: HuntError }

type Tok =
  | { t: 'word'; v: string; pos: number }
  | { t: 'str'; v: string; pos: number }
  | { t: 'op'; v: HuntOp; pos: number }
  | { t: 'and' | 'or'; pos: number }

export function tokenize(src: string): { tokens: Tok[]; error?: HuntError } {
  const tokens: Tok[] = []
  let i = 0
  while (i < src.length) {
    const c = src[i]
    if (/\s/.test(c)) {
      i++
      continue
    }
    if (c === '"' || c === "'") {
      const q = c
      const start = i
      i++
      let v = ''
      while (i < src.length && src[i] !== q) {
        if (src[i] === '\\' && i + 1 < src.length) {
          v += src[i + 1]
          i += 2
          continue
        }
        v += src[i++]
      }
      if (i >= src.length) return { tokens, error: { message: 'Unterminated string', pos: start } }
      i++
      tokens.push({ t: 'str', v, pos: start })
      continue
    }
    if (c === '!' && src[i + 1] === '=') {
      tokens.push({ t: 'op', v: '!=', pos: i })
      i += 2
      continue
    }
    if (c === '=' || c === '~' || c === '>' || c === '<') {
      tokens.push({ t: 'op', v: c as HuntOp, pos: i })
      i++
      continue
    }
    const start = i
    let v = ''
    while (i < src.length && !/\s/.test(src[i]) && !'=~<>"\''.includes(src[i]) && !(src[i] === '!' && src[i + 1] === '=')) {
      v += src[i++]
    }
    const lower = v.toLowerCase()
    if (lower === 'and' || lower === 'or') tokens.push({ t: lower, pos: start })
    else tokens.push({ t: 'word', v, pos: start })
  }
  return { tokens }
}

export function parseHunt(src: string): ParseResult {
  if (!src.trim()) return { ok: true, ast: [] }
  const { tokens, error } = tokenize(src)
  if (error) return { ok: false, error }
  const groups: HuntAst = [[]]
  let i = 0
  const expectCondition = (): Condition | HuntError => {
    const f = tokens[i]
    if (!f || f.t !== 'word') return { message: 'Expected a field name', pos: f?.pos ?? src.length }
    const field = f.v.toLowerCase()
    if (!(HUNT_FIELDS as readonly string[]).includes(field))
      return { message: `Unknown field "${f.v}". Try: ${suggestField(f.v).join(', ') || HUNT_FIELDS.join(', ')}`, pos: f.pos }
    i++
    const o = tokens[i]
    if (!o || o.t !== 'op') return { message: `Expected an operator after ${field} (=, !=, ~, >, <)`, pos: o?.pos ?? src.length }
    i++
    const v = tokens[i]
    if (!v || (v.t !== 'word' && v.t !== 'str'))
      return { message: `Expected a value after ${field} ${o.v}`, pos: v?.pos ?? src.length }
    i++
    const hf = field as HuntField
    if ((o.v === '>' || o.v === '<') && !NUMERIC_FIELDS.has(hf))
      return { message: `"${o.v}" only works on numeric fields (${[...NUMERIC_FIELDS].join(', ')})`, pos: o.pos }
    if (NUMERIC_FIELDS.has(hf) && o.v !== '~' && !/^\d+$/.test(v.v))
      return { message: `${field} expects a number`, pos: v.pos }
    return { field: hf, op: o.v, value: v.v }
  }
  for (;;) {
    const c = expectCondition()
    if ('message' in c) return { ok: false, error: c }
    groups[groups.length - 1].push(c)
    const j = tokens[i]
    if (!j) break
    if (j.t === 'and') {
      i++
      continue
    }
    if (j.t === 'or') {
      i++
      groups.push([])
      continue
    }
    return { ok: false, error: { message: 'Expected "and" or "or" between conditions', pos: j.pos } }
  }
  return { ok: true, ast: groups }
}

function levenshtein(a: string, b: string): number {
  const m = a.length
  const n = b.length
  const d = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)] as number[])
  for (let j = 1; j <= n; j++) d[0][j] = j
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1))
  return d[m][n]
}

export function suggestField(input: string): HuntField[] {
  const s = input.toLowerCase()
  return HUNT_FIELDS.filter((f) => f.startsWith(s) || f.includes(s) || levenshtein(f, s) <= 2).slice(0, 3)
}

export type CompletionKind = 'field' | 'op' | 'keyword' | 'value'
export interface Completion {
  label: string
  insert: string
  kind: CompletionKind
  detail?: string
}
export interface CompletionResult {
  /** Replace src.slice(from, cursor) with the chosen `insert`. */
  from: number
  items: Completion[]
}

/** Context-aware completions at `cursor`. */
export function complete(src: string, cursor: number, valueHints: Partial<Record<HuntField, string[]>> = {}): CompletionResult {
  const before = src.slice(0, cursor)
  const m = /([A-Za-z_][\w.]*|"[^"]*|'[^']*|[!=~<>]+)?$/.exec(before)
  const partial = m?.[1] ?? ''
  const from = cursor - partial.length
  const { tokens } = tokenize(before.slice(0, from))
  const last = tokens[tokens.length - 1]
  const prev = tokens[tokens.length - 2]

  const fieldItems = (p: string): Completion[] =>
    HUNT_FIELDS.filter((f) => f.startsWith(p.toLowerCase())).map((f) => ({
      label: f,
      insert: f + ' ',
      kind: 'field' as const,
      detail: FIELD_HELP[f],
    }))

  // Start, or after and/or → field
  if (!last || last.t === 'and' || last.t === 'or') return { from, items: fieldItems(partial) }
  // After a field → operator
  if (last.t === 'word' && (!prev || prev.t === 'and' || prev.t === 'or')) {
    const field = last.v.toLowerCase() as HuntField
    const ops = NUMERIC_FIELDS.has(field) ? HUNT_OPS : HUNT_OPS.filter((o) => o !== '>' && o !== '<')
    const opHelp: Record<HuntOp, string> = { '=': 'equals', '!=': 'not equal', '~': 'contains (case-insensitive)', '>': 'greater than', '<': 'less than' }
    return {
      from,
      items: ops.filter((o) => o.startsWith(partial)).map((o) => ({ label: o, insert: o + ' ', kind: 'op' as const, detail: opHelp[o] })),
    }
  }
  // After an operator → value hints
  if (last.t === 'op' && prev && prev.t === 'word') {
    const field = prev.v.toLowerCase() as HuntField
    const p = partial.replace(/^["']/, '').toLowerCase()
    const hints = (valueHints[field] ?? []).filter((v) => v.toLowerCase().includes(p)).slice(0, 12)
    return {
      from,
      items: hints.map((v) => ({ label: v, insert: (/[\s=~<>!]/.test(v) || v.includes('\\') ? JSON.stringify(v) : v) + ' ', kind: 'value' as const })),
    }
  }
  // After a value → and/or
  if (last.t === 'word' || last.t === 'str') {
    return {
      from,
      items: ['and', 'or']
        .filter((k) => k.startsWith(partial.toLowerCase()))
        .map((k) => ({ label: k, insert: k + ' ', kind: 'keyword' as const })),
    }
  }
  return { from, items: [] }
}

/** Flat record view of an event used for local evaluation (mock API, client filtering). */
export type HuntRecord = Partial<Record<HuntField, string | number | null | undefined>>

export function matchCondition(rec: HuntRecord, c: Condition): boolean {
  const raw = rec[c.field]
  if (raw == null) return c.op === '!='
  if (NUMERIC_FIELDS.has(c.field) && (c.op === '>' || c.op === '<' || c.op === '=' || c.op === '!=')) {
    const a = Number(raw)
    const b = Number(c.value)
    if (c.op === '>') return a > b
    if (c.op === '<') return a < b
    if (c.op === '=') return a === b
    return a !== b
  }
  const a = String(raw).toLowerCase()
  const b = c.value.toLowerCase()
  switch (c.op) {
    case '=':
      return a === b
    case '!=':
      return a !== b
    case '~':
      return a.includes(b)
    default:
      return false
  }
}

export function evaluate(ast: HuntAst, rec: HuntRecord): boolean {
  if (ast.length === 0) return true
  return ast.some((group) => group.every((c) => matchCondition(rec, c)))
}

export function astToString(ast: HuntAst): string {
  return ast
    .map((g) => g.map((c) => `${c.field} ${c.op} ${/[\s"=~<>!]/.test(c.value) || c.value === '' ? JSON.stringify(c.value) : c.value}`).join(' and '))
    .join(' or ')
}

export const EXAMPLE_QUERIES: { label: string; query: string }[] = [
  { label: 'Non-browser access to Telegram API', query: 'dns_qname = api.telegram.org' },
  { label: 'Programs started from Downloads', query: 'event_type = process_start and image ~ \\Downloads\\' },
  { label: 'Reads of Chrome Login Data', query: 'event_type = file_access and file_path ~ "Login Data"' },
  { label: 'Browser launched with remote debugging', query: 'cmdline ~ --remote-debugging and cmdline ~ --headless' },
  { label: 'Blockchain RPC (port 8545)', query: 'dst_port = 8545' },
  { label: 'PowerShell with encoded/download cradle', query: 'image ~ powershell and cmdline ~ downloadstring or cmdline ~ frombase64string' },
]
