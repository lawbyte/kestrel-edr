import { describe, expect, it } from 'vitest'
import { astToString, complete, evaluate, parseHunt, suggestField, tokenize } from './hunt'

describe('tokenize', () => {
  it('splits fields, operators, values and keywords', () => {
    const { tokens } = tokenize('image ~ powershell AND dst_port>8000')
    expect(tokens.map((t) => t.t)).toEqual(['word', 'op', 'word', 'and', 'word', 'op', 'word'])
  })
  it('handles quoted strings with escapes', () => {
    const { tokens } = tokenize('file_path = "C:\\\\Users\\\\a b\\\\Login Data"')
    expect(tokens[2]).toMatchObject({ t: 'str', v: 'C:\\Users\\a b\\Login Data' })
  })
  it('reports unterminated strings', () => {
    expect(tokenize('cmdline ~ "abc').error?.message).toMatch(/Unterminated/)
  })
  it('treats != as one operator', () => {
    expect(tokenize('signer!=x').tokens.map((t) => (t.t === 'op' ? t.v : t.t))).toEqual(['word', '!=', 'word'])
  })
})

describe('parseHunt', () => {
  it('accepts an empty query', () => {
    expect(parseHunt('  ')).toEqual({ ok: true, ast: [] })
  })
  it('builds DNF with and binding tighter than or', () => {
    const r = parseHunt('event_type = dns_query and dns_qname ~ telegram or dst_port = 8545')
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.ast).toHaveLength(2)
    expect(r.ast[0]).toHaveLength(2)
    expect(r.ast[1][0]).toEqual({ field: 'dst_port', op: '=', value: '8545' })
  })
  it('rejects unknown fields with a suggestion', () => {
    const r = parseHunt('imge = x')
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.error.message).toContain('image')
    expect(r.error.pos).toBe(0)
  })
  it('rejects > on text fields and non-numbers on numeric fields', () => {
    expect(parseHunt('image > 3').ok).toBe(false)
    const r = parseHunt('dst_port = https')
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.message).toMatch(/number/)
  })
  it('requires and/or between conditions', () => {
    const r = parseHunt('image = a cmdline = b')
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.pos).toBe(10)
  })
  it('reports missing values at end of input', () => {
    const r = parseHunt('image =')
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error.pos).toBe(7)
  })
  it('round-trips through astToString', () => {
    const q = 'image ~ "Login Data" and dst_port > 1000 or signer != "Google LLC"'
    const a = parseHunt(q)
    expect(a.ok).toBe(true)
    if (!a.ok) return
    const b = parseHunt(astToString(a.ast))
    expect(b).toEqual(a)
  })
})

describe('evaluate', () => {
  const rec = { event_type: 'net_connect', image: 'C:\\Users\\a\\AppData\\Local\\Temp\\Setup_x64.exe', dst_ip: '149.154.167.220', dst_port: 443, dns_qname: 'api.telegram.org' }
  const run = (q: string) => {
    const p = parseHunt(q)
    if (!p.ok) throw new Error(p.error.message)
    return evaluate(p.ast, rec)
  }
  it('matches case-insensitive equality and contains', () => {
    expect(run('event_type = NET_CONNECT')).toBe(true)
    expect(run('image ~ \\temp\\')).toBe(true)
    expect(run('image ~ chrome')).toBe(false)
  })
  it('compares numbers', () => {
    expect(run('dst_port > 400 and dst_port < 500')).toBe(true)
    expect(run('dst_port = 8545')).toBe(false)
  })
  it('treats missing fields as not equal', () => {
    expect(run('cmdline != x')).toBe(true)
    expect(run('cmdline = x')).toBe(false)
  })
  it('handles or groups', () => {
    expect(run('dst_port = 8545 or dns_qname = api.telegram.org')).toBe(true)
  })
  it('empty query matches everything', () => {
    expect(evaluate([], rec)).toBe(true)
  })
})

describe('complete', () => {
  it('suggests fields at the start', () => {
    const c = complete('dn', 2)
    expect(c.from).toBe(0)
    expect(c.items.map((i) => i.label)).toEqual(['dns_qname'])
  })
  it('suggests operators after a field, numeric ops only for numeric fields', () => {
    expect(complete('image ', 6).items.map((i) => i.label)).toEqual(['=', '!=', '~'])
    expect(complete('dst_port ', 9).items.map((i) => i.label)).toContain('>')
  })
  it('suggests values from hints after an operator, quoting when needed', () => {
    const c = complete('file_path ~ log', 15, { file_path: ['Login Data', 'logins.json'] })
    expect(c.from).toBe(12)
    expect(c.items.map((i) => i.insert)).toEqual(['"Login Data" ', 'logins.json '])
  })
  it('suggests and/or after a complete condition', () => {
    expect(complete('image = x ', 10).items.map((i) => i.label)).toEqual(['and', 'or'])
  })
  it('suggests fields after a keyword', () => {
    expect(complete('image = x and us', 16).items.map((i) => i.label)).toEqual(['user'])
  })
})

describe('suggestField', () => {
  it('finds near misses', () => {
    expect(suggestField('hostnmae')).toContain('hostname')
    expect(suggestField('dst')).toEqual(['dst_ip', 'dst_port'])
  })
})
