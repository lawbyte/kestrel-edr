export interface Change {
  path: string
  before: unknown
  after: unknown
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** Structural diff of two JSON values; arrays are compared as a whole. */
export function diffJson(a: unknown, b: unknown, path = ''): Change[] {
  if (isObj(a) && isObj(b)) {
    const keys = Array.from(new Set([...Object.keys(a), ...Object.keys(b)])).sort()
    return keys.flatMap((k) => diffJson(a[k], b[k], path ? `${path}.${k}` : k))
  }
  if (JSON.stringify(a) === JSON.stringify(b)) return []
  return [{ path, before: a, after: b }]
}
