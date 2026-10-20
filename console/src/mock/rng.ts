/** Deterministic PRNG so the demo data is stable between reloads. */
export function mulberry32(seed: number) {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export const rand = mulberry32(0x6b657374)

export function pick<T>(xs: readonly T[]): T {
  return xs[Math.floor(rand() * xs.length)]
}
export function int(min: number, max: number): number {
  return Math.floor(min + rand() * (max - min + 1))
}
export function chance(p: number): boolean {
  return rand() < p
}
export function hexId(len = 32): string {
  let s = ''
  for (let i = 0; i < len; i++) s += Math.floor(rand() * 16).toString(16)
  return s
}
export function uuid(): string {
  const h = hexId(32)
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${'89ab'[Math.floor(rand() * 4)]}${h.slice(17, 20)}-${h.slice(20, 32)}`
}
export function sha256(): string {
  return hexId(64)
}
