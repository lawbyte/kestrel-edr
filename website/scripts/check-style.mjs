#!/usr/bin/env node
// Style check for the documentation site source. Fails (exit 1) on:
//   * en dash (U+2013) and em dash (U+2014)
//   * emoji and other pictographs (\p{Extended_Pictographic})
//   * banned marketing / filler phrases (case-insensitive, word-boundaried)
// Scans .md, .mts, .ts, .vue and .css files under website/, skipping
// node_modules, .vitepress/cache and .vitepress/dist.

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const exts = ['.md', '.mts', '.ts', '.vue', '.css']
const skip = [
  'node_modules',
  join('.vitepress', 'cache'),
  join('.vitepress', 'dist'),
]

const banned = [
  'seamless', 'seamlessly', 'robust', 'leverage', 'leverages', 'leveraging', 'delve', 'delves',
  'comprehensive', 'cutting-edge', 'state-of-the-art', 'empower', 'empowers', 'unlock', 'unlocks',
  'elevate', 'elevates', 'harness', 'journey', 'game-changer', 'effortless', 'effortlessly',
  'world-class', "in today's", "it's important to note", 'it is worth noting', "let's",
  'dive in', 'dive into', "whether you're", 'look no further', 'rest assured', 'supercharge',
  'streamline', 'streamlines', 'revolutionize', 'revolutionise', 'best-in-class', 'furthermore',
  'moreover', 'in conclusion', 'navigate the', 'landscape', 'tapestry', 'boasts',
]
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const bannedRe = new RegExp(`(?<![\\p{L}\\p{N}_-])(?:${banned.map(escape).join('|')})(?![\\p{L}\\p{N}_-])`, 'giu')
const dashRe = /[–—]/gu
const pictoRe = /\p{Extended_Pictographic}/gu

function walk(dir, out) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    const rel = relative(root, p)
    if (skip.some((s) => rel === s || rel.startsWith(s + sep) || rel.split(sep).includes('node_modules'))) continue
    const st = statSync(p)
    if (st.isDirectory()) walk(p, out)
    else if (exts.some((e) => name.endsWith(e))) out.push(p)
  }
  return out
}

const problems = []
for (const file of walk(root, [])) {
  const lines = readFileSync(file, 'utf8').split(/\r?\n/)
  lines.forEach((raw, i) => {
    const line = raw.replace(/’/g, "'")
    const hits = []
    for (const m of line.matchAll(dashRe)) hits.push(`dash U+${m[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`)
    for (const m of line.matchAll(pictoRe)) hits.push(`pictograph U+${m[0].codePointAt(0).toString(16).toUpperCase()}`)
    for (const m of line.matchAll(bannedRe)) hits.push(`banned phrase "${m[0]}"`)
    for (const h of hits) problems.push(`${relative(root, file)}:${i + 1}: ${h}`)
  })
}

if (problems.length) {
  console.error(`Style check failed (${problems.length} problem${problems.length === 1 ? '' : 's'}):`)
  for (const p of problems) console.error('  ' + p)
  process.exit(1)
}
console.log('Style check passed.')
