import { Fragment, type ReactNode } from 'react'
import { cn } from '@/lib/utils'

/**
 * How `[text](url)` is rendered:
 * - `'none'`: never an anchor; the markdown is shown as literal text. Use for
 *   server-generated text that embeds endpoint-controlled values (incident
 *   storylines), where the server never produces links.
 * - `'external'` (default): only `https://` URLs become anchors (new tab,
 *   `rel="noreferrer noopener"`); anything else (`http:`, `mailto:`,
 *   `javascript:`…) is shown as literal text. For admin-written text.
 */
export type MarkdownLinks = 'none' | 'external'

/**
 * Minimal, XSS-safe markdown (headings, paragraphs, lists, > quotes, **bold**,
 * *em*, `code`, [links](https://…)) with CommonMark backslash escapes outside
 * code spans. Produces React nodes only.
 *
 * Contract with the server (V-M6): endpoint text outside code spans has
 * `` \ ` * _ [ ] < > # | `` backslash-escaped; endpoint values inside code
 * spans are wrapped in single backticks (inner backticks replaced by U+02CB)
 * and are literal (no escapes, so `C:\Users\x` keeps its backslashes).
 */
export function Markdown({ source, className, links = 'external' }: { source: string; className?: string; links?: MarkdownLinks }) {
  const blocks: ReactNode[] = []
  const lines = source.replace(/\r\n?/g, '\n').split('\n')
  const inl = (s: string) => inline(s, links)
  let i = 0
  let key = 0
  while (i < lines.length) {
    const line = lines[i]
    if (!line.trim()) {
      i++
      continue
    }
    const h = /^(#{1,3})\s+(.*)$/.exec(line)
    if (h) {
      const Tag = (['h1', 'h2', 'h3'] as const)[h[1].length - 1]
      blocks.push(<Tag key={key++}>{inl(h[2])}</Tag>)
      i++
      continue
    }
    if (/^>\s?/.test(line)) {
      const quote: string[] = []
      while (i < lines.length && /^>\s?/.test(lines[i])) quote.push(lines[i++].replace(/^>\s?/, ''))
      blocks.push(<blockquote key={key++}>{inl(quote.join(' '))}</blockquote>)
      continue
    }
    if (/^\s*([-*]|\d+\.)\s+/.test(line)) {
      const ordered = /^\s*\d+\./.test(line)
      const items: ReactNode[] = []
      while (i < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[i])) {
        items.push(<li key={items.length}>{inl(lines[i].replace(/^\s*([-*]|\d+\.)\s+/, ''))}</li>)
        i++
      }
      blocks.push(ordered ? <ol key={key++}>{items}</ol> : <ul key={key++}>{items}</ul>)
      continue
    }
    const para: string[] = []
    while (i < lines.length && lines[i].trim() && !/^(#{1,3})\s/.test(lines[i]) && !/^>\s?/.test(lines[i]) && !/^\s*([-*]|\d+\.)\s+/.test(lines[i])) para.push(lines[i++])
    blocks.push(<p key={key++}>{inl(para.join(' '))}</p>)
  }
  return <div className={cn('prose-k', className)}>{blocks}</div>
}

/** ASCII punctuation, the characters CommonMark allows to be backslash-escaped. */
const PUNCT = String.raw`!"#$%&'()*+,\-./:;<=>?@[\\\]^_\`{|}~`
const ESC_RE = new RegExp(String.raw`\\([${PUNCT}])`, 'g')

/** Resolve backslash escapes (`\*` → `*`, `\\` → `\`) in literal text. */
export function unescapeMarkdown(s: string): string {
  return s.replace(ESC_RE, '$1')
}

/** Only absolute `https:` URLs may become anchors. */
export function isSafeExternalUrl(url: string): boolean {
  try {
    return new URL(url).protocol === 'https:'
  } catch {
    return false
  }
}

/*
 * Inline tokens, tried left to right; at a given position the alternatives are
 * tried in order, so a backslash escape always wins over bold/em/link/code
 * starting at the same character (`\[x](https://…)` stays literal).
 *  1 escape        \<punct>
 *  2 code span     `…`             (content literal, no escapes)
 *  3 bold          **…**           (content may contain escapes)
 *  4 em            *…*
 *  5 link          [text](url)     (6 = text, 7 = url)
 */
const INLINE_RE = new RegExp(
  [
    String.raw`(\\[${PUNCT}])`,
    '(`[^`]+`)',
    String.raw`(\*\*(?:\\[${PUNCT}]|[^*\\]|\\(?![${PUNCT}]))+\*\*)`,
    String.raw`(\*(?:\\[${PUNCT}]|[^*\\]|\\(?![${PUNCT}]))+\*)`,
    String.raw`(\[((?:\\[${PUNCT}]|[^\]\\]|\\(?![${PUNCT}]))+)\]\(([^)\s]+)\))`,
  ].join('|'),
  'g',
)

function inline(s: string, links: MarkdownLinks): ReactNode {
  const out: ReactNode[] = []
  const re = new RegExp(INLINE_RE.source, 'g')
  let last = 0
  let m: RegExpExecArray | null
  let k = 0
  while ((m = re.exec(s))) {
    if (m.index > last) out.push(<Fragment key={k++}>{s.slice(last, m.index)}</Fragment>)
    const t = m[0]
    if (m[1]) out.push(<Fragment key={k++}>{t.slice(1)}</Fragment>)
    else if (m[2]) out.push(<code key={k++}>{t.slice(1, -1)}</code>)
    else if (m[3]) out.push(<strong key={k++}>{inline(t.slice(2, -2), links)}</strong>)
    else if (m[4]) out.push(<em key={k++}>{inline(t.slice(1, -1), links)}</em>)
    else if (m[5]) {
      const text = unescapeMarkdown(m[6])
      const url = m[7]
      if (links === 'external' && isSafeExternalUrl(url)) {
        out.push(
          <a key={k++} href={url} target="_blank" rel="noreferrer noopener">
            {text}
          </a>,
        )
      } else {
        // Shown exactly as written so nothing can pose as a clickable link.
        out.push(<Fragment key={k++}>{`[${text}](${url})`}</Fragment>)
      }
    }
    last = m.index + t.length
  }
  if (last < s.length) out.push(<Fragment key={k++}>{s.slice(last)}</Fragment>)
  return out
}
