// A deliberately small Markdown parser for the org's privacy notice.
//
// Safety model: the notice comes from the server policy, so it is treated as
// untrusted. This parser never produces HTML strings. It builds a tiny AST of
// plain text and a fixed set of node types, which <Markdown> renders as React
// elements (React escapes text). Raw HTML in the source is shown literally as
// text, and only http(s) and mailto: links are kept. Any other scheme, such as
// javascript: or data:, is reduced to its label text.
//
// Supported: # / ## / ### headings, paragraphs, - * + and 1. lists, > quotes,
// **bold**, *italic* / _italic_, `code`, [label](url), bare https:// URLs, ---.

export type Inline =
  | { t: "text"; v: string }
  | { t: "strong"; c: Inline[] }
  | { t: "em"; c: Inline[] }
  | { t: "code"; v: string }
  | { t: "link"; href: string; c: Inline[] };

export type Block =
  | { t: "h"; level: 1 | 2 | 3; c: Inline[] }
  | { t: "p"; c: Inline[] }
  | { t: "ul"; items: Inline[][] }
  | { t: "ol"; items: Inline[][]; start: number }
  | { t: "quote"; c: Inline[] }
  | { t: "hr" };

const MAX_INPUT = 20_000;

/** Returns the URL if it is safe to open from the notice, else null. */
export function safeHref(raw: string): string | null {
  const href = raw.trim();
  // Reject control characters and whitespace tricks (e.g. "java\tscript:").
  if (/[\u0000-\u001f\u007f\s]/.test(href)) return null;
  if (/^https:\/\/[^/?#]+/i.test(href) || /^http:\/\/[^/?#]+/i.test(href)) return href;
  if (/^mailto:[^@\s]+@[^@\s]+$/i.test(href)) return href;
  return null;
}

export function parseInline(src: string): Inline[] {
  const out: Inline[] = [];
  let buf = "";
  const flush = () => {
    if (buf) out.push({ t: "text", v: buf });
    buf = "";
  };
  let i = 0;
  while (i < src.length) {
    const ch = src[i]!;
    const rest = src.slice(i);
    // Backslash escape of punctuation.
    if (ch === "\\" && i + 1 < src.length && /[\\`*_[\]()#+\-.!>]/.test(src[i + 1]!)) {
      buf += src[i + 1];
      i += 2;
      continue;
    }
    if (ch === "`") {
      const end = src.indexOf("`", i + 1);
      if (end > i) {
        flush();
        out.push({ t: "code", v: src.slice(i + 1, end) });
        i = end + 1;
        continue;
      }
    }
    if (rest.startsWith("**") || rest.startsWith("__")) {
      const mark = rest.slice(0, 2);
      const end = src.indexOf(mark, i + 2);
      if (end > i + 2) {
        flush();
        out.push({ t: "strong", c: parseInline(src.slice(i + 2, end)) });
        i = end + 2;
        continue;
      }
    }
    if ((ch === "*" || ch === "_") && src[i + 1] !== " " && src[i + 1] !== ch) {
      const end = src.indexOf(ch, i + 1);
      // `_` must not be inside a word (snake_case stays literal).
      const wordish = ch === "_" && ((i > 0 && /\w/.test(src[i - 1]!)) || (end > 0 && /\w/.test(src[end + 1] ?? "")));
      if (end > i + 1 && src[end - 1] !== " " && !wordish) {
        flush();
        out.push({ t: "em", c: parseInline(src.slice(i + 1, end)) });
        i = end + 1;
        continue;
      }
    }
    if (ch === "[") {
      const m = /^\[([^\]]+)\]\(([^)\s]*)(?:\s+"[^"]*")?\)/.exec(rest);
      if (m) {
        flush();
        const label = parseInline(m[1]!);
        const href = safeHref(m[2]!);
        if (href) out.push({ t: "link", href, c: label });
        else out.push(...label);
        i += m[0].length;
        continue;
      }
    }
    if (ch === "h" && (i === 0 || /[\s(]/.test(src[i - 1]!))) {
      const m = /^https?:\/\/[^\s<>()]+[^\s<>().,;:!?'"]/.exec(rest);
      if (m) {
        const href = safeHref(m[0]);
        if (href) {
          flush();
          out.push({ t: "link", href, c: [{ t: "text", v: m[0] }] });
          i += m[0].length;
          continue;
        }
      }
    }
    buf += ch;
    i++;
  }
  flush();
  return out;
}

export function parseMarkdown(input: string): Block[] {
  const src = input.length > MAX_INPUT ? input.slice(0, MAX_INPUT) : input;
  const lines = src.replace(/\r\n?/g, "\n").split("\n");
  const blocks: Block[] = [];
  let para: string[] = [];
  let list: { kind: "ul" | "ol"; items: string[]; start: number } | null = null;
  let quote: string[] = [];

  const endPara = () => {
    if (para.length) blocks.push({ t: "p", c: parseInline(para.join(" ")) });
    para = [];
  };
  const endList = () => {
    if (list) {
      const items = list.items.map(parseInline);
      blocks.push(list.kind === "ul" ? { t: "ul", items } : { t: "ol", items, start: list.start });
    }
    list = null;
  };
  const endQuote = () => {
    if (quote.length) blocks.push({ t: "quote", c: parseInline(quote.join(" ")) });
    quote = [];
  };
  const endAll = () => {
    endPara();
    endList();
    endQuote();
  };

  for (const raw of lines) {
    const line = raw.replace(/\s+$/, "");
    if (!line.trim()) {
      endAll();
      continue;
    }
    let m: RegExpExecArray | null;
    if ((m = /^\s{0,3}(#{1,6})\s+(.*?)\s*#*$/.exec(line))) {
      endAll();
      const level = Math.min(m[1]!.length, 3) as 1 | 2 | 3;
      blocks.push({ t: "h", level, c: parseInline(m[2]!) });
      continue;
    }
    if (/^\s{0,3}([-*_])(\s*\1){2,}\s*$/.test(line)) {
      endAll();
      blocks.push({ t: "hr" });
      continue;
    }
    if ((m = /^\s{0,3}>\s?(.*)$/.exec(line))) {
      endPara();
      endList();
      quote.push(m[1]!);
      continue;
    }
    if ((m = /^\s{0,3}[-*+]\s+(.*)$/.exec(line))) {
      endPara();
      endQuote();
      if (!list || list.kind !== "ul") {
        endList();
        list = { kind: "ul", items: [], start: 1 };
      }
      list.items.push(m[1]!);
      continue;
    }
    if ((m = /^\s{0,3}(\d{1,9})[.)]\s+(.*)$/.exec(line))) {
      endPara();
      endQuote();
      if (!list || list.kind !== "ol") {
        endList();
        list = { kind: "ol", items: [], start: Number(m[1]) };
      }
      list.items.push(m[2]!);
      continue;
    }
    if (list && /^\s{2,}\S/.test(line)) {
      // Continuation of the previous list item.
      list.items[list.items.length - 1] += " " + line.trim();
      continue;
    }
    endList();
    endQuote();
    para.push(line.trim());
  }
  endAll();
  return blocks;
}

/** Plain-text rendering (used for tests and toasts). */
export function inlineText(c: Inline[]): string {
  return c.map((n) => (n.t === "text" || n.t === "code" ? n.v : inlineText(n.c))).join("");
}
