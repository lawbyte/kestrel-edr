import { describe, expect, it } from "vitest";
import { inlineText, parseInline, parseMarkdown, safeHref, type Block, type Inline } from "./markdown";

function links(blocks: Block[]): string[] {
  const out: string[] = [];
  const walk = (c: Inline[]) =>
    c.forEach((n) => {
      if (n.t === "link") out.push(n.href);
      if ("c" in n) walk(n.c);
    });
  blocks.forEach((b) => {
    if ("c" in b) walk(b.c);
    if ("items" in b) b.items.forEach(walk);
  });
  return out;
}
const text = (md: string) => JSON.stringify(parseMarkdown(md));

describe("safeHref", () => {
  it("allows https, http and mailto", () => {
    expect(safeHref("https://intranet.example/privacy")).toBe("https://intranet.example/privacy");
    expect(safeHref("http://intranet.example")).toBe("http://intranet.example");
    expect(safeHref("mailto:dpo@example.com")).toBe("mailto:dpo@example.com");
  });
  it.each([
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    " javascript:alert(1)",
    "java\tscript:alert(1)",
    "java\u0000script:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox",
    "file:///C:/Windows/System32/calc.exe",
    "ms-msdt:/id",
    "search-ms:query=x",
    "\\\\attacker\\share\\x.exe",
    "//evil.example",
    "https://",
    "mailto:",
    "https://a b",
  ])("rejects %s", (h) => expect(safeHref(h)).toBeNull());
});

describe("parseMarkdown", () => {
  it("parses headings, lists, emphasis, code and links", () => {
    const md = "## Monitoring notice\n\nWe use **Kestrel** to *detect* `stealers`.\n\n- one\n- two [policy](https://x.example/p)\n\n1. first\n2. second\n\n> quoted\n\n---";
    const b = parseMarkdown(md);
    expect(b.map((x) => x.t)).toEqual(["h", "p", "ul", "ol", "quote", "hr"]);
    expect(b[0]).toMatchObject({ t: "h", level: 2 });
    expect(links(b)).toEqual(["https://x.example/p"]);
    const p = b[1] as Extract<Block, { t: "p" }>;
    expect(p.c.map((n) => n.t)).toEqual(["text", "strong", "text", "em", "text", "code", "text"]);
  });

  it("never emits HTML: raw tags stay literal text", () => {
    const md = '<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>\n\n<a href="javascript:alert(1)">x</a>';
    const b = parseMarkdown(md);
    expect(b.every((x) => x.t === "p")).toBe(true);
    expect(inlineText((b[0] as { c: Inline[] }).c)).toBe("<script>alert(1)</script>");
    expect(links(b)).toEqual([]);
    // No node type exists that could carry raw HTML.
    expect(text(md)).not.toMatch(/"t":"(html|raw)"/);
  });

  it("drops unsafe link targets but keeps the label", () => {
    const b = parseMarkdown("Click [here](javascript:alert(1)) or [there](data:text/html;base64,PHNjcmlwdD4=) or [file](file:///c:/x.exe)");
    expect(links(b)).toEqual([]);
    expect(inlineText((b[0] as { c: Inline[] }).c)).toContain("Click here");
  });

  it("autolinks bare https URLs without trailing punctuation", () => {
    const b = parseMarkdown("Full policy: https://intranet.example/privacy/endpoint.");
    expect(links(b)).toEqual(["https://intranet.example/privacy/endpoint"]);
  });

  it("keeps snake_case words literal and supports escapes", () => {
    expect(inlineText(parseInline("file_name_here and \\*not em\\*"))).toBe("file_name_here and *not em*");
    expect(parseInline("file_name_here").every((n) => n.t === "text")).toBe(true);
  });

  it("bounds input size", () => {
    const huge = "a".repeat(100_000);
    const b = parseMarkdown(huge);
    expect(inlineText((b[0] as { c: Inline[] }).c).length).toBe(20_000);
  });

  it("handles CRLF and list continuation lines", () => {
    const b = parseMarkdown("- item one\r\n  continues here\r\n- item two");
    expect(b).toHaveLength(1);
    const ul = b[0] as Extract<Block, { t: "ul" }>;
    expect(inlineText(ul.items[0]!)).toBe("item one continues here");
  });
});
