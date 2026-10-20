import { Fragment, useMemo, type ReactNode } from "react";
import { parseMarkdown, type Block, type Inline } from "../markdown";

// Renders the sanitised AST from markdown.ts. No dangerouslySetInnerHTML:
// every string becomes a React text node, and links only carry hrefs that
// `safeHref` accepted. Clicks are routed through `onLink` (the backend opens
// them in the system browser, never inside the webview).

interface Props {
  source: string;
  onLink: (href: string) => void;
}

export function Markdown({ source, onLink }: Props) {
  const blocks = useMemo(() => parseMarkdown(source), [source]);
  return <div className="md">{blocks.map((b, i) => renderBlock(b, i, onLink))}</div>;
}

function renderBlock(b: Block, key: number, onLink: Props["onLink"]): ReactNode {
  const inl = (c: Inline[]) => renderInline(c, onLink);
  switch (b.t) {
    case "h": {
      // Notice headings sit below the section heading, so shift levels down.
      const Tag = (["h3", "h4", "h5"] as const)[b.level - 1]!;
      return <Tag key={key}>{inl(b.c)}</Tag>;
    }
    case "p":
      return <p key={key}>{inl(b.c)}</p>;
    case "ul":
      return (
        <ul key={key}>
          {b.items.map((it, i) => (
            <li key={i}>{inl(it)}</li>
          ))}
        </ul>
      );
    case "ol":
      return (
        <ol key={key} start={b.start}>
          {b.items.map((it, i) => (
            <li key={i}>{inl(it)}</li>
          ))}
        </ol>
      );
    case "quote":
      return <blockquote key={key}>{inl(b.c)}</blockquote>;
    case "hr":
      return <hr key={key} />;
  }
}

function renderInline(nodes: Inline[], onLink: Props["onLink"]): ReactNode {
  return nodes.map((n, i) => {
    switch (n.t) {
      case "text":
        return <Fragment key={i}>{n.v}</Fragment>;
      case "strong":
        return <strong key={i}>{renderInline(n.c, onLink)}</strong>;
      case "em":
        return <em key={i}>{renderInline(n.c, onLink)}</em>;
      case "code":
        return <code key={i}>{n.v}</code>;
      case "link":
        return (
          <a
            key={i}
            href={n.href}
            rel="noopener noreferrer"
            onClick={(e) => {
              e.preventDefault();
              onLink(n.href);
            }}
          >
            {renderInline(n.c, onLink)}
          </a>
        );
    }
  });
}
