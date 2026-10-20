import { useEffect, useRef, useState } from "react";
import type { TrayStatus } from "../protocol";
import type { Ack } from "../api/types";
import { stateCopy } from "../copy";
import { ago, fullDate } from "../format";
import { IconCheck, IconChevron, IconClock, IconCross, IconPc, IconPolicy, IconScan, IconSync, StateShield, type ShieldKind } from "./Icons";

export type CheckState = { phase: "idle" } | { phase: "running"; started: number } | { phase: "done"; ack: Ack } | { phase: "failed"; message: string };

interface Props {
  kind: ShieldKind;
  status: TrayStatus | null;
  recentBlocks: number;
  check: CheckState;
  onQuickCheck: () => void;
  onDismissCheck: () => void;
  onGo: (tab: "activity" | "help") => void;
}

export function StatusTab({ kind, status, recentBlocks, check, onQuickCheck, onDismissCheck, onGo }: Props) {
  const copy = stateCopy(kind, status, recentBlocks);
  const unavailable = kind === "unavailable";
  return (
    <div className="status">
      <section className={`hero hero--${kind}`} aria-live="polite">
        <StateShield kind={kind} size={76} />
        <h1 className="hero__headline">{copy.headline}</h1>
        <p className="hero__detail">{copy.detail}</p>
        {unavailable ? (
          <button className="btn btn--accent" onClick={() => onGo("help")}>
            Contact IT
          </button>
        ) : kind === "attention" ? (
          <button className="btn btn--accent" onClick={() => onGo("activity")}>
            See what was blocked
          </button>
        ) : kind === "isolated" ? (
          <button className="btn btn--accent" onClick={() => onGo("help")}>
            Contact IT
          </button>
        ) : null}
      </section>

      {!unavailable && kind !== "loading" && (
        <QuickCheck check={check} lastCheck={status?.last_check ?? null} onRun={onQuickCheck} onDismiss={onDismissCheck} disabled={!status} />
      )}

      {status && (
        <section className="group" aria-label="This PC">
          <p className="group__intro">Your company's IT team protects this PC with Kestrel.</p>
          <dl className="rows">
            <Row icon={<IconPc />} label="PC name" value={status.hostname} mono />
            <Row
              icon={<IconSync />}
              label="Connection to IT"
              value={status.server_connected ? "Connected" : "Not connected"}
              tone={status.server_connected ? undefined : "muted"}
            />
            <Row
              icon={<IconPolicy />}
              label="Settings last updated"
              value={ago(status.last_policy_sync)}
              title={status.last_policy_sync ? fullDate(status.last_policy_sync) : undefined}
              sub={status.policy_name}
            />
            <Row icon={<IconClock />} label="Kestrel version" value={status.agent_version} />
          </dl>
        </section>
      )}

      {unavailable && (
        <section className="group">
          <p className="group__intro">What you can do now</p>
          <ul className="steps">
            <li>Restart your PC. Kestrel starts by itself when Windows starts.</li>
            <li>If you still see this message, contact IT and mention the time it started.</li>
            <li>Until it's fixed, avoid opening downloads or attachments you weren't expecting.</li>
          </ul>
          <button className="linkrow" onClick={() => onGo("help")}>
            <span>IT contact details</span>
            <IconChevron />
          </button>
        </section>
      )}
    </div>
  );
}

function Row(p: { icon: React.ReactNode; label: string; value: string; sub?: string; mono?: boolean; title?: string | undefined; tone?: "muted" | undefined }) {
  return (
    <div className="row">
      <span className="row__icon">{p.icon}</span>
      <dt className="row__label">{p.label}</dt>
      <dd className={`row__value${p.mono ? " row__value--mono" : ""}${p.tone ? ` row__value--${p.tone}` : ""}`} title={p.title}>
        {p.value}
        {p.sub && <span className="row__sub">{p.sub}</span>}
      </dd>
    </div>
  );
}

function QuickCheck({ check, lastCheck, onRun, onDismiss, disabled }: { check: CheckState; lastCheck: number | null; onRun: () => void; onDismiss: () => void; disabled: boolean }) {
  const resultRef = useRef<HTMLDivElement>(null);
  const [, tick] = useState(0);
  useEffect(() => {
    if (check.phase !== "running") return;
    const t = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [check.phase]);
  useEffect(() => {
    if (check.phase === "done" || check.phase === "failed") resultRef.current?.focus();
  }, [check.phase]);

  return (
    <section className="check" aria-label="Quick check">
      <div className="check__bar">
        <span className="check__icon">
          <IconScan size={20} />
        </span>
        <div className="check__text">
          <span className="check__title">Quick check</span>
          <span className="check__sub">
            {check.phase === "running"
              ? "Looking at apps running from your user folders…"
              : `Looks at running apps for anything suspicious. Last run: ${ago(lastCheck).toLowerCase()}.`}
          </span>
        </div>
        <button className="btn" onClick={onRun} disabled={disabled || check.phase === "running"}>
          {check.phase === "running" ? "Checking…" : "Run check"}
        </button>
      </div>
      {check.phase === "running" && (
        <div className="progress" role="progressbar" aria-label="Quick check in progress" aria-busy="true">
          <span />
        </div>
      )}
      {(check.phase === "done" || check.phase === "failed") && (
        <div
          ref={resultRef}
          tabIndex={-1}
          className={`check__result ${check.phase === "done" && check.ack.ok ? "check__result--ok" : "check__result--bad"}`}
          role="status"
        >
          {check.phase === "done" && check.ack.ok ? <IconCheck /> : <IconCross />}
          <span>{check.phase === "done" ? check.ack.message || (check.ack.ok ? "Check finished. Nothing found." : "Check finished.") : check.message}</span>
          <button className="iconbtn iconbtn--sm" onClick={onDismiss} aria-label="Dismiss result">
            <IconCross size={12} />
          </button>
        </div>
      )}
    </section>
  );
}
