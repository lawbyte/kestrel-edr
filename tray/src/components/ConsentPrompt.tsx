import { useEffect, useRef } from "react";
import { consentAsk, countdown, isArmed, secondsLeft, type ConsentEntry } from "../consent";
import { RemoteIcon } from "./Icons";

interface Props {
  entry: ConsentEntry;
  now: number;
  /** Requests waiting behind this one. */
  queued: number;
  onAnswer: (allow: boolean) => void;
}

/**
 * Allow / Deny prompt for an IT remote-access request.
 * - Deny is the safe default: Escape denies; if the countdown runs out the
 *   prompt closes without answering (the agent treats that as a deny).
 * - Enter allows, but only once the prompt has been visible for a moment
 *   (the window takes focus when a request arrives) and only when focus isn't
 *   on another button (Enter on Deny means Deny).
 */
export function ConsentPrompt({ entry, now, queued, onAnswer }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const { req } = entry;
  const armed = isArmed(entry, now);
  const busy = entry.sending !== null;
  const secs = secondsLeft(req, now);
  const id = req.request_id;

  useEffect(() => {
    const d = ref.current;
    if (d && !d.open) d.showModal?.();
    d?.focus();
  }, [id]);

  return (
    <dialog
      ref={ref}
      className="dialog consent"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby={`consent-title-${id}`}
      aria-describedby={`consent-desc-${id}`}
      tabIndex={-1}
      onCancel={(e) => {
        // Escape = Deny.
        e.preventDefault();
        if (!busy) onAnswer(false);
      }}
      onKeyDown={(e) => {
        if (e.key !== "Enter") return;
        const t = e.target as HTMLElement;
        if (t.tagName === "BUTTON" && t.dataset.answer !== "allow") return; // native activation (Deny)
        e.preventDefault();
        if (armed && !busy) onAnswer(true);
      }}
    >
      <div className="consent__head">
        <span className="consent__icon">
          <RemoteIcon session={req} size={22} />
        </span>
        <h2 id={`consent-title-${id}`}>{consentAsk(req)}</h2>
      </div>
      <div id={`consent-desc-${id}`} aria-live="polite">
        {req.reason.trim() ? <p className="consent__reason">Reason: {req.reason.trim()}</p> : <p className="consent__reason consent__reason--none">No reason was given.</p>}
        <p className="dialog__lead">
          {req.kind === "files"
            ? "If you allow it, they can open, copy and change files on this PC. You'll see a banner while they're connected."
            : req.view_only
              ? "If you allow it, they can see everything on your screen but can't use your mouse or keyboard. You'll see a banner while they're connected."
              : "If you allow it, they can see your screen and use your mouse and keyboard. You'll see a banner while they're connected."}{" "}
          Only allow it if you were expecting IT.
        </p>
      </div>
      <p className="consent__timer" role="timer" aria-label={`${secs} seconds left to answer`}>
        Closes in {countdown(secs)}. If you don't answer, IT can't connect.
      </p>
      {queued > 0 && <p className="consent__queued">{queued === 1 ? "1 more request is waiting." : `${queued} more requests are waiting.`}</p>}
      {entry.error && (
        <p className="dialog__error" role="alert">
          {entry.error}
        </p>
      )}
      <div className="dialog__actions">
        <button type="button" className="btn" data-answer="deny" onClick={() => onAnswer(false)} disabled={busy}>
          {entry.sending === "deny" ? "Sending…" : "Deny"}
        </button>
        <button type="button" className="btn btn--accent" data-answer="allow" onClick={() => armed && onAnswer(true)} disabled={busy || !armed}>
          {entry.sending === "allow" ? "Sending…" : "Allow"}
        </button>
      </div>
    </dialog>
  );
}

/** Short-lived outcome line after a prompt closes. */
export function ConsentResultLine({ message, kind, onDismiss }: { message: string; kind: string; onDismiss: () => void }) {
  return (
    <div className={`banner banner--${kind === "allowed" ? "low" : kind === "error" ? "critical" : "medium"} consent-result`} role="status">
      <span className="banner__text">{message}</span>
      <button className="btn btn--sm" onClick={onDismiss}>
        OK
      </button>
    </div>
  );
}
