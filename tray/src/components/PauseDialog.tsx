import { useEffect, useRef, useState } from "react";
import type { PauseMode, PauseOffer, PauseResult } from "../protocol";
import { toApiError } from "../api/types";
import { defaultMinutes, durationLabel, FULL_WARNING, lockedText, lockedUntil, MODE_COPY, PAUSE_INTRO, pauseErrorText, pauseTransportText } from "../pause";
import { IconWarning } from "./Icons";

interface Props {
  offer: PauseOffer;
  hostname: string;
  /** Sends the request; rejects with an ApiError-like value on transport trouble. */
  onSubmit: (token: string, mode: PauseMode, minutes: number | null) => Promise<PauseResult>;
  /** Protection is now off (or already was): the caller closes the dialog and shows the status. */
  onDone: (r: PauseResult) => void;
  onClose: () => void;
  /** Clock override for tests. */
  now?: number;
}

const UNTIL = "until";

/**
 * "Turn off protection" dialog (uninstall token required). Modal <dialog>:
 * focus stays inside while it is open, Escape closes it (unless a request is
 * in flight). The token field is cleared after every attempt and the token is
 * never kept anywhere else.
 */
export function PauseDialog({ offer, hostname, onSubmit, onDone, onClose, now: nowOverride }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const tokenRef = useRef<HTMLInputElement>(null);
  const [token, setToken] = useState("");
  const [mode, setMode] = useState<PauseMode>("detection_only");
  const initial = defaultMinutes(offer);
  const [duration, setDuration] = useState<string>(initial === null ? UNTIL : String(initial));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [last, setLast] = useState<PauseResult | null>(null);
  const [clock, setClock] = useState(() => Date.now());
  const now = nowOverride ?? clock;

  const locked = lockedUntil(offer, last, now);

  useEffect(() => {
    const d = ref.current;
    if (d && !d.open) d.showModal?.();
  }, []);

  // Live lockout countdown; when it ends the form unlocks by itself.
  useEffect(() => {
    if (locked === null || nowOverride !== undefined) return;
    const t = setInterval(() => setClock(Date.now()), 1000);
    return () => clearInterval(t);
  }, [locked, nowOverride]);

  const minutes = duration === UNTIL ? null : Number(duration);
  const canSubmit = !busy && locked === null && token.trim().length > 0;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    const t = token;
    setToken(""); // cleared after every attempt, whatever the outcome
    setBusy(true);
    setError(null);
    try {
      const r = await onSubmit(t, mode, minutes);
      setLast(r);
      setClock(Date.now());
      if (r.ok || r.error === "already_off") {
        onDone(r);
        return;
      }
      setError(pauseErrorText(r));
    } catch (err) {
      setError(pauseTransportText(toApiError(err)));
    }
    setBusy(false);
    tokenRef.current?.focus();
  };

  return (
    <dialog
      ref={ref}
      className="dialog pause-dialog"
      aria-labelledby="pause-title"
      aria-describedby="pause-intro"
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) onClose();
      }}
    >
      <form onSubmit={submit} autoComplete="off">
        <h2 id="pause-title">Turn off protection</h2>
        <p className="dialog__lead" id="pause-intro">
          {PAUSE_INTRO}
        </p>

        <label className="field">
          <span className="field__label">Uninstall token for {hostname ? <code>{hostname}</code> : "this PC"}</span>
          <input
            ref={tokenRef}
            className="field__input"
            type="password"
            name="kestrel-uninstall-token"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
            maxLength={512}
            autoFocus
            required
            aria-describedby={error || locked !== null ? "pause-error" : undefined}
          />
        </label>

        <fieldset className="field pause-modes">
          <legend className="field__label">What Kestrel does while it is off</legend>
          {(["detection_only", "full"] as const)
            .filter((m) => m === "detection_only" || offer.allow_full)
            .map((m) => (
              <label key={m} className="radio">
                <input type="radio" name="pause-mode" value={m} checked={mode === m} onChange={() => setMode(m)} />
                <span>
                  <span className="radio__label">{MODE_COPY[m].label}</span>
                  <span className="radio__detail">{MODE_COPY[m].detail}</span>
                </span>
              </label>
            ))}
        </fieldset>
        {mode === "full" && (
          <p className="pause-warning" role="note">
            <IconWarning />
            <span>
              <strong>Warning: </strong>
              {FULL_WARNING}
            </span>
          </p>
        )}

        <label className="field pause-duration">
          <span className="field__label">Turn back on</span>
          <select value={duration} onChange={(e) => setDuration(e.target.value)}>
            {offer.minutes.map((m) => (
              <option key={m} value={String(m)}>
                After {durationLabel(m)}
              </option>
            ))}
            {offer.allow_until_resumed && <option value={UNTIL}>Until I turn it back on</option>}
          </select>
        </label>

        {locked !== null ? (
          <p className="dialog__error" role="alert" id="pause-error">
            {lockedText(locked, now)}
          </p>
        ) : (
          error && (
            <p className="dialog__error" role="alert" id="pause-error">
              {error}
            </p>
          )
        )}

        <div className="dialog__actions">
          <button type="button" className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button type="submit" className="btn btn--accent" disabled={!canSubmit}>
            {busy ? "Checking…" : "Turn off protection"}
          </button>
        </div>
      </form>
    </dialog>
  );
}
