import { useEffect, useRef, useState } from "react";
import type { ActivityItem } from "../protocol";
import { relativeTime } from "../format";

interface Props {
  item: ActivityItem;
  hostname: string;
  onSubmit: (justification: string) => Promise<void>;
  onClose: () => void;
}

const MAX = 2000;

export function ReviewDialog({ item, hostname, onSubmit, onClose }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const d = ref.current;
    if (d && !d.open) d.showModal();
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!text.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onSubmit(text.trim());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setBusy(false);
    }
  };

  return (
    <dialog
      ref={ref}
      className="dialog"
      aria-labelledby="review-title"
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) onClose();
      }}
    >
      <form onSubmit={submit}>
        <h2 id="review-title">Ask IT to review this block</h2>
        <p className="dialog__lead">IT will look at what happened and decide whether to allow it. Until then it stays blocked.</p>
        <dl className="dialog__facts">
          <dt>What happened</dt>
          <dd>{item.title}</dd>
          <dt>When</dt>
          <dd>{relativeTime(item.ts)}</dd>
          {item.file && (
            <>
              <dt>File</dt>
              <dd>
                <code>{item.file}</code>
              </dd>
            </>
          )}
          <dt>PC name</dt>
          <dd>
            <code>{hostname}</code>
          </dd>
        </dl>
        <label className="field">
          <span className="field__label">Why do you need it?</span>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value.slice(0, MAX))}
            rows={4}
            required
            autoFocus
            placeholder="For example: this is the installer for the accounting software my team uses. I downloaded it from the vendor's website."
          />
          <span className="field__hint">
            {text.length > MAX - 200 ? `${MAX - text.length} characters left` : "Where it came from and what you use it for helps IT decide faster."}
          </span>
        </label>
        {error && (
          <p className="dialog__error" role="alert">
            {error}
          </p>
        )}
        <div className="dialog__actions">
          <button type="button" className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button type="submit" className="btn btn--accent" disabled={!text.trim() || busy}>
            {busy ? "Sending…" : "Send to IT"}
          </button>
        </div>
      </form>
    </dialog>
  );
}
