import { useState } from "react";
import type { ActivityItem } from "../protocol";
import { reviewCopy } from "../copy";
import { baseName, fullDate, relativeTime } from "../format";
import { IconCheck, IconChevron, IconClock, IconCross, SeverityMark } from "./Icons";

interface Props {
  items: ActivityItem[] | null;
  error: string | null;
  unavailable: boolean;
  onRequestReview: (item: ActivityItem) => void;
  onRetry: () => void;
}

export function ActivityTab({ items, error, unavailable, onRequestReview, onRetry }: Props) {
  if (unavailable) {
    return (
      <div className="empty">
        <h2>Activity isn't available</h2>
        <p>Kestrel service isn't running, so its history can't be shown. Contact IT.</p>
      </div>
    );
  }
  if (error) {
    return (
      <div className="empty">
        <h2>Couldn't load activity</h2>
        <p>{error}</p>
        <button className="btn" onClick={onRetry}>
          Try again
        </button>
      </div>
    );
  }
  if (items === null) {
    return (
      <div className="cards" aria-busy="true">
        {[0, 1, 2].map((i) => (
          <div key={i} className="card card--skeleton" />
        ))}
      </div>
    );
  }
  if (items.length === 0) {
    return (
      <div className="empty">
        <h2>Nothing has been blocked</h2>
        <p>When Kestrel stops an app on this PC, you'll see what happened here, in plain words.</p>
      </div>
    );
  }
  return (
    <ol className="cards" aria-label="Recent activity">
      {items.map((it) => (
        <Card key={it.id} item={it} onRequestReview={onRequestReview} />
      ))}
    </ol>
  );
}

function Card({ item, onRequestReview }: { item: ActivityItem; onRequestReview: (i: ActivityItem) => void }) {
  const [open, setOpen] = useState(false);
  const bodyId = `card-body-${item.id}`;
  const canReview = item.alert_id !== null && item.review === null;
  return (
    <li className={`card card--${item.severity}${open ? " card--open" : ""}`}>
      <button className="card__head" aria-expanded={open} aria-controls={bodyId} onClick={() => setOpen((o) => !o)}>
        <SeverityMark severity={item.severity} />
        <span className="card__title">
          <Title text={item.title} file={item.file} />
        </span>
        <span className="card__chev">
          <IconChevron />
        </span>
      </button>
      <div className="card__meta">
        <time dateTime={new Date(item.ts).toISOString()} title={fullDate(item.ts)}>
          {relativeTime(item.ts)}
        </time>
        <span className="card__action">{item.action_taken}</span>
      </div>
      <div id={bodyId} className="card__body" hidden={!open}>
        <p>{item.body}</p>
        {item.file && (
          <p className="card__file">
            <span>File</span>
            <code>{item.file}</code>
          </p>
        )}
      </div>
      {(item.review || canReview) && (
        <div className="card__foot">
          {item.review ? (
            <span className={`review review--${item.review}`} title={reviewCopy[item.review].detail}>
              {item.review === "approved" ? <IconCheck size={14} /> : item.review === "denied" ? <IconCross size={14} /> : <IconClock size={14} />}
              {reviewCopy[item.review].label}
            </span>
          ) : (
            <>
              <span className="card__hint">Needed this app for work?</span>
              <button className="btn btn--sm" onClick={() => onRequestReview(item)}>
                Request review
              </button>
            </>
          )}
        </div>
      )}
    </li>
  );
}

/** Emphasise the file name inside the agent's plain-language title, if present. */
function Title({ text, file }: { text: string; file: string | null }) {
  const name = file ? baseName(file) : null;
  const at = name ? text.indexOf(name) : -1;
  if (!name || at < 0) return <>{text}</>;
  return (
    <>
      {text.slice(0, at)}
      <em className="card__file-name">{name}</em>
      {text.slice(at + name.length)}
    </>
  );
}
