import type { ItContact, RemoteSessionNotice } from "../protocol";
import { remoteSessionCopy } from "../copy";
import { RemoteIcon } from "./Icons";

interface Props {
  session: RemoteSessionNotice;
  contact: ItContact | null;
  onContactIT: () => void;
}

/**
 * Always-visible notice while an IT admin has a remote session on this PC.
 * There is no consent step (owner decision), so the employee must always be
 * told: the banner can't be dismissed and stays until the session ends.
 * The mode is conveyed by icon + text, never by colour alone.
 */
export function RemoteSessionBanner({ session, contact, onContactIT }: Props) {
  const copy = remoteSessionCopy(session, contact);
  return (
    <section className={`remote remote--${session.kind === "files" ? "files" : session.view_only ? "view" : "control"}`} role="status" aria-live="polite" aria-atomic="true" aria-label="IT is connected to this PC">
      <span className="remote__icon">
        <RemoteIcon session={session} size={20} />
      </span>
      <div className="remote__body">
        <p className="remote__title">{copy.headline}</p>
        <p className="remote__meta">
          <span className="remote__mode">{copy.mode}</span>
          <span aria-hidden="true"> · </span>
          <span>{copy.since}</span>
        </p>
        {copy.reason && <p className="remote__reason">{copy.reason}</p>}
        <p className="remote__help">
          {copy.help}{" "}
          <button className="remote__link" onClick={onContactIT}>
            Contact IT
          </button>
        </p>
      </div>
    </section>
  );
}
