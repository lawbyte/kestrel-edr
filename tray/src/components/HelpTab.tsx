import { useState } from "react";
import type { ItContact, TrayStatus } from "../protocol";
import { COLLECTS, DOES_NOT_COLLECT } from "../copy";
import { Markdown } from "./Markdown";
import { IconCheck, IconCross, IconGlobe, IconMail, IconOpen, IconPhone } from "./Icons";

interface Props {
  status: TrayStatus | null;
  onLink: (href: string) => void;
  /** Start the uninstall tool; resolves with a message to show (or null). */
  onUninstall?: () => Promise<string | null>;
}

export function HelpTab({ status, onLink, onUninstall }: Props) {
  const [removeNote, setRemoveNote] = useState<string | null>(null);
  const [launching, setLaunching] = useState(false);
  const startUninstall = async () => {
    if (!onUninstall || launching) return;
    setLaunching(true);
    setRemoveNote(await onUninstall());
    setLaunching(false);
  };
  const contact = status?.it_contact;
  const org = status?.org_name || "your company";
  return (
    <div className="help">
      <section className="group" aria-labelledby="h-contact">
        <h2 id="h-contact" className="group__title">
          Contact IT
        </h2>
        {contact && hasContact(contact) ? (
          <ContactCard contact={contact} onLink={onLink} />
        ) : (
          <p className="muted">{status ? "Your IT team hasn't added contact details yet. Use your usual IT help channel." : "Contact details appear here when Kestrel is running. Use your usual IT help channel."}</p>
        )}
      </section>

      <section className="group" aria-labelledby="h-collect">
        <h2 id="h-collect" className="group__title">
          What Kestrel looks at
        </h2>
        <p className="group__intro">Kestrel watches for malware that steals passwords, logins and crypto wallets. To do that it records a small amount of activity on this PC.</p>
        <div className="ledger">
          <div className="ledger__col">
            <h3>It records</h3>
            <ul>
              {COLLECTS.map((t) => (
                <li key={t}>
                  <IconCheck size={14} />
                  <span>{t}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="ledger__col ledger__col--no">
            <h3>It doesn't record</h3>
            <ul>
              {DOES_NOT_COLLECT.map((t) => (
                <li key={t}>
                  <IconCross size={14} />
                  <span>{t}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      <section className="group" aria-labelledby="h-notice">
        <h2 id="h-notice" className="group__title">
          Privacy notice from {org}
        </h2>
        {status?.privacy_notice_md.trim() ? (
          <div className="notice">
            <Markdown source={status.privacy_notice_md} onLink={onLink} />
          </div>
        ) : (
          <p className="muted">{status ? `${org} hasn't published a notice in Kestrel. Ask IT or HR for the monitoring policy.` : "The notice appears here when Kestrel is running."}</p>
        )}
      </section>

      {onUninstall && (
        <section className="group" aria-labelledby="h-remove">
          <h2 id="h-remove" className="group__title">
            Remove Kestrel
          </h2>
          <p className="group__intro">For IT staff. Removing Kestrel needs this PC's uninstall token and administrator approval.</p>
          <button className="btn btn--sm" onClick={() => void startUninstall()} disabled={launching}>
            Uninstall Kestrel...
          </button>
          {removeNote && (
            <p className="muted remove-note" role="status">
              {removeNote}
            </p>
          )}
        </section>
      )}

      {status && (
        <p className="foot">
          Kestrel {status.agent_version}. This app can't change protection settings. Only your IT team can.
        </p>
      )}
    </div>
  );
}

function hasContact(c: ItContact) {
  return Boolean(c.name || c.email || c.phone || c.url);
}

function ContactCard({ contact, onLink }: { contact: ItContact; onLink: (href: string) => void }) {
  const tel = contact.phone.replace(/[^\d+]/g, "");
  return (
    <div className="contact">
      {contact.name && <p className="contact__name">{contact.name}</p>}
      <ul className="contact__list">
        {contact.email && (
          <li>
            <button className="contact__item" onClick={() => onLink(`mailto:${contact.email}`)}>
              <IconMail />
              <span>{contact.email}</span>
            </button>
          </li>
        )}
        {contact.phone && (
          <li>
            <button className="contact__item" onClick={() => tel && onLink(`tel:${tel}`)}>
              <IconPhone />
              <span>{contact.phone}</span>
            </button>
          </li>
        )}
        {contact.url && (
          <li>
            <button className="contact__item" onClick={() => onLink(contact.url)}>
              <IconGlobe />
              <span>{contact.url.replace(/^https?:\/\//, "").replace(/\/$/, "")}</span>
              <IconOpen />
            </button>
          </li>
        )}
      </ul>
    </div>
  );
}
