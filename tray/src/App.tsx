import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import type { ActivityItem, PauseMode, TrayStatus } from "./protocol";
import { activeRemoteSession, upsertActivity } from "./protocol";
import type { KestrelApi, Tab, WindowMode } from "./api/types";
import { toApiError } from "./api/types";
import { StatusTab, type CheckState, type ResumeState } from "./components/StatusTab";
import { PauseDialog } from "./components/PauseDialog";
import { pauseErrorText, pauseTransportText } from "./pause";
import { ActivityTab } from "./components/ActivityTab";
import { HelpTab } from "./components/HelpTab";
import { ReviewDialog } from "./components/ReviewDialog";
import { RemoteSessionBanner } from "./components/RemoteSessionBanner";
import { ConsentPrompt, ConsentResultLine } from "./components/ConsentPrompt";
import { consentReducer, initialConsentState } from "./consent";
import { IconClose, IconDock, IconHelp, IconHome, IconList, IconPopOut, type ShieldKind } from "./components/Icons";
import { shieldKind, stateCopy } from "./copy";

const DAY = 24 * 60 * 60 * 1000;

interface Props {
  api: KestrelApi;
  initialTab?: Tab | null;
}

export function App({ api, initialTab }: Props) {
  const [tab, setTab] = useState<Tab>(initialTab ?? "status");
  const [status, setStatus] = useState<TrayStatus | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [items, setItems] = useState<ActivityItem[] | null>(null);
  const [activityError, setActivityError] = useState<string | null>(null);
  const [check, setCheck] = useState<CheckState>({ phase: "idle" });
  const [reviewing, setReviewing] = useState<ActivityItem | null>(null);
  const [banner, setBanner] = useState<ActivityItem | null>(null);
  const [mode, setMode] = useState<WindowMode>("flyout");
  const checkRunning = useRef(false);
  const [consent, dispatchConsent] = useReducer(consentReducer, initialConsentState);
  const [now, setNow] = useState(() => Date.now());
  const [pausing, setPausing] = useState(false);
  const [resume, setResume] = useState<ResumeState>({ busy: false, error: null });
  const [pauseNow, setPauseNow] = useState(() => Date.now());

  const loadStatus = useCallback(async () => {
    try {
      setStatus(await api.getStatus());
      setUnavailable(false);
    } catch (e) {
      const err = toApiError(e);
      if (err.kind === "unavailable" || err.kind === "timeout") {
        setUnavailable(true);
        setStatus(null);
      }
    }
  }, [api]);

  const loadActivity = useCallback(async () => {
    try {
      setItems(await api.getActivity(50));
      setActivityError(null);
    } catch (e) {
      const err = toApiError(e);
      if (err.kind === "unavailable") setUnavailable(true);
      else setActivityError("Kestrel didn't answer correctly. Try again in a moment.");
    }
  }, [api]);

  const runQuickCheck = useCallback(async () => {
    if (checkRunning.current) return;
    checkRunning.current = true;
    setTab("status");
    setCheck({ phase: "running", started: Date.now() });
    try {
      const ack = await api.quickCheck();
      setCheck({ phase: "done", ack });
      void loadStatus();
      void loadActivity();
    } catch (e) {
      const err = toApiError(e);
      setCheck({
        phase: "failed",
        message: err.kind === "unavailable" ? "Kestrel service isn't running, so the check couldn't start. Contact IT." : err.kind === "timeout" ? "The check took too long and was stopped. Try again later." : "The check couldn't finish. Try again later.",
      });
    } finally {
      checkRunning.current = false;
    }
  }, [api, loadStatus, loadActivity]);

  // Initial load + backend events.
  useEffect(() => {
    void loadStatus();
    void loadActivity();
    void api.getWindowMode().then(setMode).catch(() => {});
    const subs = [
      api.onNotification((item) => {
        setItems((prev) => upsertActivity(prev ?? [], item));
        if (item.severity !== "info") setBanner(item);
        void loadStatus();
      }),
      api.onStatus((s) => {
        setStatus(s);
        setUnavailable(false);
      }),
      // Remote-session pushes patch the status immediately; the next status
      // refresh (triggered by the paired notification) confirms it.
      api.onRemoteSession((n) => {
        setStatus((prev) => (prev ? { ...prev, remote_session: activeRemoteSession(n) } : prev));
      }),
      api.onConnection(({ connected }) => {
        if (connected) {
          void loadStatus();
          void loadActivity();
        } else {
          setUnavailable(true);
          setStatus(null);
        }
      }),
      api.onConsentRequest((req) => dispatchConsent({ type: "received", req, now: Date.now() })),
      api.onNavigate((t) => setTab(t)),
      api.onQuickCheck(() => void runQuickCheck()),
    ];
    // Requests that arrived before this UI was listening.
    void api
      .getPendingConsents()
      .then((reqs) => reqs.forEach((req) => dispatchConsent({ type: "received", req, now: Date.now() })))
      .catch(() => {});
    // Refresh when the flyout is shown again.
    const onVis = () => {
      if (document.visibilityState === "visible") {
        void loadStatus();
        void loadActivity();
      }
    };
    document.addEventListener("visibilitychange", onVis);
    window.addEventListener("focus", onVis);
    return () => {
      subs.forEach((p) => void p.then((un) => un()));
      document.removeEventListener("visibilitychange", onVis);
      window.removeEventListener("focus", onVis);
    };
  }, [api, loadStatus, loadActivity, runQuickCheck]);

  // Esc closes the flyout (like Windows flyouts) when no dialog is open.
  const consentOpen = consent.queue.length > 0;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !reviewing && !pausing && !consentOpen && mode === "flyout") void api.hideWindow();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [api, reviewing, pausing, consentOpen, mode]);

  // While protection is off: keep the remaining time current and pick up the
  // automatic turn-on as soon as it is due.
  const pauseUntil = status?.pause ? status.pause.until_ms : undefined;
  useEffect(() => {
    if (pauseUntil === undefined) return;
    setPauseNow(Date.now());
    const t = setInterval(() => {
      const n = Date.now();
      setPauseNow(n);
      if (pauseUntil !== null && n >= pauseUntil) void loadStatus();
    }, 5_000);
    return () => clearInterval(t);
  }, [pauseUntil, loadStatus]);

  // Countdown / expiry for pending consent requests (no answer = deny).
  useEffect(() => {
    if (!consentOpen) return;
    const t = setInterval(() => {
      const n = Date.now();
      setNow(n);
      dispatchConsent({ type: "tick", now: n });
    }, 250);
    return () => clearInterval(t);
  }, [consentOpen]);

  useEffect(() => {
    if (!consent.result) return;
    const t = setTimeout(() => dispatchConsent({ type: "dismiss_result" }), 10_000);
    return () => clearTimeout(t);
  }, [consent.result]);

  const answerConsent = async (id: string, allow: boolean) => {
    dispatchConsent({ type: "sending", id, allow });
    try {
      const ack = await api.respondConsent(id, allow);
      dispatchConsent({ type: "answered", id, allow, ok: ack.ok, message: ack.message, now: Date.now() });
      if (allow) void loadStatus();
    } catch (e) {
      const err = toApiError(e);
      dispatchConsent({
        type: "failed",
        id,
        now: Date.now(),
        // The agent refused it (expired/unknown): drop it. Transport trouble: keep it so they can retry.
        drop: err.kind === "agent",
        message:
          err.kind === "agent"
            ? "Kestrel couldn't pass on your answer because the request is no longer valid. IT can't connect unless they ask again."
            : err.kind === "unavailable"
              ? "Kestrel service isn't running, so your answer couldn't be sent. If you don't answer, IT can't connect."
              : "Your answer couldn't be sent. Try again.",
      });
    }
  };

  useEffect(() => {
    if (!banner) return;
    const t = setTimeout(() => setBanner(null), 8000);
    return () => clearTimeout(t);
  }, [banner]);

  const kind: ShieldKind = shieldKind(unavailable, status);
  const remote = unavailable ? null : activeRemoteSession(status?.remote_session);
  const recentBlocks = useMemo(
    () => (items ?? []).filter((i) => i.severity !== "info" && i.review !== "approved" && Date.now() - i.ts < DAY).length,
    [items],
  );
  const pendingCount = useMemo(() => (items ?? []).filter((i) => i.alert_id && i.review === null && i.severity !== "info" && Date.now() - i.ts < 7 * DAY).length, [items]);

  const submitReview = async (justification: string) => {
    if (!reviewing?.alert_id) return;
    try {
      const ack = await api.requestReview(reviewing.alert_id, justification);
      if (!ack.ok) throw new Error(ack.message || "IT couldn't receive the request. Try again later.");
      setItems((prev) => (prev ?? []).map((i) => (i.id === reviewing.id ? { ...i, review: "requested" } : i)));
      setReviewing(null);
    } catch (e) {
      if (e instanceof Error) throw e;
      const err = toApiError(e);
      throw new Error(err.kind === "unavailable" ? "Kestrel service isn't running, so the request couldn't be sent. Contact IT directly." : "The request couldn't be sent. Try again in a moment.");
    }
  };

  const submitPause = (token: string, pauseMode: PauseMode, minutes: number | null) => api.pauseProtection(token, pauseMode, minutes);

  const closePause = () => {
    setPausing(false);
    // Return focus to what opened the dialog (or the resume button that replaced it).
    setTimeout(() => (document.getElementById("resume-btn") ?? document.getElementById("turn-off-btn"))?.focus(), 0);
  };

  const resumeProtection = async () => {
    setResume({ busy: true, error: null });
    try {
      const r = await api.resumeProtection();
      // "Already on" needs no message: the refreshed status shows it.
      setResume({ busy: false, error: r.ok || r.error === "not_off" ? null : pauseErrorText(r) });
      if (r.ok || r.error === "not_off") setStatus((prev) => (prev ? { ...prev, pause: null } : prev));
    } catch (e) {
      setResume({ busy: false, error: pauseTransportText(toApiError(e), true) });
    }
    void loadStatus();
  };

  const toggleMode = async () => {
    const next: WindowMode = mode === "flyout" ? "window" : "flyout";
    await api.setWindowMode(next).catch(() => {});
    setMode(next);
  };

  const openLink = (href: string) => void api.openLink(href).catch(() => {});
  const label = stateCopy(kind, status).label;

  return (
    <div className={`app app--${mode}`} data-state={kind} data-remote={remote ? "on" : undefined}>
      <header className="titlebar" data-tauri-drag-region>
        <img className="titlebar__mark" src="/kestrel-mark.svg" alt="" width={18} height={18} data-tauri-drag-region />
        <span className="titlebar__name" data-tauri-drag-region>
          Kestrel
        </span>
        {status?.org_name && (
          <span className="titlebar__org" data-tauri-drag-region>
            {status.org_name}
          </span>
        )}
        <span className="titlebar__spacer" data-tauri-drag-region />
        <button className="iconbtn" onClick={toggleMode} title={mode === "flyout" ? "Keep open as a window" : "Dock to the taskbar"} aria-label={mode === "flyout" ? "Keep open as a window" : "Dock to the taskbar"}>
          {mode === "flyout" ? <IconPopOut /> : <IconDock />}
        </button>
        <button className="iconbtn" onClick={() => void api.hideWindow()} title="Close" aria-label="Close">
          <IconClose />
        </button>
      </header>

      {remote && <RemoteSessionBanner session={remote} contact={status?.it_contact ?? null} onContactIT={() => setTab("help")} />}

      <nav className="pivot" role="tablist" aria-label="Sections">
        <PivotTab id="status" tab={tab} setTab={setTab} icon={<IconHome />} label="Status" badge={<span className={`dot dot--${kind}`} title={label} />} />
        <PivotTab id="activity" tab={tab} setTab={setTab} icon={<IconList />} label="Activity" badge={pendingCount > 0 ? <span className="count">{pendingCount}</span> : null} />
        <PivotTab id="help" tab={tab} setTab={setTab} icon={<IconHelp />} label="Help & privacy" />
      </nav>

      {banner && (
        <div className={`banner banner--${banner.severity}`} role="alert">
          <span className="banner__text">{banner.title}</span>
          <button
            className="btn btn--sm"
            onClick={() => {
              setTab("activity");
              setBanner(null);
            }}
          >
            View
          </button>
        </div>
      )}

      <main className="content" role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} tabIndex={-1} key={tab}>
        {tab === "status" && (
          <StatusTab
            kind={kind}
            status={status}
            remote={remote}
            recentBlocks={recentBlocks}
            check={check}
            onQuickCheck={() => void runQuickCheck()}
            onDismissCheck={() => setCheck({ phase: "idle" })}
            onGo={setTab}
            onTurnOff={() => setPausing(true)}
            onResume={() => void resumeProtection()}
            resume={resume}
            now={pauseNow}
          />
        )}
        {tab === "activity" && <ActivityTab items={items} error={activityError} unavailable={unavailable} onRequestReview={setReviewing} onRetry={() => void loadActivity()} />}
        {tab === "help" && <HelpTab status={status} onLink={openLink} />}
      </main>

      {consent.result && <ConsentResultLine message={consent.result.message} kind={consent.result.kind} onDismiss={() => dispatchConsent({ type: "dismiss_result" })} />}

      {consent.queue[0] && (
        <ConsentPrompt entry={consent.queue[0]} now={now} queued={consent.queue.length - 1} onAnswer={(allow) => void answerConsent(consent.queue[0]!.req.request_id, allow)} />
      )}

      {pausing && !consentOpen && status?.local_pause && !status.pause && (
        <PauseDialog
          offer={status.local_pause}
          hostname={status.hostname}
          onSubmit={submitPause}
          onDone={(r) => {
            setStatus((prev) => (prev && r.state ? { ...prev, pause: r.state } : prev));
            setResume({ busy: false, error: null });
            closePause();
            void loadStatus();
          }}
          onClose={closePause}
        />
      )}

      {reviewing && !consentOpen && <ReviewDialog item={reviewing} hostname={status?.hostname ?? ""} onSubmit={submitReview} onClose={() => setReviewing(null)} />}
    </div>
  );
}

function PivotTab(p: { id: Tab; tab: Tab; setTab: (t: Tab) => void; icon: React.ReactNode; label: string; badge?: React.ReactNode }) {
  const selected = p.id === p.tab;
  return (
    <button
      role="tab"
      id={`tab-${p.id}`}
      aria-selected={selected}
      aria-controls={`panel-${p.id}`}
      tabIndex={selected ? 0 : -1}
      className="pivot__tab"
      onClick={() => p.setTab(p.id)}
      onKeyDown={(e) => {
        const order: Tab[] = ["status", "activity", "help"];
        const i = order.indexOf(p.id);
        const next = e.key === "ArrowRight" ? order[(i + 1) % 3] : e.key === "ArrowLeft" ? order[(i + 2) % 3] : undefined;
        if (next) {
          p.setTab(next);
          document.getElementById(`tab-${next}`)?.focus();
        }
      }}
    >
      {p.icon}
      <span>{p.label}</span>
      {p.badge}
    </button>
  );
}
