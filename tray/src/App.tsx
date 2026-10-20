import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ActivityItem, TrayStatus } from "./protocol";
import { upsertActivity } from "./protocol";
import type { KestrelApi, Tab, WindowMode } from "./api/types";
import { toApiError } from "./api/types";
import { StatusTab, type CheckState } from "./components/StatusTab";
import { ActivityTab } from "./components/ActivityTab";
import { HelpTab } from "./components/HelpTab";
import { ReviewDialog } from "./components/ReviewDialog";
import { IconClose, IconDock, IconHelp, IconHome, IconList, IconPopOut, type ShieldKind } from "./components/Icons";
import { stateCopy } from "./copy";

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
      api.onConnection(({ connected }) => {
        if (connected) {
          void loadStatus();
          void loadActivity();
        } else {
          setUnavailable(true);
          setStatus(null);
        }
      }),
      api.onNavigate((t) => setTab(t)),
      api.onQuickCheck(() => void runQuickCheck()),
    ];
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
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !reviewing && mode === "flyout") void api.hideWindow();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [api, reviewing, mode]);

  useEffect(() => {
    if (!banner) return;
    const t = setTimeout(() => setBanner(null), 8000);
    return () => clearTimeout(t);
  }, [banner]);

  const kind: ShieldKind = unavailable ? "unavailable" : status ? status.state : "loading";
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

  const toggleMode = async () => {
    const next: WindowMode = mode === "flyout" ? "window" : "flyout";
    await api.setWindowMode(next).catch(() => {});
    setMode(next);
  };

  const openLink = (href: string) => void api.openLink(href).catch(() => {});
  const label = stateCopy(kind, status).label;

  return (
    <div className={`app app--${mode}`} data-state={kind}>
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
            recentBlocks={recentBlocks}
            check={check}
            onQuickCheck={() => void runQuickCheck()}
            onDismissCheck={() => setCheck({ phase: "idle" })}
            onGo={setTab}
          />
        )}
        {tab === "activity" && <ActivityTab items={items} error={activityError} unavailable={unavailable} onRequestReview={setReviewing} onRetry={() => void loadActivity()} />}
        {tab === "help" && <HelpTab status={status} onLink={openLink} />}
      </main>

      {reviewing && <ReviewDialog item={reviewing} hostname={status?.hostname ?? ""} onSubmit={submitReview} onClose={() => setReviewing(null)} />}
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
