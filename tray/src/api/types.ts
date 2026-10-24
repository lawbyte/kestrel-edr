import type { ActivityItem, ConsentRequest, PauseMode, PauseResult, RemoteSessionNotice, TrayStatus } from "../protocol";

export interface Ack {
  ok: boolean;
  message: string;
}

/** Error shape returned by the Rust commands (`ClientError`, serde adjacently tagged). */
export interface ApiError {
  kind: "unavailable" | "timeout" | "protocol" | "agent";
  message: string;
}

export type WindowMode = "flyout" | "window";
export type Tab = "status" | "activity" | "help";
export type Unlisten = () => void;

/** What a freshly built window should do first (asked for while it didn't exist). */
export interface UiIntent {
  tab: Tab | null;
  quick_check: boolean;
}

/** Validate the backend's `ui_ready` answer; anything odd means "nothing to do". */
export function parseUiIntent(v: unknown): UiIntent {
  const o = typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
  const tabs: Tab[] = ["status", "activity", "help"];
  const tab = tabs.find((t) => t === o.tab) ?? null;
  return { tab, quick_check: o.quick_check === true };
}

/** Everything the UI needs from the host (Tauri backend or the browser mock). */
export interface KestrelApi {
  readonly host: "tauri" | "mock";
  getStatus(): Promise<TrayStatus>;
  getActivity(limit?: number): Promise<ActivityItem[]>;
  quickCheck(): Promise<Ack>;
  requestReview(alertId: string, justification: string): Promise<Ack>;
  openLink(url: string): Promise<void>;
  /** Start kestrel-uninstall.exe from the install folder (it asks for elevation and the token itself; no agent involvement). */
  launchUninstaller(): Promise<void>;
  getWindowMode(): Promise<WindowMode>;
  setWindowMode(mode: WindowMode): Promise<void>;
  /** Close the window. The backend destroys it (no hidden WebView2) and rebuilds it on demand. */
  hideWindow(): Promise<void>;
  /**
   * The UI has mounted and its listeners are registered: the backend shows a
   * freshly built window and returns what was asked for while it didn't exist.
   */
  uiReady(): Promise<UiIntent>;
  onNotification(cb: (item: ActivityItem) => void): Promise<Unlisten>;
  onStatus(cb: (s: TrayStatus) => void): Promise<Unlisten>;
  /** Remote-session start/end pushes (UI state only; the toast comes from the paired notification). */
  onRemoteSession(cb: (n: RemoteSessionNotice) => void): Promise<Unlisten>;
  /** IT asks to connect (the backend has already brought the window forward and toasted). */
  onConsentRequest(cb: (r: ConsentRequest) => void): Promise<Unlisten>;
  /** Requests still waiting for an answer (for a UI that starts after the push). */
  getPendingConsents(): Promise<ConsentRequest[]>;
  /** Send Allow / Deny to the agent; resolves with its Ack. */
  respondConsent(requestId: string, allow: boolean): Promise<Ack>;
  /** Turn protection off with the uninstall token (`minutes: null` = until turned back on). Older agents reject with kind "agent". */
  pauseProtection(token: string, mode: PauseMode, minutes: number | null): Promise<PauseResult>;
  /** Turn protection back on (no token). */
  resumeProtection(): Promise<PauseResult>;
  onConnection(cb: (c: { connected: boolean; reason: string | null }) => void): Promise<Unlisten>;
  onNavigate(cb: (tab: Tab) => void): Promise<Unlisten>;
  onQuickCheck(cb: () => void): Promise<Unlisten>;
}

export function toApiError(e: unknown): ApiError {
  if (typeof e === "object" && e !== null && "kind" in e) {
    const o = e as { kind: unknown; message?: unknown };
    const kinds = ["unavailable", "timeout", "protocol", "agent"] as const;
    const kind = kinds.find((k) => k === o.kind) ?? "protocol";
    return { kind, message: typeof o.message === "string" ? o.message : "" };
  }
  return { kind: "protocol", message: e instanceof Error ? e.message : String(e) };
}
