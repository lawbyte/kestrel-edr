import type { ActivityItem, TrayStatus } from "../protocol";

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

/** Everything the UI needs from the host (Tauri backend or the browser mock). */
export interface KestrelApi {
  readonly host: "tauri" | "mock";
  getStatus(): Promise<TrayStatus>;
  getActivity(limit?: number): Promise<ActivityItem[]>;
  quickCheck(): Promise<Ack>;
  requestReview(alertId: string, justification: string): Promise<Ack>;
  openLink(url: string): Promise<void>;
  getWindowMode(): Promise<WindowMode>;
  setWindowMode(mode: WindowMode): Promise<void>;
  hideWindow(): Promise<void>;
  onNotification(cb: (item: ActivityItem) => void): Promise<Unlisten>;
  onStatus(cb: (s: TrayStatus) => void): Promise<Unlisten>;
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
