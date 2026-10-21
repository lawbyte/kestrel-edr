// IT consent requests (remote desktop / file access): queue + prompt state.
//
// Deny is the safe default: when a request reaches `expires_at` without an
// answer it's dropped here and nothing is sent; the agent treats the missing
// answer as a deny. Requests are answered in arrival order.
import type { ConsentRequest } from "./protocol";

/** Allow can't be used until the prompt has been visible this long. The flyout
 *  takes focus when a request arrives, so a stray Enter typed into another app
 *  at that moment must not grant access. Deny/Escape work immediately. */
export const ARM_DELAY_MS = 1000;
/** Upper bound on queued requests (mirrors the Rust side). */
export const MAX_PENDING = 16;

export interface ConsentEntry {
  req: ConsentRequest;
  /** When this entry became the visible (first) one; gates Allow. */
  shownAt: number | null;
  sending: "allow" | "deny" | null;
  error: string | null;
}

export type ConsentResult = { kind: "allowed" | "denied" | "expired" | "error"; message: string; id: string };

export interface ConsentState {
  queue: ConsentEntry[];
  /** Outcome of the last request, shown briefly after the prompt closes. */
  result: ConsentResult | null;
}

export type ConsentAction =
  | { type: "received"; req: ConsentRequest; now: number }
  | { type: "tick"; now: number }
  | { type: "sending"; id: string; allow: boolean }
  | { type: "answered"; id: string; allow: boolean; ok: boolean; message: string; now: number }
  | { type: "failed"; id: string; message: string; drop: boolean; now: number }
  | { type: "dismiss_result" };

export const initialConsentState: ConsentState = { queue: [], result: null };

function showHead(queue: ConsentEntry[], now: number): ConsentEntry[] {
  const head = queue[0];
  if (!head || head.shownAt !== null) return queue;
  return [{ ...head, shownAt: now }, ...queue.slice(1)];
}

export function consentReducer(s: ConsentState, a: ConsentAction): ConsentState {
  switch (a.type) {
    case "received": {
      if (a.req.expires_at <= a.now) return s;
      const i = s.queue.findIndex((e) => e.req.request_id === a.req.request_id);
      if (i >= 0) {
        const queue = s.queue.slice();
        queue[i] = { ...queue[i]!, req: a.req };
        return { ...s, queue };
      }
      if (s.queue.length >= MAX_PENDING) return s;
      return { ...s, queue: showHead([...s.queue, { req: a.req, shownAt: null, sending: null, error: null }], a.now) };
    }
    case "tick": {
      // An answer already in flight is allowed to finish.
      const expired = s.queue.filter((e) => e.sending === null && e.req.expires_at <= a.now);
      if (expired.length === 0) return s;
      const queue = showHead(
        s.queue.filter((e) => !expired.includes(e)),
        a.now,
      );
      const last = expired[expired.length - 1]!;
      return {
        queue,
        result: {
          kind: "expired",
          id: last.req.request_id,
          message: `You didn't answer in time, so ${who(last.req)} from IT can't connect. They can ask again.`,
        },
      };
    }
    case "sending":
      return { ...s, queue: s.queue.map((e) => (e.req.request_id === a.id ? { ...e, sending: a.allow ? "allow" : "deny", error: null } : e)) };
    case "answered": {
      const entry = s.queue.find((e) => e.req.request_id === a.id);
      const queue = s.queue.filter((e) => e.req.request_id !== a.id);
      const fallback = a.allow ? `You allowed ${entry ? who(entry.req) : "IT"} to connect.` : "You said no. IT can't connect.";
      return {
        queue: showHead(queue, a.now),
        result: a.ok
          ? { kind: a.allow ? "allowed" : "denied", id: a.id, message: a.message || fallback }
          : { kind: "error", id: a.id, message: a.message || "Kestrel couldn't pass on your answer." },
      };
    }
    case "failed": {
      if (a.drop) {
        // The agent rejected it (e.g. already expired): it can't be answered again.
        return { queue: showHead(s.queue.filter((e) => e.req.request_id !== a.id), a.now), result: { kind: "error", id: a.id, message: a.message } };
      }
      return { ...s, queue: s.queue.map((e) => (e.req.request_id === a.id ? { ...e, sending: null, error: a.message } : e)) };
    }
    case "dismiss_result":
      return { ...s, result: null };
  }
}

export function who(req: Pick<ConsentRequest, "admin_name">): string {
  return req.admin_name.trim() || "Someone";
}

/** "Rina from IT wants to see and control your screen" etc. */
export function consentAsk(req: ConsentRequest): string {
  if (req.kind === "files") return `${who(req)} from IT wants to access files on this PC`;
  return req.view_only ? `${who(req)} from IT wants to see your screen (view only)` : `${who(req)} from IT wants to see and control your screen`;
}

export function secondsLeft(req: ConsentRequest, now: number): number {
  return Math.max(0, Math.ceil((req.expires_at - now) / 1000));
}

/** "1:05", "0:09". */
export function countdown(secs: number): string {
  const m = Math.floor(secs / 60);
  return `${m}:${String(secs % 60).padStart(2, "0")}`;
}

export function isArmed(e: ConsentEntry, now: number): boolean {
  return e.shownAt !== null && now - e.shownAt >= ARM_DELAY_MS;
}
