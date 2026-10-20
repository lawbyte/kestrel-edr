import type { ProtectionState, ReviewState, TrayStatus } from "./protocol";
import type { ShieldKind } from "./components/Icons";

// All user-facing state wording lives here so it stays consistent between the
// window, the tray tooltip (mirrored in src-tauri/src/lib.rs) and tests.

export interface StateCopy {
  /** Short label (tab badge, tray tooltip). */
  label: string;
  headline: string;
  detail: string;
}

export function stateCopy(kind: ShieldKind, s?: TrayStatus | null, recentBlocks = 0): StateCopy {
  switch (kind) {
    case "protected":
      return { label: "Protected", headline: "You're protected", detail: "Kestrel is running and has the latest settings from your IT team." };
    case "attention":
      return {
        label: "Protected",
        headline: recentBlocks === 1 ? "Kestrel stopped an app" : "Kestrel stopped some apps",
        detail:
          recentBlocks > 0
            ? `Your PC is still protected. ${recentBlocks === 1 ? "One thing was" : `${recentBlocks} things were`} blocked recently. Take a look in Activity.`
            : "Your PC is still protected. Something was blocked recently. Take a look in Activity.",
      };
    case "isolated":
      return {
        label: "Network limited",
        headline: "Your network access is limited",
        detail: `${s?.org_name || "Your IT team"} has temporarily cut this PC off from the network to keep your accounts safe. Only Kestrel can reach IT. Contact IT if you need to keep working.`,
      };
    case "degraded":
      return {
        label: "Partly working",
        headline: "Protection is partly working",
        detail: "Some of Kestrel's checks aren't running right now. Restarting your PC usually fixes this. If it doesn't, contact IT.",
      };
    case "offline":
      return {
        label: "Not connected",
        headline: "Protected, but not connected to IT",
        detail: "Kestrel is still protecting this PC but can't reach your company's servers. It will catch up when you're back online.",
      };
    case "unavailable":
      return { label: "Not running", headline: "Kestrel isn't running", detail: "Kestrel service isn't running, so this PC may not be protected. Contact IT so they can fix it." };
    case "loading":
      return { label: "Checking", headline: "Checking protection", detail: "Connecting to Kestrel on this PC." };
  }
}

export function isProtectionState(k: ShieldKind): k is ProtectionState {
  return k !== "unavailable" && k !== "loading";
}

export const reviewCopy: Record<ReviewState, { label: string; detail: string }> = {
  requested: { label: "Waiting for IT", detail: "You asked IT to review this. You'll get a notification when they decide." },
  approved: { label: "Allowed by IT", detail: "IT reviewed this and allowed it on your PC." },
  denied: { label: "Kept blocked by IT", detail: "IT reviewed this and kept it blocked. Contact IT if you have questions." },
};

export const COLLECTS = [
  "Names and fingerprints of apps that run, and which app started them",
  "When an app opens browser password, cookie or wallet files",
  "Network addresses that apps other than your browser connect to",
];

export const DOES_NOT_COLLECT = [
  "The contents of your documents, emails or chats",
  "Keystrokes or screenshots",
  "The websites you visit (not recorded by default)",
  "Your passwords. Kestrel only sees that a file was opened, not what's inside",
];
