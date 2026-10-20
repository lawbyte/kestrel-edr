const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
const dateFmt = new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short" });
const fullFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "full", timeStyle: "short" });

/** "Just now", "12 minutes ago", "Today at 9:41", "Yesterday at 16:05", "3 Oct at 10:12". */
export function relativeTime(ts: number, now = Date.now()): string {
  const diff = now - ts;
  if (diff < 0) return `Today at ${timeFmt.format(ts)}`;
  if (diff < MIN) return "Just now";
  if (diff < HOUR) {
    const m = Math.floor(diff / MIN);
    return m === 1 ? "1 minute ago" : `${m} minutes ago`;
  }
  const d = new Date(ts);
  const n = new Date(now);
  const startOfToday = new Date(n.getFullYear(), n.getMonth(), n.getDate()).getTime();
  if (ts >= startOfToday) {
    const h = Math.floor(diff / HOUR);
    return h < 6 ? (h === 1 ? "1 hour ago" : `${h} hours ago`) : `Today at ${timeFmt.format(d)}`;
  }
  if (ts >= startOfToday - DAY) return `Yesterday at ${timeFmt.format(d)}`;
  if (ts >= startOfToday - 6 * DAY) return `${d.toLocaleDateString(undefined, { weekday: "long" })} at ${timeFmt.format(d)}`;
  return `${dateFmt.format(d)} at ${timeFmt.format(d)}`;
}

/** Coarse version for status rows: "4 minutes ago", "2 days ago", "Never". */
export function ago(ts: number | null, now = Date.now()): string {
  if (ts === null) return "Never";
  const diff = Math.max(0, now - ts);
  if (diff < MIN) return "Just now";
  if (diff < HOUR) return plural(Math.floor(diff / MIN), "minute") + " ago";
  if (diff < DAY) return plural(Math.floor(diff / HOUR), "hour") + " ago";
  return plural(Math.floor(diff / DAY), "day") + " ago";
}

export function fullDate(ts: number): string {
  return fullFmt.format(ts);
}

function plural(n: number, unit: string): string {
  return `${n} ${unit}${n === 1 ? "" : "s"}`;
}

/** File name from a Windows or POSIX path. */
export function baseName(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}
