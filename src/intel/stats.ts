export function median(values: readonly number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const high = sorted[mid] ?? 0;
  if (sorted.length % 2 === 1) return high;
  return ((sorted[mid - 1] ?? 0) + high) / 2;
}

export function mad(values: readonly number[]): number {
  if (values.length === 0) return 0;
  const center = median(values);
  return median(values.map((value) => Math.abs(value - center)));
}

export function percentile(values: readonly number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(p * sorted.length) - 1));
  return sorted[index] ?? 0;
}

export function robustZ(value: number, center: number, scale: number, epsilon = 1e-6): number {
  return (value - center) / (1.4826 * Math.max(scale, epsilon));
}

export function ewma(previous: number, observed: number, alpha: number): number {
  return alpha * observed + (1 - alpha) * previous;
}

export function hourOfDay(now: number, timeZone = 'UTC'): number {
  const formatted = new Intl.DateTimeFormat('en-US', { timeZone, hour: 'numeric', hourCycle: 'h23' }).format(new Date(now));
  const hour = Number(formatted);
  return Number.isFinite(hour) ? hour : new Date(now).getUTCHours();
}

export function dayOfWeek(now: number, timeZone = 'UTC'): number {
  const formatted = new Intl.DateTimeFormat('en-US', { timeZone, weekday: 'short' }).format(new Date(now));
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const index = days.indexOf(formatted);
  return index >= 0 ? index : new Date(now).getUTCDay();
}
