/**
 * Dates are shown in UTC with an explicit zone, so they can be correlated
 * with gateway and SIEM logs. The original header text is shown alongside.
 */
const DATE_FORMAT = new Intl.DateTimeFormat('en-GB', {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
  timeZone: 'UTC',
});

export function formatDate(iso: string | null): string | null {
  if (!iso) return null;
  const time = Date.parse(iso);
  return Number.isNaN(time) ? null : `${DATE_FORMAT.format(new Date(time))} UTC`;
}

export function formatDuration(ms: number): string {
  const abs = Math.abs(ms);
  if (abs < 60_000) return `${Math.round(abs / 1000)} s`;
  if (abs < 3_600_000) return `${Math.round(abs / 60_000)} min`;
  if (abs < 86_400_000) return `${(abs / 3_600_000).toFixed(1)} h`;
  return `${(abs / 86_400_000).toFixed(1)} days`;
}
