import type { ExclusionCandidate, ExportRow } from './repository.ts';

export function googleAdsCsv(rows: readonly ExportRow[], timeZone: string): { csv: string; exported: string[] } {
  const lines = [
    `Parameters:TimeZone=${timeZone}`,
    'Google Click ID,Conversion Name,Conversion Time,Conversion Value,Conversion Currency,Order ID',
  ];
  const exported: string[] = [];
  for (const row of rows) {
    if (!row.gclid) continue;
    lines.push([row.gclid, row.conversion_action, localTime(row.created_at, timeZone), row.value ?? '', row.currency, row.id].map(cell).join(','));
    exported.push(row.id);
  }
  return { csv: `${lines.join('\r\n')}\r\n`, exported };
}

export interface ApiConversion {
  readonly orderId: string;
  readonly conversionAction: string;
  readonly conversionDateTime: string;
  readonly conversionValue: number | null;
  readonly currencyCode: string;
  readonly gclid: string | null;
  readonly gbraid: string | null;
  readonly wbraid: string | null;
  readonly gadSource: string | null;
  readonly gadCampaignId: string | null;
  readonly hashedEmail: string | null;
  readonly hashedPhoneNumber: string | null;
}

export function apiConversions(rows: readonly ExportRow[], timeZone: string): ApiConversion[] {
  return rows.map((row) => ({
    orderId: row.id,
    conversionAction: row.conversion_action,
    conversionDateTime: `${localTime(row.created_at, timeZone)}${offset(row.created_at, timeZone)}`,
    conversionValue: row.value === null ? null : Number(row.value),
    currencyCode: row.currency,
    gclid: row.gclid ?? null,
    gbraid: row.gclid ? null : (row.gbraid ?? null),
    wbraid: row.gclid || row.gbraid ? null : (row.wbraid ?? null),
    gadSource: row.gadSource ?? null,
    gadCampaignId: row.gadCampaignId ?? null,
    hashedEmail: row.hashed_email,
    hashedPhoneNumber: row.hashed_phone,
  }));
}

export function googleAdsExclusion(candidate: ExclusionCandidate): string {
  const ipv4Block = /^(\d{1,3}\.\d{1,3}\.\d{1,3})\.0\/24$/.exec(candidate.target);
  return ipv4Block ? `${ipv4Block[1]}.*` : candidate.target;
}

function localTime(date: Date, timeZone: string): string {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat('en-US', {
      timeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23',
    })
      .formatToParts(date)
      .map((part) => [part.type, part.value]),
  );
  return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`;
}

function offset(date: Date, timeZone: string): string {
  const name = new Intl.DateTimeFormat('en-US', { timeZone, timeZoneName: 'longOffset' }).formatToParts(date).find((part) => part.type === 'timeZoneName')?.value ?? 'GMT';
  const match = /GMT([+-]\d{2}):?(\d{2})?/.exec(name);
  return match ? `${match[1]}:${match[2] ?? '00'}` : '+00:00';
}

function cell(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
}
