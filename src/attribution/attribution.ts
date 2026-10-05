export const CLICK_ID_TYPES = ['gclid', 'gbraid', 'wbraid'] as const;
export type ClickIdType = (typeof CLICK_ID_TYPES)[number];

export const UTM_FIELDS = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'] as const;
export type UtmField = (typeof UTM_FIELDS)[number];

export interface PaidAttribution {
  readonly clickIds: Readonly<Partial<Record<ClickIdType, string>>>;
  readonly primary: { readonly type: ClickIdType; readonly value: string } | undefined;
  readonly gadSource: string | undefined;
  readonly gadCampaignId: string | undefined;
  readonly utm: Readonly<Partial<Record<UtmField, string>>>;
}

export interface AttributionResult {
  readonly attribution: PaidAttribution | undefined;
  readonly malformed: readonly string[];
}

const CLICK_ID = /^[A-Za-z0-9._~-]{10,512}$/;
const GAD_SOURCE = /^[0-9]{1,4}$/;
const CAMPAIGN_ID = /^[0-9]{1,20}$/;
const CONTROL = /\p{Cc}/gu;
const MAX_UTM_LENGTH = 150;
const NONE: AttributionResult = Object.freeze({ attribution: undefined, malformed: Object.freeze([]) });

export function parseAttribution(search: URLSearchParams): AttributionResult {
  if (search.size === 0) return NONE;
  const malformed: string[] = [];

  const single = (name: string, pattern: RegExp): string | undefined => {
    const values = search.getAll(name);
    if (values.length === 0) return undefined;
    const distinct = new Set(values.map((v) => v.trim()));
    const [value] = distinct;
    if (distinct.size !== 1 || value === undefined || !pattern.test(value)) {
      malformed.push(name);
      return undefined;
    }
    return value;
  };

  const clickIds: Partial<Record<ClickIdType, string>> = {};
  for (const type of CLICK_ID_TYPES) {
    const value = single(type, CLICK_ID);
    if (value) clickIds[type] = value;
  }
  const gadSource = single('gad_source', GAD_SOURCE);
  const gadCampaignId = single('gad_campaignid', CAMPAIGN_ID);

  const primaryType = CLICK_ID_TYPES.find((type) => clickIds[type] !== undefined);
  const primary = primaryType ? { type: primaryType, value: clickIds[primaryType] as string } : undefined;
  if (!primary && !gadSource) return malformed.length > 0 ? { attribution: undefined, malformed } : NONE;

  const utm: Partial<Record<UtmField, string>> = {};
  for (const field of UTM_FIELDS) {
    const raw = search.get(field);
    if (raw === null) continue;
    const clean = raw.replace(CONTROL, ' ').replace(/\s+/g, ' ').trim().slice(0, MAX_UTM_LENGTH);
    if (clean) utm[field] = clean;
  }

  return { attribution: { clickIds, primary, gadSource, gadCampaignId, utm }, malformed };
}
