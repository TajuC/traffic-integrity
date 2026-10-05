export const ATTACKER_CLASSES = [
  'legitimate',
  'obvious_bot',
  'stealth_automation',
  'scripted_http',
  'datacenter_browser',
  'residential_proxy',
  'repeated_click',
  'conversion_spam',
  'crawler',
  'ambiguous',
] as const;

export type AttackerClass = (typeof ATTACKER_CLASSES)[number];

export type Split = 'train' | 'validation' | 'test';

export interface LabeledSession {
  readonly id: string;
  readonly split: Split;
  readonly clazz: AttackerClass;
  readonly label: 0 | 1;
  readonly expectedFailure?: string;
}

export function isFraudClass(clazz: AttackerClass): boolean {
  return clazz !== 'legitimate' && clazz !== 'ambiguous' && clazz !== 'crawler';
}
