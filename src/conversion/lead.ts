import { z } from 'zod';
import { sha256Hex, type Keyring } from '../crypto/keyring.ts';

const blankToUndefined = (value: unknown): unknown => (typeof value === 'string' && value.trim() === '' ? undefined : value);

const extraSchema = z
  .record(z.string().regex(/^[a-z][a-z0-9_]{0,39}$/), z.string().max(1000))
  .refine((value) => Object.keys(value).length <= 20, { message: 'too many fields' });

export const leadSchema = z
  .object({
    formId: z.string().min(1).max(24),
    name: z.string().trim().min(1).max(120),
    email: z.preprocess(blankToUndefined, z.email().max(254).optional()),
    phone: z.preprocess(blankToUndefined, z.string().trim().regex(/^[+()0-9 .-]{6,32}$/).optional()),
    message: z.preprocess(blankToUndefined, z.string().trim().max(4000).optional()),
    extra: extraSchema.optional(),
    formToken: z.preprocess(blankToUndefined, z.string().max(400).optional()),
    turnstileToken: z.preprocess(blankToUndefined, z.string().max(2048).optional()),
    idempotencyKey: z.string().regex(/^[A-Za-z0-9-]{16,64}$/),
  })
  .refine((lead) => lead.email !== undefined || lead.phone !== undefined, { message: 'email or phone is required', path: ['email'] });

export type LeadSubmission = z.infer<typeof leadSchema>;

export interface NormalizedContact {
  readonly email: string | undefined;
  readonly phoneE164: string | undefined;
  readonly emailFingerprint: string | undefined;
  readonly phoneFingerprint: string | undefined;
  readonly messageFingerprint: string | undefined;
  readonly hashedEmail: string | undefined;
  readonly hashedPhone: string | undefined;
}

const MIN_FINGERPRINT_MESSAGE = 20;

export function normalizeContact(lead: LeadSubmission, keyring: Keyring, phoneCountryCode: string | undefined): NormalizedContact {
  const email = lead.email?.trim().toLowerCase();
  const phoneE164 = lead.phone ? toE164(lead.phone, phoneCountryCode) : undefined;
  const phoneDigits = lead.phone?.replace(/\D/g, '');
  const message = lead.message?.toLowerCase().replace(/\s+/g, ' ').trim();
  return {
    email,
    phoneE164,
    emailFingerprint: email ? keyring.digest('fingerprint', `email:${dedupeEmail(email)}`, 16) : undefined,
    phoneFingerprint: phoneDigits ? keyring.digest('fingerprint', `phone:${phoneE164 ?? phoneDigits}`, 16) : undefined,
    messageFingerprint:
      message && message.length >= MIN_FINGERPRINT_MESSAGE ? keyring.digest('fingerprint', `message:${message}`, 16) : undefined,
    hashedEmail: email ? sha256Hex(googleNormalizedEmail(email)) : undefined,
    hashedPhone: phoneE164 ? sha256Hex(phoneE164) : undefined,
  };
}

export function googleNormalizedEmail(email: string): string {
  const lowered = email.trim().toLowerCase();
  const at = lowered.lastIndexOf('@');
  if (at <= 0) return lowered;
  const domain = lowered.slice(at + 1);
  if (domain !== 'gmail.com' && domain !== 'googlemail.com') return lowered;
  const local = lowered.slice(0, at).split('+')[0]?.replaceAll('.', '') ?? '';
  return `${local}@${domain}`;
}

function dedupeEmail(email: string): string {
  const normalized = googleNormalizedEmail(email);
  const at = normalized.lastIndexOf('@');
  if (at <= 0) return normalized;
  return `${normalized.slice(0, at).split('+')[0] ?? ''}${normalized.slice(at)}`;
}

export function toE164(phone: string, countryCode: string | undefined): string | undefined {
  const trimmed = phone.trim();
  const digits = trimmed.replace(/\D/g, '');
  let international: string | undefined;
  if (trimmed.startsWith('+')) international = digits;
  else if (digits.startsWith('00')) international = digits.slice(2);
  else if (countryCode && digits.startsWith('0')) international = `${countryCode}${digits.slice(1)}`;
  if (!international || international.length < 8 || international.length > 15 || international.startsWith('0')) return undefined;
  return `+${international}`;
}
