import { pino, type DestinationStream, type Logger } from 'pino';

export const REDACT_PATHS: readonly string[] = [
  'headers.cookie',
  'headers.authorization',
  'headers["x-edge-auth"]',
  'req.headers.cookie',
  'req.headers.authorization',
  'req.headers["x-edge-auth"]',
  'token',
  'formToken',
  'turnstileToken',
  'secret',
  'password',
  'email',
  'phone',
  'name',
  'message',
  '*.token',
  '*.formToken',
  '*.turnstileToken',
  '*.secret',
  '*.password',
  '*.email',
  '*.phone',
  '*.message',
];

export interface LoggerOptions {
  readonly level: string;
  readonly service?: string;
  readonly destination?: DestinationStream;
}

export function createLogger(options: LoggerOptions): Logger {
  return pino(
    {
      level: options.level,
      base: { service: options.service ?? 'traffic-integrity', pid: process.pid },
      timestamp: pino.stdTimeFunctions.isoTime,
      formatters: { level: (label) => ({ level: label }) },
      redact: { paths: [...REDACT_PATHS], censor: '[redacted]' },
    },
    options.destination,
  );
}
