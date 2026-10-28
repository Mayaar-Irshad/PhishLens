import {
  ABSOLUTE_MAX_INPUT_BYTES,
  DEFAULT_LIMITS,
  MEGABYTE,
  type AnalysisLimits,
} from './core/limits';

/**
 * Build-time configuration. The input size limit can be changed with the
 * VITE_MAX_EMAIL_MB environment variable (for example `VITE_MAX_EMAIL_MB=25
 * npm run build`). Values are capped at ABSOLUTE_MAX_INPUT_BYTES.
 */
export function resolveMaxInputBytes(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === '') return DEFAULT_LIMITS.maxInputBytes;
  const megabytes = Number(raw);
  if (!Number.isFinite(megabytes) || megabytes <= 0) return DEFAULT_LIMITS.maxInputBytes;
  return Math.min(Math.round(megabytes * MEGABYTE), ABSOLUTE_MAX_INPUT_BYTES);
}

export const APP_LIMITS: AnalysisLimits = Object.freeze({
  ...DEFAULT_LIMITS,
  maxInputBytes: resolveMaxInputBytes(import.meta.env.VITE_MAX_EMAIL_MB),
});

export const ANALYSIS_TIMEOUT_MS = 30_000;

export const REPOSITORY_URL = 'https://github.com/Mayaar-Irshad/PhishLens';
