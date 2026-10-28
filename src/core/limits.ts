/**
 * Resource limits applied to every analysis. Inputs are hostile by assumption,
 * so every loop over attacker-controlled data is bounded by one of these.
 */
export interface AnalysisLimits {
  /** Maximum size of a raw message in bytes. */
  maxInputBytes: number;
  /** Maximum distinct URLs analysed per message. */
  maxUrls: number;
  /** Maximum attachments analysed per message. */
  maxAttachments: number;
  /** HTML bodies longer than this (in characters) are truncated before parsing. */
  maxHtmlChars: number;
  /** Plain-text bodies longer than this are truncated before URL scanning. */
  maxTextChars: number;
  /** Maximum evidence instances stored per finding. */
  maxInstancesPerFinding: number;
}

export const MEGABYTE = 1024 * 1024;

export const DEFAULT_LIMITS: Readonly<AnalysisLimits> = Object.freeze({
  maxInputBytes: 10 * MEGABYTE,
  maxUrls: 1000,
  maxAttachments: 200,
  maxHtmlChars: 4_000_000,
  maxTextChars: 4_000_000,
  maxInstancesPerFinding: 25,
});

/** Hard ceiling for a configured input limit, regardless of build configuration. */
export const ABSOLUTE_MAX_INPUT_BYTES = 50 * MEGABYTE;
