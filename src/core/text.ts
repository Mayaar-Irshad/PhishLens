/**
 * Helpers for displaying untrusted strings. React already escapes markup, but
 * escaping does not stop *visual* spoofing: bidirectional overrides can make
 * `invoice[U+202E]fdp.exe` render as `invoiceexe.pdf`, and zero-width characters can
 * hide inside a domain name. These helpers make such characters visible.
 */

/** Bidirectional formatting characters (embeddings, overrides, isolates, marks). */
const BIDI_PATTERN = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/u;

/**
 * Zero-width and other invisible formatting characters. U+034F (combining
 * grapheme joiner) is matched outside the class: a combining mark inside a
 * character class is ambiguous.
 */
const INVISIBLE_PATTERN =
  /[\u00AD\u115F\u1160\u180E\u200B-\u200D\u2060-\u2064\u3164\uFEFF\uFFA0]|\u034F/u;

/** C0/C1 control characters except tab and line feed. */
// eslint-disable-next-line no-control-regex
const CONTROL_PATTERN = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/u;

const REVEAL_PATTERN = new RegExp(
  `${BIDI_PATTERN.source}|${INVISIBLE_PATTERN.source}|${CONTROL_PATTERN.source}`,
  'gu',
);

export function hasBidiControls(value: string): boolean {
  return BIDI_PATTERN.test(value);
}

const OVERRIDES = /[\u202A-\u202E\u2066-\u2069]/u;
// eslint-disable-next-line no-control-regex
const CONTROLS = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/u;
const ZERO_WIDTH = /[\u00AD\u115F\u1160\u180E\u200B\u2060-\u2064\u3164\uFEFF\uFFA0]|\u034F/u;
const ASCII_ALNUM = /[A-Za-z0-9]/u;

/**
 * True when a string contains characters used to disguise text rather than to
 * write a language: direction overrides and isolates, control characters, and
 * invisible characters placed inside Latin words. Direction marks (LRM, RLM),
 * zero-width joiners in emoji and ZWNJ in Persian or Indic text are normal
 * writing and do not count.
 */
export function hasSpoofingCharacters(value: string): boolean {
  if (OVERRIDES.test(value) || CONTROLS.test(value)) return true;
  const chars = [...value];
  return chars.some((char, i) => {
    const before = chars[i - 1] ?? '';
    const after = chars[i + 1] ?? '';
    if (char === '\u200C' || char === '\u200D') {
      return ASCII_ALNUM.test(before) && ASCII_ALNUM.test(after);
    }
    return ZERO_WIDTH.test(char) && (ASCII_ALNUM.test(before) || ASCII_ALNUM.test(after));
  });
}

export function hasInvisibleCharacters(value: string): boolean {
  return INVISIBLE_PATTERN.test(value) || CONTROL_PATTERN.test(value);
}

export function codePointLabel(char: string): string {
  const cp = char.codePointAt(0) ?? 0;
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

export type TextSegment = { kind: 'text'; value: string } | { kind: 'hidden'; value: string };

/**
 * Splits a string into plain text and hidden-character segments so the UI can
 * render hidden characters as visible, styled markers.
 */
export function segmentHiddenCharacters(value: string): TextSegment[] {
  const segments: TextSegment[] = [];
  let last = 0;
  for (const match of value.matchAll(REVEAL_PATTERN)) {
    const index = match.index;
    if (index > last) segments.push({ kind: 'text', value: value.slice(last, index) });
    segments.push({ kind: 'hidden', value: codePointLabel(match[0]) });
    last = index + match[0].length;
  }
  if (last < value.length) segments.push({ kind: 'text', value: value.slice(last) });
  return segments;
}

/** Replaces hidden characters with `[U+XXXX]` markers, for plain-text contexts such as reports. */
export function revealHiddenCharacters(value: string): string {
  return value.replace(REVEAL_PATTERN, (char) => `[${codePointLabel(char)}]`);
}

/**
 * Approximates how a right-to-left override (U+202E) reorders text on screen:
 * characters after it, up to a pop (U+202C), are shown reversed. Returns null
 * when the string has no override. Real rendering also depends on context.
 */
export function simulateRightToLeftOverride(value: string): string | null {
  const start = value.indexOf('\u202E');
  if (start === -1) return null;
  const end = value.indexOf('\u202C', start);
  const segment = value.slice(start + 1, end === -1 ? undefined : end);
  const after = end === -1 ? '' : value.slice(end + 1);
  const visible = (text: string) => text.replace(new RegExp(BIDI_PATTERN.source, 'gu'), '');
  return visible(value.slice(0, start)) + [...visible(segment)].reverse().join('') + visible(after);
}

export function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, Math.max(0, max - 1))}…`;
}

export function collapseWhitespace(value: string): string {
  return value.replace(/\s+/gu, ' ').trim();
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return 'unknown size';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit] ?? 'GB'}`;
}

export function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}
