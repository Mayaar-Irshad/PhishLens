import { detectSignature } from './signatures';
import { AnalysisError } from './errors';
import { formatBytes } from './text';

/**
 * Validation that happens before any parsing. It rejects inputs that are
 * clearly not RFC 5322 messages with a specific, helpful error instead of
 * letting the MIME parser produce a meaningless result.
 */

export const ACCEPTED_EXTENSIONS: readonly string[] = ['eml', 'txt'];
export const ACCEPT_ATTRIBUTE = '.eml,.txt,message/rfc822,text/plain';

const HEADER_SCAN_BYTES = 1024 * 1024;
const MAX_HEADER_LINES = 20_000;
const HEADER_FIELD = /^[\x21-\x39\x3B-\x7E]+[ \t]*:/u;

const KNOWN_HEADERS: ReadonlySet<string> = new Set([
  'from',
  'to',
  'cc',
  'bcc',
  'subject',
  'date',
  'received',
  'message-id',
  'return-path',
  'reply-to',
  'sender',
  'mime-version',
  'content-type',
  'content-transfer-encoding',
  'authentication-results',
  'dkim-signature',
  'delivered-to',
  'received-spf',
  'in-reply-to',
  'references',
  'list-unsubscribe',
  'list-id',
  'thread-topic',
  'thread-index',
  'importance',
  'arc-seal',
  'arc-message-signature',
  'arc-authentication-results',
  'user-agent',
]);

const MSG_ADVICE =
  'Outlook .msg files use a proprietary binary format that PhishLens does not read. Save the message as .eml from a mail client that supports it, or paste its internet headers instead (Outlook desktop: open the message, then File > Properties > Internet headers).';

export function extensionOf(name: string): string | null {
  const dot = name.lastIndexOf('.');
  if (dot <= 0 || dot === name.length - 1) return null;
  return name.slice(dot + 1).toLowerCase();
}

/** Checks a file's name and size before it is read into memory. */
export function checkFileMetadata(name: string, size: number, maxBytes: number): void {
  const extension = extensionOf(name);
  if (extension === 'msg') {
    throw new AnalysisError('OUTLOOK_MSG', MSG_ADVICE);
  }
  if (!extension || !ACCEPTED_EXTENSIONS.includes(extension)) {
    throw new AnalysisError(
      'UNSUPPORTED_FILE_TYPE',
      'Choose a raw email file with the .eml extension (or a .txt file containing raw headers or a raw message).',
    );
  }
  checkSize(size, maxBytes);
}

export function checkSize(size: number, maxBytes: number): void {
  if (size > maxBytes) {
    throw new AnalysisError(
      'FILE_TOO_LARGE',
      `The message is ${formatBytes(size)}, which exceeds the ${formatBytes(maxBytes)} limit. Large messages are usually large because of attachments; you can paste just the headers instead.`,
    );
  }
}

export interface PreparedInput {
  /** The message bytes with any BOM, leading blank lines or mbox separator removed. */
  bytes: Uint8Array;
  headersOnly: boolean;
  malformedHeaderLines: number;
  /** Lines of non-header text skipped before the first header (e.g. a mail client's summary). */
  skippedLines: number;
}

const MAX_PREAMBLE_LINES = 400;

/** Optional blank lines and an mbox/emlx prefix line, then a header field. */
const STARTS_WITH_HEADER =
  /^(?:[ \t]*\r?\n){0,50}(?:From \S[^\r\n]{0,998}\r?\n|\d{1,12}[ \t]*\r?\n)?[\x21-\x39\x3B-\x7E]{1,200}[ \t]*:/u;

function headerName(line: string): string | null {
  return (
    HEADER_FIELD.exec(line)?.[0]
      .replace(/[ \t]*:$/u, '')
      .toLowerCase() ?? null
  );
}

function isKnownHeader(name: string): boolean {
  return KNOWN_HEADERS.has(name) || name.startsWith('x-');
}

/**
 * True when a clean header block starts at `start`: at least two header
 * fields (one of them a standard header) and nothing but fields and folded
 * continuations until the blank line that ends the headers.
 */
function isHeaderBlock(lines: string[], start: number): boolean {
  let fields = 0;
  let known = 0;
  for (let i = start; i < lines.length && i < start + MAX_HEADER_LINES; i += 1) {
    const line = lines[i] ?? '';
    if (line.trim() === '') break;
    if (/^[ \t]/u.test(line) && i > start) continue;
    const name = headerName(line);
    if (!name) return false;
    fields += 1;
    if (isKnownHeader(name)) known += 1;
  }
  return fields >= 2 && known >= 1;
}

/**
 * Finds where the headers start when text precedes them, for example when a
 * whole "Show original" page is copied rather than just the message source.
 */
function findHeaderStart(lines: string[]): number {
  for (let i = 1; i < lines.length && i < MAX_PREAMBLE_LINES; i += 1) {
    if (headerName(lines[i] ?? '') && isHeaderBlock(lines, i)) return i;
  }
  return -1;
}

function latin1(bytes: Uint8Array): string {
  return new TextDecoder('latin1').decode(bytes);
}

export function prepareInput(input: Uint8Array, maxBytes: number): PreparedInput {
  checkSize(input.byteLength, maxBytes);
  let bytes = input;
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) bytes = bytes.subarray(3);

  const head = bytes.subarray(0, HEADER_SCAN_BYTES);
  // Input that starts with a header line is text. Magic numbers or NUL bytes
  // further in belong to its body and must not cause a rejection, or a sender
  // could make a message unanalysable by planting them.
  if (!STARTS_WITH_HEADER.test(latin1(head.subarray(0, 4096)))) {
    const signature = detectSignature(head);
    if (signature === 'ole') {
      throw new AnalysisError('OUTLOOK_MSG', `This looks like an Outlook .msg file. ${MSG_ADVICE}`);
    }
    // ISO images are recognised at offset 32 KiB, which text can reach too;
    // a real disk image is caught by the NUL check below instead.
    if (signature && !['email', 'html', 'rtf', 'iso'].includes(signature)) {
      throw new AnalysisError(
        'BINARY_CONTENT',
        `This file appears to be a binary file (detected: ${signature}), not a raw email message. PhishLens analyses RFC 5322 email source such as .eml files.`,
      );
    }
    if (head.subarray(0, 65536).includes(0)) {
      throw new AnalysisError(
        'BINARY_CONTENT',
        'This file contains binary data, so it is not a raw email message. PhishLens analyses RFC 5322 email source such as .eml files.',
      );
    }
  }

  const text = latin1(head);
  if (!text.trim()) {
    throw new AnalysisError('EMPTY_INPUT', 'The file or pasted text is empty.');
  }

  // Skip leading blank lines, then an optional mbox "From " separator or an
  // Apple .emlx byte-count line. latin1 maps one byte to one character, so
  // character offsets are byte offsets.
  let offset = /^(?:[ \t]*\r?\n)*/u.exec(text)?.[0].length ?? 0;
  const firstLine = /^[^\r\n]*/u.exec(text.slice(offset))?.[0] ?? '';
  if (/^From \S/u.test(firstLine) || /^\d+\s*$/u.test(firstLine)) {
    offset += firstLine.length + (text.slice(offset + firstLine.length).startsWith('\r\n') ? 2 : 1);
  }
  let rest = text.slice(offset);
  let lines = rest.split(/\r?\n/u);
  let skippedLines = 0;
  if (!HEADER_FIELD.test(lines[0] ?? '')) {
    const start = findHeaderStart(lines);
    if (start === -1) {
      throw new AnalysisError(
        'NO_HEADERS',
        'The text does not contain an email header block (lines such as "Received:" or "From:"). Paste the raw message source (in most mail apps: "Show original" or "View source").',
      );
    }
    // Advance past the skipped lines; every split line ended with "\n" (or "\r\n").
    let consumed = 0;
    for (let line = 0; line < start; line += 1) consumed = rest.indexOf('\n', consumed) + 1;
    offset += consumed;
    rest = rest.slice(consumed);
    lines = lines.slice(start);
    skippedLines = start;
  }
  bytes = bytes.subarray(offset);

  let knownHeaders = 0;
  let malformed = 0;
  let headersOnly = true;
  for (let i = 0; i < lines.length && i < MAX_HEADER_LINES; i += 1) {
    const line = lines[i] ?? '';
    if (line.trim() === '') {
      headersOnly =
        lines
          .slice(i + 1)
          .join('')
          .trim() === '' && rest.length < HEADER_SCAN_BYTES;
      break;
    }
    if (/^[ \t]/u.test(line)) continue;
    const name = headerName(line);
    if (!name) {
      malformed += 1;
      continue;
    }
    if (isKnownHeader(name)) knownHeaders += 1;
  }

  if (knownHeaders === 0) {
    throw new AnalysisError(
      'NO_HEADERS',
      'No standard email headers (such as From, To, Subject, Date or Received) were found. Paste the raw message source, starting from its first header line.',
    );
  }
  return { bytes, headersOnly, malformedHeaderLines: malformed, skippedLines };
}
