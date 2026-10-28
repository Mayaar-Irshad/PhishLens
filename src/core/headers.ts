import { addressParser, decodeWords, type Address, type Header } from 'postal-mime';
import { analyzeHost, domainOfAddress, toUnicodeHost } from './domain';
import { isPublicIp } from './ip';
import { collapseWhitespace } from './text';
import type {
  AddressInfo,
  HeaderAnalysis,
  HeaderEntry,
  HeaderField,
  OriginIp,
  ReceivedHop,
} from './types';

/** Header fields shown in the key-field table, in display order. */
export const KEY_HEADERS: readonly { key: string; label: string }[] = [
  { key: 'from', label: 'From' },
  { key: 'reply-to', label: 'Reply-To' },
  { key: 'return-path', label: 'Return-Path' },
  { key: 'sender', label: 'Sender' },
  { key: 'to', label: 'To' },
  { key: 'cc', label: 'Cc' },
  { key: 'subject', label: 'Subject' },
  { key: 'date', label: 'Date' },
  { key: 'message-id', label: 'Message-ID' },
  { key: 'received', label: 'Received' },
  { key: 'authentication-results', label: 'Authentication-Results' },
  { key: 'dkim-signature', label: 'DKIM-Signature' },
];

/** Headers that are not always present but help an investigation; shown only when present. */
export const NOTABLE_HEADERS: readonly { key: string; label: string }[] = [
  { key: 'x-mailer', label: 'X-Mailer' },
  { key: 'user-agent', label: 'User-Agent' },
  { key: 'x-originating-ip', label: 'X-Originating-IP' },
  { key: 'x-sender-ip', label: 'X-Sender-IP' },
  { key: 'x-php-originating-script', label: 'X-PHP-Originating-Script' },
  { key: 'organization', label: 'Organization' },
  { key: 'list-unsubscribe', label: 'List-Unsubscribe' },
  { key: 'list-id', label: 'List-Id' },
  { key: 'precedence', label: 'Precedence' },
  { key: 'in-reply-to', label: 'In-Reply-To' },
  { key: 'references', label: 'References' },
  { key: 'thread-topic', label: 'Thread-Topic' },
];

const MAX_HEADER_VALUE_CHARS = 20_000;

export function safeDecodeWords(value: string): string {
  try {
    return decodeWords(value);
  } catch {
    return value;
  }
}

/**
 * The literal domain when Unicode normalisation changed more than letter case:
 * full-width or compatibility characters (and ideographic full stops) look
 * like a familiar domain in mail clients but are mapped to ASCII by parsers.
 */
function disguisedDomain(address: string, canonical: string | null): string | null {
  const at = address.lastIndexOf('@');
  if (at < 0 || !canonical || canonical.startsWith('[')) return null;
  const literal = address
    .slice(at + 1)
    .trim()
    .toLowerCase()
    .replace(/\.$/u, '')
    .normalize('NFC');
  if (/^[ -~]*$/u.test(literal)) return null;
  const expected = (toUnicodeHost(canonical) ?? canonical).normalize('NFC');
  return literal === expected ? null : literal;
}

function toAddressInfo(name: string, address: string, group?: string): AddressInfo {
  const cleanAddress = address.trim();
  const domain = domainOfAddress(cleanAddress);
  const info = domain && !domain.startsWith('[') ? analyzeHost(domain) : null;
  return {
    domainWrittenAs: disguisedDomain(cleanAddress, domain),
    name: collapseWhitespace(name),
    address: cleanAddress,
    domain,
    domainUnicode: info?.hostUnicode ?? null,
    registrableDomain: info?.registrableDomain ?? (domain?.startsWith('[') ? domain : null),
    valid: domain !== null && /^[^\s@]+@[^\s@]+$/u.test(cleanAddress),
    ...(group === undefined ? {} : { group }),
  };
}

export function parseAddressList(value: string): AddressInfo[] {
  let parsed: Address[];
  try {
    parsed = addressParser(value.slice(0, MAX_HEADER_VALUE_CHARS));
  } catch {
    return [];
  }
  const out: AddressInfo[] = [];
  for (const entry of parsed) {
    if (entry.group) {
      for (const member of entry.group)
        out.push(toAddressInfo(member.name, member.address, entry.name));
    } else {
      out.push(toAddressInfo(entry.name, entry.address));
    }
  }
  return out;
}

/** Return-Path holds a single address in angle brackets, or "<>" for bounces. */
function parseReturnPath(value: string): AddressInfo[] {
  const inner = value.trim().replace(/^<|>$/gu, '').trim();
  if (!inner) return [];
  return [toAddressInfo('', inner)];
}

const IPV4_EXACT =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/u;
/** Bracketed or parenthesised tokens, where relays record peer addresses. */
const ENCLOSED = /[[(]([^[\]()]{1,100})[\])]/gu;

function validIpv6(value: string): boolean {
  if ((value.match(/:/gu) ?? []).length < 2 || !/^[0-9a-f:.]+$/iu.test(value)) return false;
  try {
    new URL(`http://[${value}]/`);
    return true;
  } catch {
    return false;
  }
}

/**
 * IP addresses recorded by a relay. Only bracketed or parenthesised tokens
 * (and "from <ip>") count: free text such as Exchange's "id 14.3.235.1" build
 * number must not be mistaken for an address.
 */
function receivedIps(clauses: string): string[] {
  const ips = new Set<string>();
  const consider = (token: string) => {
    const value = token.trim().replace(/^IPv6:/iu, '');
    if (IPV4_EXACT.test(value)) ips.add(value);
    else if (validIpv6(value)) ips.add(value.toLowerCase());
  };
  for (const match of clauses.matchAll(ENCLOSED)) {
    for (const token of (match[1] ?? '').split(/\s+/u)) consider(token);
  }
  const bare = /\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b/iu.exec(clauses)?.[1];
  if (bare) consider(bare);
  return [...ips];
}

function firstToken(source: string, keyword: string): string | null {
  const match = new RegExp(`(?:^|\\s)${keyword}\\s+([^\\s;()]+)`, 'iu').exec(source);
  return match?.[1] ?? null;
}

function stripComments(value: string): string {
  let depth = 0;
  let out = '';
  for (const char of value) {
    if (char === '(') depth += 1;
    else if (char === ')' && depth > 0) depth -= 1;
    else if (depth === 0) out += char;
  }
  return out;
}

function findOriginIp(all: HeaderEntry[], received: ReceivedHop[]): OriginIp | null {
  // Received headers are prepended, so the last one is the earliest hop.
  for (const hop of [...received].reverse()) {
    const ip = hop.ips.find(isPublicIp);
    if (ip) return { ip, source: 'received', headerIndex: hop.headerIndex };
  }
  for (const entry of all) {
    if (entry.key !== 'x-originating-ip' && entry.key !== 'x-sender-ip') continue;
    const ip = /[0-9a-f:.]{7,}/iu.exec(entry.value.replace(/[[\]]/gu, ''))?.[0];
    if (ip && isPublicIp(ip)) return { ip, source: 'x-originating-ip', headerIndex: entry.index };
  }
  return null;
}

/** RFC 5322 dates ("Tue, 20 Oct 2026 10:00:05 +0000") or ISO 8601; anything else is invalid. */
const DATE_SHAPE =
  /\b\d{1,2}\s+[a-z]{3,9}\s+\d{2,4}\s+\d{1,2}:\d{2}|\b\d{4}-\d{2}-\d{2}[t ]\d{1,2}:\d{2}/iu;

export function parseDateValue(raw: string): string | null {
  const cleaned = stripComments(raw).trim();
  // Date.parse accepts almost anything ("1" becomes 2001-01-01), so require a date shape first.
  if (!cleaned || !DATE_SHAPE.test(cleaned)) return null;
  const time = Date.parse(cleaned);
  return Number.isNaN(time) ? null : new Date(time).toISOString();
}

/**
 * Parses a Received header. The format is loosely specified and freely
 * written by every relay, so this extracts the common clauses and IP
 * addresses on a best-effort basis.
 */
export function parseReceived(value: string, headerIndex: number): ReceivedHop {
  const raw = value.slice(0, MAX_HEADER_VALUE_CHARS);
  const semicolon = raw.lastIndexOf(';');
  const clauses = semicolon >= 0 ? raw.slice(0, semicolon) : raw;
  const dateRaw = semicolon >= 0 ? raw.slice(semicolon + 1).trim() || null : null;
  const withoutComments = stripComments(clauses);

  return {
    headerIndex,
    raw,
    from: firstToken(withoutComments, 'from'),
    by: firstToken(withoutComments, 'by'),
    with: firstToken(withoutComments, 'with'),
    ips: receivedIps(clauses),
    dateRaw,
    dateIso: dateRaw ? parseDateValue(dateRaw) : null,
  };
}

export function toHeaderEntries(headers: Header[]): HeaderEntry[] {
  return headers.map((header, index) => ({
    index,
    name: header.originalKey,
    key: header.key,
    value: header.value,
  }));
}

export function analyzeHeaders(headers: Header[]): HeaderAnalysis {
  const all = toHeaderEntries(headers);
  const counts: Record<string, number> = {};
  for (const entry of all) counts[entry.key] = (counts[entry.key] ?? 0) + 1;

  const valuesOf = (key: string) =>
    all.filter((entry) => entry.key === key).map((entry) => entry.value);
  const toField = ({ key, label }: { key: string; label: string }): HeaderField => {
    const values = valuesOf(key);
    return { key, label, values, decoded: values.map((value) => safeDecodeWords(value)) };
  };
  const fields = KEY_HEADERS.map(toField);
  const notable = NOTABLE_HEADERS.map(toField).filter((field) => field.values.length > 0);
  const received = all
    .filter((entry) => entry.key === 'received')
    .map((entry) => parseReceived(entry.value, entry.index));

  const subjectRaw = valuesOf('subject')[0];
  const dateRaw = valuesOf('date')[0] ?? null;
  const dateIso = dateRaw ? parseDateValue(dateRaw) : null;
  const messageId = valuesOf('message-id')[0]?.trim() ?? null;

  return {
    fields,
    notable,
    originIp: findOriginIp(all, received),
    from: valuesOf('from').flatMap(parseAddressList),
    replyTo: valuesOf('reply-to').flatMap(parseAddressList),
    returnPath: valuesOf('return-path').flatMap(parseReturnPath),
    sender: valuesOf('sender').flatMap(parseAddressList),
    to: valuesOf('to').flatMap(parseAddressList),
    cc: valuesOf('cc').flatMap(parseAddressList),
    subject: subjectRaw === undefined ? null : collapseWhitespace(safeDecodeWords(subjectRaw)),
    date: { raw: dateRaw, iso: dateIso, valid: dateIso !== null },
    messageId: messageId || null,
    received,
    all,
    counts,
  };
}
