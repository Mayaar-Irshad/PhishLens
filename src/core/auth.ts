import { analyzeHost, normalizeDomain } from './domain';
import type {
  AddressInfo,
  AuthMethodResult,
  AuthProperty,
  AuthResultsHeader,
  AuthStatus,
  AuthenticationAnalysis,
  DkimSignatureInfo,
  HeaderEntry,
  ReceivedSpf,
  ReportedMethodSummary,
} from './types';

/**
 * Parsers for authentication headers. These only *read* what the message
 * claims. Nothing here verifies SPF, DKIM or DMARC: that requires DNS lookups
 * and the original SMTP transaction, which a browser-only tool does not have.
 */

const MAX_VALUE_CHARS = 20_000;
const MAX_RESULTS_PER_HEADER = 50;

export function statusOf(result: string): AuthStatus {
  switch (result.toLowerCase()) {
    case 'pass':
      return 'pass';
    // Microsoft: no DMARC record exists, although one would have passed.
    case 'bestguesspass':
      return 'none';
    case 'fail':
    case 'hardfail':
      return 'fail';
    case 'softfail':
      return 'softfail';
    case 'neutral':
    case 'policy':
      return 'neutral';
    case 'none':
      return 'none';
    case 'temperror':
    case 'permerror':
      return 'error';
    default:
      return 'other';
  }
}

interface Tokenized {
  text: string;
  comments: string[];
}

/** Removes RFC 5322 comments (nested parentheses), honouring quoted strings, and returns them separately. */
export function extractComments(value: string): Tokenized {
  let text = '';
  let comment = '';
  const comments: string[] = [];
  let depth = 0;
  let inQuote = false;
  let escaped = false;
  for (const char of value) {
    if (escaped) {
      if (depth > 0) comment += char;
      else text += char;
      escaped = false;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      if (depth === 0) text += char;
      continue;
    }
    if (depth === 0 && char === '"') {
      inQuote = !inQuote;
      text += char;
      continue;
    }
    if (!inQuote && char === '(') {
      if (depth > 0) comment += char;
      depth += 1;
      continue;
    }
    if (!inQuote && char === ')' && depth > 0) {
      depth -= 1;
      if (depth === 0) {
        if (comment.trim()) comments.push(comment.trim());
        comment = '';
        text += ' ';
      } else {
        comment += char;
      }
      continue;
    }
    if (depth > 0) comment += char;
    else text += char;
  }
  return { text, comments };
}

/**
 * Splits on a delimiter outside double quotes and outside (possibly nested)
 * comments, so "dkim=pass (2048-bit key; unprotected) header.d=x" stays whole.
 */
function splitOutsideQuotes(value: string, delimiter: string): string[] {
  const parts: string[] = [];
  let current = '';
  let inQuote = false;
  let depth = 0;
  let escaped = false;
  for (const char of value) {
    if (escaped) {
      escaped = false;
    } else if (char === '\\') {
      escaped = true;
    } else if (char === '"' && depth === 0) {
      inQuote = !inQuote;
    } else if (!inQuote && char === '(') {
      depth += 1;
    } else if (!inQuote && char === ')' && depth > 0) {
      depth -= 1;
    } else if (char === delimiter && !inQuote && depth === 0) {
      parts.push(current);
      current = '';
      continue;
    }
    current += char;
  }
  parts.push(current);
  return parts;
}

function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/\\(.)/gu, '$1');
  }
  return trimmed;
}

/**
 * Splits "a=b c.d = e" into key/value pairs, tolerating spaces around "=".
 * Whitespace is collapsed first so the normalisation cannot backtrack.
 */
function keyValuePairs(value: string): AuthProperty[] {
  const normalized = value.replace(/\s+/gu, ' ').replace(/ ?= ?/gu, '=');
  return splitOutsideQuotes(normalized, ' ')
    .map((token) => token.trim())
    .filter(Boolean)
    .map((token) => {
      const eq = token.indexOf('=');
      if (eq <= 0) return { key: token.toLowerCase(), value: '' };
      return { key: token.slice(0, eq).toLowerCase(), value: unquote(token.slice(eq + 1)) };
    });
}

function parseResinfo(segment: string, comments: string[]): AuthMethodResult | null {
  const pairs = keyValuePairs(segment);
  const first = pairs[0];
  if (!first?.value) return null;
  const method = first.key.split('/')[0] ?? first.key;
  const reasonPair = pairs.find((pair) => pair.key === 'reason');
  return {
    method,
    result: first.value.toLowerCase(),
    status: statusOf(first.value),
    reason: reasonPair?.value ?? null,
    properties: pairs.slice(1).filter((pair) => pair.key !== 'reason'),
    comments,
  };
}

const METHOD_START = /^\s*[a-z0-9][a-z0-9_-]*(?:\/\d+)?\s*=/iu;

/**
 * Parses an Authentication-Results (RFC 8601) or ARC-Authentication-Results
 * header. Microsoft 365 omits the authserv-id, so a first segment that already
 * looks like "method=result" is treated as a result.
 */
export function parseAuthenticationResults(
  value: string,
  headerIndex: number,
  headerName = 'Authentication-Results',
): AuthResultsHeader {
  const raw = value.slice(0, MAX_VALUE_CHARS);
  const warnings: string[] = [];
  const segments = splitOutsideQuotes(raw, ';');
  let arcInstance: number | null = null;

  if (headerName.toLowerCase() === 'arc-authentication-results') {
    const instance = /^\s*i\s*=\s*(\d+)\s*$/iu.exec(segments[0] ?? '');
    if (instance?.[1]) {
      arcInstance = Number(instance[1]);
      segments.shift();
    }
  }

  let authservId: string | null = null;
  const firstSegment = segments[0] ?? '';
  if (!METHOD_START.test(extractComments(firstSegment).text)) {
    segments.shift();
    const idPart = extractComments(firstSegment).text.trim().split(/\s+/u)[0] ?? '';
    authservId = idPart || null;
    if (!authservId) warnings.push('No authserv-id (reporting server) is stated.');
  } else {
    warnings.push('No authserv-id (reporting server) is stated.');
  }

  const results: AuthMethodResult[] = [];
  for (const segment of segments.slice(0, MAX_RESULTS_PER_HEADER)) {
    const { text, comments } = extractComments(segment);
    if (!text.trim()) continue;
    if (/^\s*none\s*$/iu.test(text)) continue;
    const parsed = parseResinfo(text, comments);
    if (parsed) results.push(parsed);
    else warnings.push(`Could not interpret a result segment.`);
  }
  if (segments.length > MAX_RESULTS_PER_HEADER)
    warnings.push('Too many results; the remainder were ignored.');

  return {
    headerIndex,
    headerName,
    authservId,
    arcInstance,
    results,
    raw,
    parseWarnings: warnings,
  };
}

/** Parses a Received-SPF header (RFC 7208 section 9.1). */
export function parseReceivedSpf(value: string, headerIndex: number): ReceivedSpf {
  const raw = value.slice(0, MAX_VALUE_CHARS);
  const { text, comments } = extractComments(raw);
  const trimmed = text.trim();
  const result = (/^([a-z]+)/iu.exec(trimmed)?.[1] ?? '').toLowerCase();
  const rest = trimmed.slice(result.length);
  const properties = splitOutsideQuotes(rest, ';')
    .flatMap((part) => keyValuePairs(part))
    .filter((pair) => pair.value !== '');
  return {
    headerIndex,
    result: result || 'unknown',
    status: result ? statusOf(result) : 'other',
    comment: comments[0] ?? null,
    properties,
    raw,
  };
}

function organizationalDomain(domain: string | null): string | null {
  if (!domain) return null;
  const normalized = normalizeDomain(domain);
  if (!normalized) return null;
  return analyzeHost(normalized).registrableDomain ?? normalized;
}

function formatTimestamp(value: string | undefined): string | null {
  if (!value || !/^\d{1,12}$/u.test(value)) return null;
  const date = new Date(Number(value) * 1000);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/** Parses a DKIM-Signature tag list (RFC 6376 section 3.5). The signature is not verified. */
export function parseDkimSignature(
  value: string,
  headerIndex: number,
  fromOrgDomains: ReadonlySet<string>,
): DkimSignatureInfo {
  const tags = new Map<string, string>();
  for (const part of value.slice(0, MAX_VALUE_CHARS).split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const tag = part.slice(0, eq).trim().toLowerCase();
    const tagValue = part
      .slice(eq + 1)
      .replace(/\s+/gu, tag === 'h' ? '' : ' ')
      .trim();
    if (tag && !tags.has(tag)) tags.set(tag, tagValue);
  }
  const domain = tags.get('d')?.toLowerCase() ?? null;
  const signedHeaders = (tags.get('h') ?? '')
    .split(':')
    .map((header) => header.trim().toLowerCase())
    .filter(Boolean);
  const lengthTag = tags.get('l');
  const warnings: string[] = [];
  for (const required of ['v', 'a', 'b', 'bh', 'd', 's', 'h']) {
    if (!tags.has(required)) warnings.push(`Missing required tag ${required}=.`);
  }
  if (tags.has('h') && !signedHeaders.includes('from')) {
    warnings.push('The From header is not listed in h=, which RFC 6376 requires.');
  }
  const orgDomain = organizationalDomain(domain);
  return {
    headerIndex,
    version: tags.get('v') ?? null,
    algorithm: tags.get('a')?.toLowerCase() ?? null,
    domain,
    selector: tags.get('s') ?? null,
    identity: tags.get('i') ?? null,
    canonicalization: tags.get('c') ?? null,
    signedHeaders,
    bodyLengthLimit: lengthTag && /^\d+$/u.test(lengthTag) ? Number(lengthTag) : null,
    timestamp: formatTimestamp(tags.get('t')),
    expiration: formatTimestamp(tags.get('x')),
    hasSignature: Boolean(tags.get('b')),
    hasBodyHash: Boolean(tags.get('bh')),
    alignedWithFrom: orgDomain && fromOrgDomains.size > 0 ? fromOrgDomains.has(orgDomain) : null,
    parseWarnings: warnings,
  };
}

const SUMMARY_PROPERTIES: Record<'spf' | 'dkim' | 'dmarc', string[]> = {
  spf: ['smtp.mailfrom', 'smtp.helo'],
  dkim: ['header.d', 'header.i', 'header.s'],
  dmarc: ['header.from', 'policy.dmarc', 'p', 'action'],
};

function summarize(
  headers: AuthResultsHeader[],
  method: 'spf' | 'dkim' | 'dmarc',
): ReportedMethodSummary | null {
  for (const header of headers) {
    const matches = header.results.filter((result) => result.method.toLowerCase() === method);
    if (matches.length === 0) continue;
    // With several DKIM signatures, a single pass is what DMARC needs; otherwise show the first.
    const chosen = matches.find((result) => result.status === 'pass') ?? matches[0];
    if (!chosen) continue;
    const detail = SUMMARY_PROPERTIES[method]
      .map((key) => chosen.properties.find((property) => property.key === key))
      .filter((property): property is AuthProperty => Boolean(property?.value))
      .map((property) => `${property.key}=${property.value}`)
      .join(' ');
    return {
      method,
      result: chosen.result,
      status: chosen.status,
      detail: detail || null,
      authservId: header.authservId,
      headerIndex: header.headerIndex,
    };
  }
  return null;
}

export function analyzeAuthentication(
  headers: HeaderEntry[],
  from: AddressInfo[],
): AuthenticationAnalysis {
  const fromOrgDomains = new Set(
    from
      .map((address) => address.registrableDomain)
      .filter((domain): domain is string => Boolean(domain)),
  );
  const authenticationResults = headers
    .filter((header) => header.key === 'authentication-results')
    .map((header) => parseAuthenticationResults(header.value, header.index, header.name));
  const arcAuthenticationResults = headers
    .filter((header) => header.key === 'arc-authentication-results')
    .map((header) => parseAuthenticationResults(header.value, header.index, header.name));
  const receivedSpf = headers
    .filter((header) => header.key === 'received-spf')
    .map((header) => parseReceivedSpf(header.value, header.index));
  const dkimSignatures = headers
    .filter((header) => header.key === 'dkim-signature')
    .map((header) => parseDkimSignature(header.value, header.index, fromOrgDomains));

  const authservIds = [
    ...new Set(
      authenticationResults
        .map((header) => header.authservId?.toLowerCase())
        .filter((id): id is string => Boolean(id)),
    ),
  ];

  return {
    independentlyVerified: false,
    authenticationResults,
    arcAuthenticationResults,
    receivedSpf,
    dkimSignatures,
    reported: {
      spf: summarize(authenticationResults, 'spf'),
      dkim: summarize(authenticationResults, 'dkim'),
      dmarc: summarize(authenticationResults, 'dmarc'),
    },
    authservIds,
  };
}
