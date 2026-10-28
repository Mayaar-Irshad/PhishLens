import { defangEmail, defangHost as d, defangUrl } from './defang';
import {
  analyzeHost,
  domainOfAddress,
  hostsFromDisplayText,
  isAbusedTld,
  isIcannSuffix,
  matchBrandImpersonation,
  mixedScriptLabels,
  officialBrandFor,
  type DomainInfo,
} from './domain';
import {
  CLICK_TRACKER_SUFFIXES,
  CONTACT_SCHEMES,
  FILE_EXTENSION_TLDS,
  DANGEROUS_SCHEMES,
  INTERNAL_SCHEMES,
  IPFS_GATEWAY_SUFFIXES,
  REDIRECT_PARAMETERS,
  TUNNEL_AND_DYNAMIC_DNS_SUFFIXES,
  URL_SHORTENERS,
  USER_CONTENT_HOSTS,
  WEB_SCHEMES,
} from './data/lists';
import { flag } from './findings';
import type { UrlFlag, UrlRecord, UrlSchemeClass, UrlSource, UrlSourceKind } from './types';

/**
 * URL extraction and analysis. Every URL is parsed with the WHATWG URL parser
 * (the same algorithm browsers use) so the analysed host is the host a
 * browser would actually contact. Nothing is ever fetched, resolved or opened.
 */

export interface UrlOccurrence {
  kind: UrlSourceKind;
  url: string;
  text?: string;
  /** Attachment the link was found in, if any. */
  attachment?: string;
}

const MAX_RAW_LENGTH = 4096;
const MAX_SOURCES_PER_URL = 10;
const MAX_UNWRAP_DEPTH = 2;

// ------------------------------------------------------------ extraction

const TEXT_URL =
  /\b(?:(?:https?|ftp|file|smb|javascript|vbscript|data|search-ms|ms-[a-z-]{1,40}):[^\s<>"'`]{1,4096}|www\.[^\s<>"'`]{1,4096})/giu;

function trimTrailingPunctuation(candidate: string): string {
  // Parentheses are counted once, so trimming stays linear.
  let open = 0;
  let close = 0;
  for (const char of candidate) {
    if (char === '(') open += 1;
    else if (char === ')') close += 1;
  }
  let end = candidate.length;
  while (end > 0) {
    const last = candidate[end - 1] ?? '';
    if ('.,;:!?\'">]}*'.includes(last)) {
      end -= 1;
    } else if (last === ')' && close > open) {
      end -= 1;
      close -= 1;
    } else {
      break;
    }
  }
  return candidate.slice(0, end);
}

/**
 * Finds URLs written as plain text. Plain text has no markup, so pattern
 * matching is the appropriate tool here; every candidate is then validated by
 * the WHATWG URL parser in analyzeOccurrences.
 */
export function extractTextUrls(text: string, max: number): string[] {
  const found: string[] = [];
  // Matched URLs are blanked out (in one pass) so the bare-domain scan does not re-find them.
  const kept: string[] = [];
  let cursor = 0;
  for (const match of text.matchAll(TEXT_URL)) {
    const candidate = trimTrailingPunctuation(match[0]);
    if (candidate.length > 4) found.push(candidate);
    kept.push(text.slice(cursor, match.index), ' ');
    cursor = match.index + match[0].length;
    if (found.length >= max) return found;
  }
  kept.push(text.slice(cursor));
  for (const domain of extractBareDomains(kept.join(''), max - found.length)) found.push(domain);
  return found;
}

/**
 * Lowercase host names with an optional path, the form mail clients turn into
 * links ("paypa1-secure.example/verify"). The lookbehind skips the domain part
 * of email addresses and fragments of longer tokens.
 */
const BARE_DOMAIN =
  /(?<![@\w./:%-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,10}[a-z]{2,24})(\/[^\s<>"'`]{0,2048})?(?![\w@-])/gu;
const RESERVED_TEST_TLDS: ReadonlySet<string> = new Set(['example', 'test', 'invalid']);

function extractBareDomains(text: string, max: number): string[] {
  const out: string[] = [];
  if (max <= 0) return out;
  for (const match of text.matchAll(BARE_DOMAIN)) {
    const host = match[1] ?? '';
    const tld = host.split('.').pop() ?? '';
    if (FILE_EXTENSION_TLDS.has(tld)) continue;
    const parsed = analyzeHost(host);
    if (parsed.registrableDomain === null) continue;
    if (!isIcannSuffix(host) && !RESERVED_TEST_TLDS.has(tld)) continue;
    // Returned protocol-relative, so the parser treats the scheme as assumed.
    out.push(`//${trimTrailingPunctuation(match[0])}`);
    if (out.length >= max) break;
  }
  return out;
}

// ----------------------------------------------------------- parsing

interface ParsedCandidate {
  url: URL | null;
  cleaned: string;
  schemeAssumed: boolean;
}

/** Applies the same whitespace stripping browsers apply before parsing a URL. */
function cleanUrlInput(raw: string): string {
  // Trim C0 controls and spaces with index scans; a regex anchored at $ backtracks on long runs.
  const value = raw.replace(/[\t\n\r]/gu, '');
  let start = 0;
  let end = value.length;
  while (start < end && value.charCodeAt(start) <= 0x20) start += 1;
  while (end > start && value.charCodeAt(end - 1) <= 0x20) end -= 1;
  return value.slice(start, end);
}

function parseCandidate(raw: string, baseHref: string | null): ParsedCandidate | 'relative' {
  const cleaned = cleanUrlInput(raw);
  if (/^www\./iu.test(cleaned)) {
    return { url: safeUrl(`http://${cleaned}`), cleaned, schemeAssumed: true };
  }
  if (cleaned.startsWith('//')) {
    return { url: safeUrl(`https:${cleaned}`), cleaned, schemeAssumed: true };
  }
  if (!/^[a-z][a-z0-9+.-]*:/iu.test(cleaned)) {
    // Relative references ("#top", "/path") mean nothing inside an email
    // unless a <base> element provides a base URL.
    const base = baseHref ? safeUrl(cleanUrlInput(baseHref)) : null;
    if (!base) return 'relative';
    return { url: safeUrl(cleaned, base), cleaned, schemeAssumed: false };
  }
  return { url: safeUrl(cleaned), cleaned, schemeAssumed: false };
}

function safeUrl(value: string, base?: URL): URL | null {
  try {
    return base ? new URL(value, base) : new URL(value);
  } catch {
    return null;
  }
}

function schemeClassOf(protocol: string): UrlSchemeClass {
  if (WEB_SCHEMES.has(protocol)) return 'web';
  if (CONTACT_SCHEMES.has(protocol)) return 'contact';
  if (DANGEROUS_SCHEMES.has(protocol)) return 'dangerous';
  return 'unusual';
}

/** The authority exactly as written, before browser normalization. */
function rawAuthority(cleaned: string): string | null {
  const match = /^[a-z][a-z0-9+.-]*:[\\/]{2}([^/?#\\]*)/iu.exec(cleaned);
  return match?.[1] ?? null;
}

function rawHostOf(cleaned: string): string | null {
  const authority = rawAuthority(cleaned);
  if (authority === null) return null;
  const host = authority.slice(authority.lastIndexOf('@') + 1);
  return host
    .replace(/:\d*$/u, '')
    .replace(/^\[|\]$/gu, '')
    .replace(/\.$/u, '')
    .toLowerCase();
}

const IPV4_HOST = /^(?:\d{1,3}\.){3}\d{1,3}$/u;

function hostMatchesSuffix(host: string, suffixes: readonly string[]): boolean {
  return suffixes.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}

// ----------------------------------------------------- embedded URLs

interface Embedded {
  kind: 'security-wrapper' | 'redirect-parameter';
  parameter: string;
  url: string;
}

function decodeProofpointV2(value: string): string | null {
  try {
    return decodeURIComponent(value.replace(/-/gu, '%').replace(/_/gu, '/'));
  } catch {
    return null;
  }
}

function decodeBase64(value: string): string | null {
  try {
    const padded = value + '='.repeat((4 - (value.length % 4)) % 4);
    return atob(padded);
  } catch {
    return null;
  }
}

function safeDecode(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

function looksLikeAbsoluteWebUrl(value: string): boolean {
  return /^(?:https?:)?\/\/[^\s/]/iu.test(value.trim());
}

function maybeDecode(value: string): string {
  if (!/^https?%3a/iu.test(value)) return value;
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Finds destinations hidden inside security-gateway wrappers or redirect parameters. */
export function embeddedDestinations(url: URL): Embedded[] {
  const host = url.hostname.toLowerCase();
  const out: Embedded[] = [];

  if (host.endsWith('safelinks.protection.outlook.com')) {
    const inner = url.searchParams.get('url');
    if (inner) out.push({ kind: 'security-wrapper', parameter: 'url', url: inner });
    return out;
  }
  if (host === 'urldefense.proofpoint.com' && url.pathname.startsWith('/v2/')) {
    const encoded = url.searchParams.get('u');
    const inner = encoded ? decodeProofpointV2(encoded) : null;
    if (inner) out.push({ kind: 'security-wrapper', parameter: 'u', url: inner });
    return out;
  }
  if (host === 'urldefense.com' && url.pathname.startsWith('/v3/__')) {
    const end = url.pathname.indexOf('__;');
    const inner = url.pathname.slice('/v3/__'.length, end === -1 ? undefined : end);
    if (inner) out.push({ kind: 'security-wrapper', parameter: 'path', url: inner });
    return out;
  }
  if (host === 'linkprotect.cudasvc.com') {
    const inner = url.searchParams.get('a');
    if (inner) out.push({ kind: 'security-wrapper', parameter: 'a', url: inner });
    return out;
  }
  // Mimecast keeps only the destination domain in the link, not the full address.
  if (
    (host.endsWith('.mimecast.com') || host.endsWith('.mimecastprotect.com')) &&
    url.pathname.startsWith('/s/')
  ) {
    const domain = url.searchParams.get('domain');
    if (domain && /^[a-z0-9.-]{1,253}$/iu.test(domain)) {
      out.push({ kind: 'security-wrapper', parameter: 'domain', url: `https://${domain}/` });
    }
    return out;
  }
  if (host.endsWith('.trendmicro.com') && url.pathname.includes('/clicktime/')) {
    const inner = url.searchParams.get('url');
    if (inner) out.push({ kind: 'security-wrapper', parameter: 'url', url: inner });
    return out;
  }
  if (host.endsWith('protection.sophos.com')) {
    const encoded = url.searchParams.get('u');
    const inner = encoded ? decodeBase64(encoded) : null;
    const domain = url.searchParams.get('d');
    if (inner && looksLikeAbsoluteWebUrl(inner)) {
      out.push({ kind: 'security-wrapper', parameter: 'u', url: inner });
    } else if (domain && /^[a-z0-9.-]{1,253}$/iu.test(domain)) {
      out.push({ kind: 'security-wrapper', parameter: 'd', url: `https://${domain}/` });
    }
    return out;
  }
  if (host === 'secure-web.cisco.com') {
    const last = url.pathname.split('/').pop() ?? '';
    const inner = safeDecode(last);
    if (inner && looksLikeAbsoluteWebUrl(inner)) {
      out.push({ kind: 'security-wrapper', parameter: 'path', url: inner });
    }
    return out;
  }
  // Google AMP viewer: https://www.google.com/amp/s/<host>/<path> opens <host>.
  if (/^(?:www\.)?google\.[a-z.]{2,8}$/u.test(host) && /^\/amp\/s?\/?[^/]/u.test(url.pathname)) {
    const rest = url.pathname.replace(/^\/amp\/(s\/)?/u, '');
    const secure = url.pathname.startsWith('/amp/s/');
    out.push({
      kind: 'redirect-parameter',
      parameter: 'amp',
      url: `${secure ? 'https' : 'http'}://${rest}`,
    });
    return out;
  }
  // Bing click-through: /ck/a?...&u=a1<base64url destination>.
  if (/^(?:www\.)?bing\.com$/u.test(host) && url.pathname === '/ck/a') {
    const encoded = url.searchParams.get('u');
    const inner = encoded?.startsWith('a1')
      ? decodeBase64(encoded.slice(2).replace(/-/gu, '+').replace(/_/gu, '/'))
      : null;
    if (inner && looksLikeAbsoluteWebUrl(inner)) {
      out.push({ kind: 'redirect-parameter', parameter: 'u', url: inner });
    }
    return out;
  }

  for (const [key, value] of url.searchParams) {
    if (!REDIRECT_PARAMETERS.has(key.toLowerCase())) continue;
    const decoded = maybeDecode(value);
    if (looksLikeAbsoluteWebUrl(decoded)) {
      out.push({ kind: 'redirect-parameter', parameter: key, url: decoded });
    }
    if (out.length >= 3) break;
  }
  return out;
}

// --------------------------------------------------------- heuristics

const RISKY_DOWNLOAD_EXTENSIONS: ReadonlySet<string> = new Set([
  'exe',
  'scr',
  'pif',
  'bat',
  'cmd',
  'vbs',
  'vbe',
  'js',
  'jse',
  'wsf',
  'hta',
  'msi',
  'ps1',
  'jar',
  'lnk',
  'iso',
  'img',
  'vhd',
  'vhdx',
  'dmg',
  'apk',
  'zip',
  'rar',
  '7z',
  'cab',
  'docm',
  'xlsm',
  'pptm',
  'one',
  'appx',
  'msix',
  'reg',
  'cpl',
  'dll',
]);

function riskyDownloadExtension(url: URL): string | null {
  let path: string;
  try {
    path = decodeURIComponent(url.pathname);
  } catch {
    path = url.pathname;
  }
  const last = path.split('/').pop() ?? '';
  const dot = last.lastIndexOf('.');
  if (dot <= 0) return null;
  const extension = last.slice(dot + 1).toLowerCase();
  return RISKY_DOWNLOAD_EXTENSIONS.has(extension) ? extension : null;
}

/** Host-level heuristics shared by every web URL. */
function hostFlags(info: DomainInfo, rawHost: string | null, flags: UrlFlag[]): void {
  if (info.isIp) {
    const obfuscated = rawHost !== null && IPV4_HOST.test(info.host) && rawHost !== info.host;
    flags.push(
      obfuscated
        ? flag(
            'URL_OBFUSCATED_IP',
            `Host written as "${d(rawHost)}" is read by browsers as IP address ${d(info.host)}`,
          )
        : flag('URL_IP_HOST', `Host is the IP address ${d(info.host)}`),
    );
    return;
  }
  if (rawHost?.includes('%')) {
    flags.push(
      flag('URL_ENCODED_HOST', `Host was written with percent-encoding ("${d(rawHost)}")`),
    );
  }
  if (info.hostUnicode) {
    const mixed = mixedScriptLabels(info.hostUnicode);
    if (mixed.length > 0) {
      flags.push(
        flag(
          'URL_MIXED_SCRIPT',
          `Label "${mixed[0] ?? ''}" mixes alphabets (displayed as ${d(info.hostUnicode)})`,
        ),
      );
    }
    flags.push(
      flag('URL_PUNYCODE', `Displayed as "${d(info.hostUnicode)}", encoded as ${d(info.host)}`),
    );
  }

  const brand = matchBrandImpersonation(info);
  if (brand) {
    switch (brand.kind) {
      case 'subdomain':
        flags.push(
          flag(
            'URL_BRAND_IN_SUBDOMAIN',
            `Starts with ${d(brand.keyword)}, but the registered domain is ${d(info.registrableDomain ?? info.host)}`,
          ),
        );
        break;
      case 'homograph':
      case 'lookalike':
        flags.push(
          flag(
            'URL_LOOKALIKE_DOMAIN',
            `"${brand.matched}" resembles ${brand.brand.name} ("${brand.keyword}")`,
          ),
        );
        break;
      case 'keyword':
        flags.push(
          flag(
            'URL_BRAND_KEYWORD',
            `Contains "${brand.keyword}" (${brand.brand.name}) but ${d(info.registrableDomain ?? info.host)} is not a domain PhishLens associates with ${brand.brand.name}`,
          ),
        );
        break;
    }
  }

  if (info.registrableDomain && URL_SHORTENERS.has(info.registrableDomain)) {
    flags.push(flag('URL_SHORTENER', `${d(info.registrableDomain)} is a URL-shortening service`));
  }
  if (hostMatchesSuffix(info.host, TUNNEL_AND_DYNAMIC_DNS_SUFFIXES)) {
    flags.push(
      flag(
        'URL_TUNNEL_OR_DYNAMIC_DNS',
        `${d(info.host)} belongs to a dynamic DNS or tunnelling service`,
      ),
    );
  } else if (info.isSharedHosting) {
    flags.push(
      flag(
        'URL_SHARED_HOSTING',
        `${d(info.registrableDomain ?? info.host)} is published on the shared platform "${d(info.publicSuffix ?? '')}"`,
      ),
    );
  }
  if (hostMatchesSuffix(info.host, IPFS_GATEWAY_SUFFIXES)) {
    flags.push(flag('URL_IPFS', `${d(info.host)} is an IPFS gateway`));
  }
  if (isAbusedTld(info)) {
    flags.push(
      flag('URL_RISKY_TLD', `Top-level domain ".${info.publicSuffix?.split('.').pop() ?? ''}"`),
    );
  }
  const labels = info.host.split('.').length;
  if (labels >= 6 || info.host.length > 70) {
    flags.push(flag('URL_COMPLEX_HOSTNAME', `${labels} labels, ${info.host.length} characters`));
  }
}

// ------------------------------------------------------------ records

interface Builder {
  record: UrlRecord;
  sourceKeys: Set<string>;
}

function addFlag(record: UrlRecord, newFlag: UrlFlag): void {
  if (!record.flags.some((existing) => existing.ruleId === newFlag.ruleId))
    record.flags.push(newFlag);
}

function buildRecord(id: number, occurrence: UrlOccurrence, parsed: ParsedCandidate): UrlRecord {
  const raw =
    occurrence.url.length > MAX_RAW_LENGTH
      ? `${occurrence.url.slice(0, MAX_RAW_LENGTH)}…`
      : occurrence.url;
  const url = parsed.url;
  const flags: UrlFlag[] = [];

  if (!url) {
    flags.push(flag('URL_UNPARSEABLE', 'Not a valid URL according to the WHATWG URL standard'));
    return {
      id,
      raw,
      normalized: null,
      defanged: defangUrl(raw),
      rawDefanged: null,
      scheme: null,
      schemeClass: 'unknown',
      host: null,
      hostUnicode: null,
      registrableDomain: null,
      isIpHost: false,
      port: null,
      sources: [],
      embedded: [],
      flags,
    };
  }

  const schemeClass = schemeClassOf(url.protocol);
  const normalized =
    url.href.length > MAX_RAW_LENGTH ? `${url.href.slice(0, MAX_RAW_LENGTH)}…` : url.href;
  const hostname = url.hostname.replace(/^\[|\]$/gu, '');
  const info = hostname ? analyzeHost(hostname) : null;

  if (schemeClass === 'dangerous') {
    flags.push(flag('URL_DANGEROUS_SCHEME', `Uses the ${url.protocol} scheme`));
  } else if (schemeClass === 'unusual') {
    flags.push(flag('URL_UNUSUAL_SCHEME', `Uses the ${url.protocol} scheme`));
  }

  if (url.username || url.password) {
    let userinfo = url.username;
    try {
      userinfo = decodeURIComponent(url.username);
    } catch {
      // keep the encoded form
    }
    flags.push(
      flag(
        'URL_USERINFO',
        `"${d(userinfo)}" appears before "@", but the link goes to ${d(hostname)}`,
      ),
    );
  }

  if (schemeClass === 'web' && info) {
    hostFlags(info, rawHostOf(parsed.cleaned), flags);
    // A scheme PhishLens assumed for "www." text is not something the sender wrote.
    if (url.protocol === 'http:' && !parsed.schemeAssumed) {
      flags.push(flag('URL_INSECURE_HTTP', 'Uses http:// rather than https://'));
    }
    if (url.port) flags.push(flag('URL_NONSTANDARD_PORT', `Port ${url.port}`));
    const extension = riskyDownloadExtension(url);
    if (extension) flags.push(flag('URL_RISKY_DOWNLOAD', `Path ends in .${extension}`));
  }

  const embedded =
    schemeClass === 'web'
      ? embeddedDestinations(url).map((entry) => {
          const innerUrl = safeUrl(entry.url.startsWith('//') ? `https:${entry.url}` : entry.url);
          const innerInfo = innerUrl?.hostname ? analyzeHost(innerUrl.hostname) : null;
          return {
            ...entry,
            defanged: defangUrl(entry.url),
            registrableDomain: innerInfo?.registrableDomain ?? innerInfo?.host ?? null,
          };
        })
      : [];
  const outerDomain = info?.registrableDomain ?? info?.host ?? null;
  for (const entry of embedded) {
    if (entry.kind === 'security-wrapper') {
      flags.push(
        flag('URL_SECURITY_WRAPPER', `Wrapped link; original destination ${entry.defanged}`),
      );
    } else if (entry.registrableDomain && entry.registrableDomain !== outerDomain) {
      flags.push(
        flag('URL_EMBEDDED_REDIRECT', `Parameter "${entry.parameter}" carries ${entry.defanged}`),
      );
    }
  }

  const defanged = defangUrl(normalized);
  const rawDefanged = defangUrl(raw);
  return {
    id,
    raw,
    normalized,
    defanged,
    rawDefanged: rawDefanged !== defanged && !parsed.schemeAssumed ? rawDefanged : null,
    scheme: url.protocol.replace(/:$/u, ''),
    schemeClass,
    host: info?.host ?? null,
    hostUnicode: info?.hostUnicode ?? null,
    registrableDomain: info?.registrableDomain ?? null,
    isIpHost: info?.isIp ?? false,
    port: url.port || null,
    sources: [],
    embedded,
    flags: dedupeFlags(flags),
  };
}

function dedupeFlags(flags: UrlFlag[]): UrlFlag[] {
  const seen = new Set<string>();
  return flags.filter((entry) => (seen.has(entry.ruleId) ? false : (seen.add(entry.ruleId), true)));
}

/** Compares visible link text that looks like an address with the real destination. */
const EMAIL_IN_TEXT = /[^\s<>"'(),;:@]{1,64}@[^\s<>"'(),;:@]{1,253}\.[a-z]{2,24}/iu;

function organisationOf(host: string): { info: DomainInfo; org: string } {
  const info = analyzeHost(host);
  return { info, org: info.registrableDomain ?? info.host };
}

function flagMismatch(
  record: UrlRecord,
  displayed: DomainInfo,
  label: string,
  actual: DomainInfo,
): void {
  const brand = officialBrandFor(displayed);
  // Customer-published content on brand infrastructure (SharePoint tenants, Google Docs) is not the brand.
  const actualBrand = hostMatchesSuffix(actual.host, USER_CONTENT_HOSTS)
    ? null
    : officialBrandFor(actual);
  if (brand && actualBrand !== brand) {
    addFlag(
      record,
      flag(
        'URL_TEXT_BRAND_MISMATCH',
        `${label} (not a domain PhishLens associates with ${brand.name})`,
      ),
    );
  } else {
    addFlag(record, flag('URL_TEXT_MISMATCH', label));
  }
}

/** A mailto: link whose text shows one address but which writes to another organisation. */
function checkMailtoText(record: UrlRecord, text: string): void {
  const shown = EMAIL_IN_TEXT.exec(text)?.[0];
  if (!shown || !record.normalized) return;
  let target: string;
  try {
    target = decodeURIComponent(new URL(record.normalized).pathname).split(',')[0]?.trim() ?? '';
  } catch {
    return;
  }
  const shownDomain = domainOfAddress(shown);
  const targetDomain = domainOfAddress(target);
  if (!shownDomain || !targetDomain) return;
  const displayed = organisationOf(shownDomain);
  const actual = organisationOf(targetDomain);
  if (displayed.org === actual.org) return;
  flagMismatch(
    record,
    displayed.info,
    `Text shows "${defangEmail(shown)}" but the link writes to ${defangEmail(target)}`,
    actual.info,
  );
}

function checkDisplayText(record: UrlRecord, text: string): void {
  if (record.scheme === 'mailto') {
    checkMailtoText(record, text);
    return;
  }
  if (record.schemeClass !== 'web' || !record.host) return;
  const actual = organisationOf(record.host);
  const viaTracker = hostMatchesSuffix(record.host, CLICK_TRACKER_SUFFIXES);
  for (const displayedHost of hostsFromDisplayText(text)) {
    const displayed = organisationOf(displayedHost);
    if (displayed.org === actual.org) continue;
    const displayedBrand = officialBrandFor(displayed.info);
    // A tracking redirect that ends at the displayed domain explains the difference,
    // unless the text shows a brand: open redirects are abused to borrow brand names.
    if (
      !displayedBrand &&
      record.embedded.some((entry) => entry.registrableDomain === displayed.org)
    )
      continue;
    const label = `Text shows "${d(displayedHost)}" but the link goes to ${d(actual.org)}`;
    if (viaTracker) {
      // Marketing click tracking hides the destination; only brand text is worth flagging.
      if (displayedBrand) {
        addFlag(
          record,
          flag(
            'URL_TEXT_MISMATCH',
            `${label}, an email click-tracking service that hides the final destination`,
          ),
        );
      }
      return;
    }
    flagMismatch(record, displayed.info, label, actual.info);
    return;
  }
}

export interface UrlAnalysis {
  records: UrlRecord[];
  truncated: boolean;
}

/**
 * Turns raw occurrences into de-duplicated, analysed URL records. Wrapped
 * links (Safe Links, URL Defense) are unwrapped and the original destination
 * is analysed as well, carrying the original link text.
 */
export function analyzeOccurrences(
  occurrences: UrlOccurrence[],
  maxUrls: number,
  baseHref: string | null,
): UrlAnalysis {
  const builders = new Map<string, Builder>();
  let truncated = false;
  const queue: { occurrence: UrlOccurrence; depth: number }[] = occurrences.map((occurrence) => ({
    occurrence,
    depth: 0,
  }));

  for (let i = 0; i < queue.length; i += 1) {
    const item = queue[i];
    if (!item) continue;
    const { occurrence, depth } = item;
    const parsed = parseCandidate(occurrence.url, baseHref);
    if (parsed === 'relative') continue;
    if (parsed.url && INTERNAL_SCHEMES.has(parsed.url.protocol)) continue;

    const key = parsed.url?.href ?? parsed.cleaned;
    let builder = builders.get(key);
    if (!builder) {
      if (builders.size >= maxUrls) {
        truncated = true;
        continue;
      }
      builder = {
        record: buildRecord(builders.size + 1, occurrence, parsed),
        sourceKeys: new Set(),
      };
      builders.set(key, builder);
      if (depth < MAX_UNWRAP_DEPTH) {
        for (const entry of builder.record.embedded) {
          // A wrapped destination keeps the link text, since it is what the reader sees.
          // A redirect destination is analysed on its own; the text belongs to the outer link.
          const inner: UrlOccurrence =
            entry.kind === 'security-wrapper'
              ? { ...occurrence, url: entry.url }
              : { kind: occurrence.kind, url: entry.url };
          if (entry.kind !== 'security-wrapper' && occurrence.attachment !== undefined) {
            inner.attachment = occurrence.attachment;
          }
          queue.push({ occurrence: inner, depth: depth + 1 });
        }
      }
    }

    const { record, sourceKeys } = builder;
    const sourceKey = `${occurrence.kind}\u0000${occurrence.text ?? ''}\u0000${occurrence.attachment ?? ''}`;
    if (!sourceKeys.has(sourceKey) && record.sources.length < MAX_SOURCES_PER_URL) {
      sourceKeys.add(sourceKey);
      const source: UrlSource = { kind: occurrence.kind };
      if (occurrence.text) source.text = occurrence.text;
      if (occurrence.attachment !== undefined) source.attachment = occurrence.attachment;
      record.sources.push(source);
    }
    const isWrapper = record.embedded.some((entry) => entry.kind === 'security-wrapper');
    if (occurrence.text && !isWrapper) checkDisplayText(record, occurrence.text);
  }

  return { records: [...builders.values()].map((builder) => builder.record), truncated };
}
