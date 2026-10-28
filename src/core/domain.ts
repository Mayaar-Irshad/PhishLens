import { toUnicode } from 'punycode/punycode.es6.js';
import { parse as parseHost } from 'tldts';
import { BRANDS, SERVICE_WORDS, type Brand } from './data/brands';
import {
  ABUSED_TLDS,
  FILE_EXTENSION_TLDS,
  SAAS_TENANT_DOMAINS,
  TENANT_PLATFORMS,
} from './data/lists';

export interface DomainInfo {
  /** Lowercase ASCII host (punycode for internationalized names). */
  host: string;
  /** Unicode rendering when the host contains punycode labels, otherwise null. */
  hostUnicode: string | null;
  registrableDomain: string | null;
  /** Registrable domain without its public suffix, e.g. "example" for "example.co.uk". */
  label: string | null;
  publicSuffix: string | null;
  subdomain: string;
  isIp: boolean;
  /** True when the public suffix is a shared platform from the PSL private section. */
  isSharedHosting: boolean;
  isIdn: boolean;
}

export function toUnicodeHost(host: string): string | null {
  if (!host.split('.').some((label) => label.startsWith('xn--'))) return null;
  try {
    return toUnicode(host);
  } catch {
    return null;
  }
}

export function analyzeHost(rawHost: string): DomainInfo {
  const host = rawHost.toLowerCase().replace(/\.$/u, '');
  const parsed = parseHost(host, { allowPrivateDomains: true });
  const hostUnicode = toUnicodeHost(host);
  return {
    host,
    hostUnicode,
    registrableDomain: parsed.domain,
    label: parsed.domainWithoutSuffix,
    publicSuffix: parsed.publicSuffix,
    subdomain: parsed.subdomain ?? '',
    isIp: parsed.isIp === true,
    isSharedHosting: parsed.isPrivate === true && parsed.domain !== null,
    isIdn: hostUnicode !== null,
  };
}

const DOMAIN_CHARS = /^[^\s/@:?#\\[\]<>"'`]+$/u;

/** Normalizes an email-address domain to lowercase ASCII, or null if it is not a usable domain. */
export function normalizeDomain(domain: string): string | null {
  const trimmed = domain.trim().toLowerCase().replace(/\.$/u, '');
  if (!trimmed) return null;
  if (/^\[[0-9a-f:.]+\]$/u.test(trimmed) || trimmed.startsWith('[ipv6:')) return trimmed;
  if (!DOMAIN_CHARS.test(trimmed)) return null;
  try {
    const url = new URL(`http://${trimmed}/`);
    return url.hostname || null;
  } catch {
    return null;
  }
}

export function domainOfAddress(address: string): string | null {
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) return null;
  return normalizeDomain(address.slice(at + 1));
}

/** True when the host ends in a public suffix from the ICANN section of the Public Suffix List. */
export function isIcannSuffix(host: string): boolean {
  return parseHost(host, { allowPrivateDomains: true }).isIcann === true;
}

export function isAbusedTld(info: DomainInfo): boolean {
  if (!info.publicSuffix || info.isSharedHosting) return false;
  const tld = info.publicSuffix.split('.').pop() ?? '';
  return ABUSED_TLDS.has(tld);
}

// ------------------------------------------------------------ scripts

type ConfusableScript = 'Latin' | 'Cyrillic' | 'Greek' | 'Armenian';

function confusableScriptsIn(label: string): Set<ConfusableScript> {
  const scripts = new Set<ConfusableScript>();
  for (const char of label) {
    if (/\p{Script=Latin}/u.test(char)) scripts.add('Latin');
    else if (/\p{Script=Cyrillic}/u.test(char)) scripts.add('Cyrillic');
    else if (/\p{Script=Greek}/u.test(char)) scripts.add('Greek');
    else if (/\p{Script=Armenian}/u.test(char)) scripts.add('Armenian');
  }
  return scripts;
}

/**
 * True when any label mixes two of Latin, Cyrillic, Greek and Armenian, the
 * scripts with many visually identical letters. Browsers display such names
 * as punycode for the same reason.
 */
export function mixedScriptLabels(unicodeHost: string): string[] {
  return unicodeHost.split('.').filter((label) => confusableScriptsIn(label).size > 1);
}

/** Characters from other scripts that are commonly mistaken for Latin letters. */
const CONFUSABLES: Readonly<Record<string, string>> = {
  // Cyrillic
  '\u0430': 'a',
  '\u0432': 'b',
  '\u0441': 'c',
  '\u0501': 'd',
  '\u0435': 'e',
  '\u0451': 'e',
  '\u04BB': 'h',
  '\u0456': 'i',
  '\u0457': 'i',
  '\u0458': 'j',
  '\u043A': 'k',
  '\u04CF': 'l',
  '\u043C': 'm',
  '\u043D': 'h',
  '\u043E': 'o',
  '\u0440': 'p',
  '\u051B': 'q',
  '\u0455': 's',
  '\u0442': 't',
  '\u0446': 'u',
  '\u0475': 'v',
  '\u051D': 'w',
  '\u0445': 'x',
  '\u0443': 'y',
  '\u04AF': 'y',
  '\u0437': '3',
  // Greek
  '\u03B1': 'a',
  '\u03B2': 'b',
  '\u03B5': 'e',
  '\u03B7': 'n',
  '\u03B9': 'i',
  '\u03BA': 'k',
  '\u03BD': 'v',
  '\u03BF': 'o',
  '\u03C1': 'p',
  '\u03C4': 't',
  '\u03C5': 'u',
  '\u03C7': 'x',
  '\u03F2': 'c',
  '\u03F3': 'j',
  '\u03C9': 'w',
  // Armenian
  '\u0585': 'o',
  '\u057D': 'u',
  '\u0570': 'h',
  '\u0578': 'n',
  '\u0566': 'q',
  '\u0581': 'g',
  '\u0561': 'w',
  // Latin look-alikes outside basic ASCII
  '\u0131': 'i',
  '\u0269': 'i',
  '\u0251': 'a',
  '\u0261': 'g',
  '\u0262': 'g',
  '\u029F': 'l',
  '\u0142': 'l',
  '\u019A': 'l',
  '\u0237': 'j',
  '\u0274': 'n',
  '\u0280': 'r',
};

/** Maps a label to plain ASCII using diacritic stripping and the confusables table. */
export function confusableSkeleton(label: string): string {
  const stripped = label.normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase();
  let out = '';
  for (const char of stripped) out += CONFUSABLES[char] ?? char;
  return out;
}

/** ASCII substitutions frequently used in typosquats, producing every plausible reading. */
function asciiVariants(value: string): string[] {
  const base = value
    .replace(/0/gu, 'o')
    .replace(/3/gu, 'e')
    .replace(/5/gu, 's')
    .replace(/\$/gu, 's');
  const readings = new Set([base.replace(/1/gu, 'l'), base.replace(/1/gu, 'i')]);
  for (const reading of [...readings]) {
    readings.add(reading.replace(/rn/gu, 'm').replace(/vv/gu, 'w'));
  }
  return [...readings];
}

/**
 * Optimal string alignment distance: Levenshtein plus transposition of two
 * adjacent letters, so "micorsoft" and "paypla" count as one edit.
 */
export function editDistance(a: string, b: string, max = 2): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const rows: number[][] = [Array.from({ length: b.length + 1 }, (_, j) => j)];
  for (let i = 1; i <= a.length; i += 1) {
    const row = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let value = Math.min(
        (rows[i - 1]?.[j] ?? 0) + 1,
        (row[j - 1] ?? 0) + 1,
        (rows[i - 1]?.[j - 1] ?? 0) + cost,
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        value = Math.min(value, (rows[i - 2]?.[j - 2] ?? 0) + 1);
      }
      row.push(value);
      rowMin = Math.min(rowMin, value);
    }
    if (rowMin > max) return max + 1;
    rows.push(row);
  }
  return rows[a.length]?.[b.length] ?? max + 1;
}

/** Real words that sit one edit away from a brand keyword and must not count as typosquats. */
const TYPO_EXCEPTIONS: ReadonlySet<string> = new Set([
  'finance',
  'cloud',
  'tunes',
  'goggle',
  'googly',
  'amazin',
  'amazons',
  'outlooks',
  'messengers',
]);

// ------------------------------------------------------------- brands

/** Brands whose name is registered under most country-code TLDs (google.de, amazon.co.uk...). */
const COUNTRY_TLD_BRANDS: ReadonlySet<string> = new Set([
  'Google',
  'Amazon',
  'Microsoft',
  'Apple',
  'PayPal',
  'DHL',
]);

/**
 * Country-code TLDs marketed for generic use, or one typo away from .com.
 * A brand name under these is not assumed to belong to the brand.
 */
const GENERIC_USE_CCTLDS: ReadonlySet<string> = new Set([
  'co',
  'cc',
  'cm',
  'om',
  'ws',
  'io',
  'ai',
  'me',
  'tv',
  'su',
  'to',
  'ly',
  'la',
  'nu',
  'fm',
  'am',
  'gg',
  'im',
  'sh',
  'ac',
  'vc',
  'ag',
  'bz',
  'mn',
  'pw',
  'cx',
  'ms',
  'nf',
  'so',
  'tl',
  'st',
  'gl',
  'md',
  'py',
  'ps',
  'vu',
  'cd',
  'ki',
  'ne',
  'cr',
  'is',
  'id',
  'li',
]);

function isCountrySuffix(publicSuffix: string): boolean {
  const parts = publicSuffix.split('.');
  const last = parts[parts.length - 1] ?? '';
  if (last.length !== 2 || ABUSED_TLDS.has(last) || GENERIC_USE_CCTLDS.has(last)) return false;
  if (parts.length === 1) return true;
  return parts.length === 2 && ['co', 'com', 'ne', 'or'].includes(parts[0] ?? '');
}

export function isOfficialBrandDomain(brand: Brand, info: DomainInfo): boolean {
  // Customer content on brand infrastructure (S3 buckets, Azure storage, appspot...) is not the brand's.
  if (!info.registrableDomain || info.isSharedHosting) return false;
  const registrable = info.registrableDomain;
  if (
    brand.domains.some(
      (domain) =>
        registrable === domain || info.host === domain || info.host.endsWith(`.${domain}`),
    )
  ) {
    return true;
  }
  return (
    COUNTRY_TLD_BRANDS.has(brand.name) &&
    info.label !== null &&
    brand.keywords.includes(info.label) &&
    info.publicSuffix !== null &&
    isCountrySuffix(info.publicSuffix)
  );
}

export function officialBrandFor(info: DomainInfo): Brand | null {
  return BRANDS.find((brand) => isOfficialBrandDomain(brand, info)) ?? null;
}

export type BrandMatchKind = 'homograph' | 'lookalike' | 'subdomain' | 'keyword';

export interface BrandMatch {
  brand: Brand;
  kind: BrandMatchKind;
  keyword: string;
  matched: string;
}

const KIND_PRIORITY: Record<BrandMatchKind, number> = {
  homograph: 0,
  subdomain: 1,
  lookalike: 2,
  keyword: 3,
};

function tokensOf(label: string): string[] {
  return label.split(/[-_.]+/u).filter(Boolean);
}

const ASCII_ONLY = /^[ -~]*$/u;

/**
 * Compares one domain token (Unicode form) with a brand's keywords. ASCII
 * tokens can only be "lookalikes" (digit/letter substitutions, one-letter
 * typos); tokens that needed the confusables table are "homographs".
 */
function matchToken(brand: Brand, token: string): BrandMatch | null {
  const isAscii = ASCII_ONLY.test(token);
  const skeleton = isAscii ? token : confusableSkeleton(token);
  const disguised: BrandMatchKind = isAscii ? 'lookalike' : 'homograph';
  const tokenVariants = asciiVariants(skeleton);

  for (const keyword of brand.keywords) {
    if (token === keyword) return { brand, kind: 'keyword', keyword, matched: token };
    const keywordVariants = asciiVariants(keyword);
    if (tokenVariants.some((variant) => keywordVariants.includes(variant))) {
      return { brand, kind: disguised, keyword, matched: token };
    }
    if (
      keyword.length >= 6 &&
      skeleton.length >= 5 &&
      !TYPO_EXCEPTIONS.has(skeleton) &&
      editDistance(skeleton, keyword, 1) === 1
    ) {
      return { brand, kind: disguised, keyword, matched: token };
    }
    if (brand.substring && keyword.length >= 5) {
      if (skeleton.includes(keyword)) {
        return { brand, kind: isAscii ? 'keyword' : 'homograph', keyword, matched: token };
      }
      if (tokenVariants.some((variant) => keywordVariants.some((k) => variant.includes(k)))) {
        return { brand, kind: disguised, keyword, matched: token };
      }
    }
  }
  return null;
}

/**
 * Looks for brand impersonation in a host name. Returns null for official
 * brand domains, IP addresses, and hosts with no brand resemblance.
 */
export function matchBrandImpersonation(info: DomainInfo): BrandMatch | null {
  if (info.isIp || !info.registrableDomain || !info.label) return null;
  if (officialBrandFor(info) || tenantPlatformOf(info)) return null;
  // On multi-tenant SaaS, a customer name in the subdomain ("microsoft.zendesk.com") is normal.
  const subdomainTokens =
    info.subdomain && !SAAS_TENANT_DOMAINS.has(info.registrableDomain)
      ? tokensOf(toUnicodeHost(info.subdomain) ?? info.subdomain)
      : [];

  const label = toUnicodeHost(info.label) ?? info.label;
  let best: BrandMatch | null = null;
  const consider = (match: BrandMatch | null) => {
    if (match && (!best || KIND_PRIORITY[match.kind] < KIND_PRIORITY[best.kind])) best = match;
  };

  for (const brand of BRANDS) {
    // A brand domain placed in front of an unrelated registered domain: "paypal.com.example.net".
    if (info.subdomain) {
      const sub = `.${info.subdomain}.`;
      const official = brand.domains.find((domain) => sub.includes(`.${domain}.`));
      if (official)
        consider({ brand, kind: 'subdomain', keyword: official, matched: info.subdomain });
    }
    // The label with separators removed catches "pay-pal" and "paypa1-login".
    const joined = label.replace(/[-_]/gu, '');
    const joinedMatch = matchToken(brand, joined);
    if (joinedMatch?.kind === 'keyword' && joined !== label && brand.keywords.includes(joined)) {
      consider({ ...joinedMatch, kind: 'lookalike', matched: label });
    } else {
      consider(joinedMatch);
    }
    for (const token of tokensOf(label)) consider(matchToken(brand, token));
    // A brand name used as a subdomain of an unrelated site: "paypal.account-verify.example".
    for (const token of subdomainTokens) consider(matchToken(brand, token));
  }
  return best;
}

/**
 * True when two different domain labels are "cousins": equal after look-alike
 * substitutions (rn/m, 0/o, Cyrillic letters...) or one edit apart.
 */
export function areCousinLabels(a: string, b: string): boolean {
  if (a === b || a.length < 4 || b.length < 4) return false;
  const variantsA = asciiVariants(confusableSkeleton(a));
  const variantsB = asciiVariants(confusableSkeleton(b));
  if (variantsA.some((variant) => variantsB.includes(variant))) return true;
  return Math.min(a.length, b.length) >= 5 && editDistance(a, b, 1) === 1;
}

/** Shared tenant domains such as "contoso.onmicrosoft.com", which anyone can create. */
export function tenantPlatformOf(info: DomainInfo): string | null {
  return info.registrableDomain ? (TENANT_PLATFORMS.get(info.registrableDomain) ?? null) : null;
}

// ------------------------------------------------------- display names

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

function containsWord(haystack: string, word: string): boolean {
  return new RegExp(`(^|[^\\p{L}\\p{N}])${escapeRegExp(word)}($|[^\\p{L}\\p{N}])`, 'u').test(
    haystack,
  );
}

/** Brands referred to by a sender display name. */
export function brandsInDisplayName(displayName: string): Brand[] {
  const name = displayName.slice(0, 500);
  // A capital I is a common stand-in for a lowercase l ("PaypaI"), so check that reading too.
  const normalized = [name, name.replace(/I/gu, 'l')]
    .map((variant) => asciiVariants(confusableSkeleton(variant))[0] ?? '')
    .join(' \u0000 ');
  const original = name.toLowerCase();
  const hasServiceWord = SERVICE_WORDS.some(
    (word) => containsWord(original, word) || containsWord(normalized, word),
  );
  return BRANDS.filter((brand) => {
    const names = [brand.name.toLowerCase(), ...brand.keywords];
    const mentioned = names.some(
      (name) => containsWord(normalized, name) || containsWord(original, name),
    );
    return mentioned && (!brand.ambiguousName || hasServiceWord);
  });
}

/**
 * Hosts that link text displays. A text that is itself an address yields that
 * host; longer text ("Visit www.bank.example today") yields the hosts of any
 * tokens that start with a scheme or "www.", the forms readers recognise as
 * links. Bare words with dots in a sentence are ignored to avoid false matches.
 */
export function hostsFromDisplayText(text: string): string[] {
  const whole = hostFromDisplayText(text);
  if (whole) return [whole];
  const hosts = new Set<string>();
  for (const match of text.matchAll(/\b(?:https?:\/\/|www\.)[^\s<>"'()]+/giu)) {
    const host = hostFromDisplayText(match[0]);
    if (host) hosts.add(host);
    if (hosts.size >= 3) break;
  }
  return [...hosts];
}

/** Top-level names reserved for documentation and testing by RFC 2606. */
const RESERVED_TLDS: ReadonlySet<string> = new Set(['example', 'test', 'invalid', 'localhost']);

/** Extracts a host from link text that looks like a web address ("www.example.com/login"). */
export function hostFromDisplayText(text: string): string | null {
  const trimmed = text.trim();
  // Bound the input before running anchored regexes over it.
  if (!trimmed || trimmed.length > 2048 || /\s/u.test(trimmed)) return null;
  const candidate = trimmed.replace(/^[<(["']+|[>)\]"'.,;:!?]+$/gu, '');
  if (!candidate) return null;
  const hasScheme = /^[a-z][a-z0-9+.-]{0,31}:\/\//iu.test(candidate);
  const withScheme = hasScheme ? candidate : `http://${candidate}`;
  if (!/^https?:\/\//iu.test(withScheme)) return null;
  try {
    const url = new URL(withScheme);
    const info = analyzeHost(url.hostname);
    if (info.isIp) return url.hostname;
    // Require a real public suffix (or an RFC 2606 reserved one) so ordinary
    // words with a dot, such as "file.txt", are not mistaken for domains.
    const parsed = parseHost(url.hostname, { allowPrivateDomains: true });
    if (!parsed.domain || !url.hostname.includes('.')) return null;
    const tld = url.hostname.split('.').pop() ?? '';
    if (!parsed.isIcann && !RESERVED_TLDS.has(tld)) return null;
    // "README.md" or "setup.py" names a file, not a website.
    if (!hasScheme && !/^www\./iu.test(candidate) && FILE_EXTENSION_TLDS.has(tld)) return null;
    return url.hostname;
  } catch {
    return null;
  }
}
