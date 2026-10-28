import { scanHtml } from './html';
import type { ArchiveEntry, AttachmentContents } from './types';
import { extractTextUrls, type UrlOccurrence } from './urls';

/**
 * Static inspection of attachment bytes. Everything here reads bytes as data:
 * archive directories are listed but never decompressed or extracted, PDFs are
 * searched for keywords but never rendered, and HTML is parsed into an inert
 * tree by parse5 but never displayed or run.
 */

const MAX_ARCHIVE_ENTRIES = 500;
const MAX_SCAN_BYTES = 8 * 1024 * 1024;
const MAX_LINKS_PER_ATTACHMENT = 200;

export interface InspectionResult {
  contents: AttachmentContents;
  occurrences: UrlOccurrence[];
}

function u16(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] ?? 0) | ((bytes[offset + 1] ?? 0) << 8);
}

function u32(bytes: Uint8Array, offset: number): number {
  return (u16(bytes, offset) | (u16(bytes, offset + 2) << 16)) >>> 0;
}

function decodeName(bytes: Uint8Array, utf8: boolean): string {
  return new TextDecoder(utf8 ? 'utf-8' : 'latin1').decode(bytes);
}

export interface RawZipEntry {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  encrypted: boolean;
}

/**
 * Lists ZIP entries from the central directory, falling back to walking local
 * file headers when the directory is missing (truncated or crafted archives).
 * Only the metadata is read; entry data is never decompressed.
 */
export function listZipEntries(bytes: Uint8Array): { entries: RawZipEntry[]; total: number } {
  const entries: RawZipEntry[] = [];
  // The end-of-central-directory record sits within the last 64 KiB + 22 bytes.
  const searchStart = Math.max(0, bytes.length - 65_557);
  let eocd = -1;
  for (let i = bytes.length - 22; i >= searchStart; i -= 1) {
    if (u32(bytes, i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd >= 0) {
    const total = u16(bytes, eocd + 10);
    let offset = u32(bytes, eocd + 16);
    for (let n = 0; n < total && entries.length < MAX_ARCHIVE_ENTRIES; n += 1) {
      if (offset + 46 > bytes.length || u32(bytes, offset) !== 0x02014b50) break;
      const flags = u16(bytes, offset + 8);
      const nameLength = u16(bytes, offset + 28);
      const extraLength = u16(bytes, offset + 30);
      const commentLength = u16(bytes, offset + 32);
      entries.push({
        name: decodeName(
          bytes.subarray(offset + 46, offset + 46 + nameLength),
          (flags & 0x800) !== 0,
        ),
        compressedSize: u32(bytes, offset + 20),
        uncompressedSize: u32(bytes, offset + 24),
        encrypted: (flags & 0x1) !== 0,
      });
      offset += 46 + nameLength + extraLength + commentLength;
    }
    if (entries.length > 0) return { entries, total };
  }

  let offset = 0;
  while (
    offset + 30 <= bytes.length &&
    u32(bytes, offset) === 0x04034b50 &&
    entries.length < MAX_ARCHIVE_ENTRIES
  ) {
    const flags = u16(bytes, offset + 6);
    const compressedSize = u32(bytes, offset + 18);
    const nameLength = u16(bytes, offset + 26);
    const extraLength = u16(bytes, offset + 28);
    entries.push({
      name: decodeName(
        bytes.subarray(offset + 30, offset + 30 + nameLength),
        (flags & 0x800) !== 0,
      ),
      compressedSize,
      uncompressedSize: u32(bytes, offset + 22),
      encrypted: (flags & 0x1) !== 0,
    });
    // With a data descriptor the size is unknown here, so the walk cannot continue safely.
    if ((flags & 0x8) !== 0 || compressedSize === 0) break;
    offset += 30 + nameLength + extraLength + compressedSize;
  }
  return { entries, total: entries.length };
}

function latin1(bytes: Uint8Array): string {
  return new TextDecoder('latin1').decode(bytes.subarray(0, MAX_SCAN_BYTES));
}

function utf8(bytes: Uint8Array): string {
  return new TextDecoder('utf-8').decode(bytes.subarray(0, MAX_SCAN_BYTES));
}

/** UTF-16LE encoding of an ASCII string, as used for OLE directory entry names. */
function utf16le(value: string): string {
  return [...value].map((char) => `${char}\u0000`).join('');
}

/** True when an OLE compound file (legacy .doc/.xls/.ppt) holds a VBA project. */
export function oleHasVbaProject(bytes: Uint8Array): boolean {
  const text = latin1(bytes);
  return text.includes(utf16le('_VBA_PROJECT')) || text.includes(utf16le('VBA_PROJECT_CUR'));
}

const PDF_KEYWORDS = [
  'JavaScript',
  'JS',
  'Launch',
  'EmbeddedFile',
  'OpenAction',
  'AA',
  'AcroForm',
  'SubmitForm',
  'XFA',
  'RichMedia',
  'URI',
  'ObjStm',
] as const;
/** Keywords that, when present, are reported as active content. */
export const PDF_ACTIVE_KEYWORDS: ReadonlySet<string> = new Set([
  'JavaScript',
  'JS',
  'Launch',
  'EmbeddedFile',
  'SubmitForm',
  'XFA',
  'RichMedia',
]);

/**
 * pdfid-style keyword census. PDF names may hide letters as #xx escapes
 * ("/J#61vaScript"), so names are decoded before counting.
 */
export function pdfKeywordCounts(text: string): { keyword: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const match of text.matchAll(/\/([A-Za-z0-9#]{2,40})/gu)) {
    const name = (match[1] ?? '').replace(/#([0-9a-f]{2})/giu, (_, hex: string) =>
      String.fromCharCode(parseInt(hex, 16)),
    );
    if ((PDF_KEYWORDS as readonly string[]).includes(name))
      counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  return PDF_KEYWORDS.filter((keyword) => counts.has(keyword)).map((keyword) => ({
    keyword,
    count: counts.get(keyword) ?? 0,
  }));
}

/** File names declared by PDF file specifications (/F or /UF), e.g. "factur-x.xml". */
export function pdfEmbeddedFileNames(text: string): string[] {
  const names = new Set<string>();
  for (const match of text.matchAll(/\/U?F\s{0,8}\(([^()\\]{1,255})\)/gu)) {
    if (match[1]) names.add(match[1].trim());
    if (names.size >= 50) break;
  }
  return [...names];
}

/** URI actions written as literal or hex strings in uncompressed PDF objects. */
export function pdfUris(text: string): string[] {
  const out: string[] = [];
  const literal = /\/URI\s*\(((?:\\.|[^\\)]){1,4096})\)/gu;
  for (const match of text.matchAll(literal)) {
    out.push((match[1] ?? '').replace(/\\(.)/gu, '$1'));
    if (out.length >= MAX_LINKS_PER_ATTACHMENT) return out;
  }
  for (const match of text.matchAll(/\/URI\s*<([0-9a-fA-F\s]{2,8192})>/gu)) {
    const hex = (match[1] ?? '').replace(/\s+/gu, '');
    let decoded = '';
    for (let i = 0; i + 1 < hex.length; i += 2)
      decoded += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
    out.push(decoded);
    if (out.length >= MAX_LINKS_PER_ATTACHMENT) break;
  }
  return out;
}

/** Linear scan for a run of base64 characters at least `length` long. */
function hasLongBase64Run(text: string, length: number): boolean {
  let run = 0;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    const base64 =
      (code >= 65 && code <= 90) ||
      (code >= 97 && code <= 122) ||
      (code >= 48 && code <= 57) ||
      code === 43 ||
      code === 47;
    run = base64 ? run + 1 : 0;
    if (run >= length) return true;
  }
  return false;
}

/** Signs that a script assembles and saves a file in the browser ("HTML smuggling"). */
export function looksLikeHtmlSmuggling(scriptText: string, html: string): boolean {
  const apis = [
    /\batob\s*\(/u,
    /\bnew\s+Blob\s*\(/u,
    /\bmsSaveOrOpenBlob\b/u,
    /\bcreateObjectURL\s*\(/u,
    /\.download\s*=/u,
    /\bnew\s+Uint8Array\s*\(/u,
    /\bcharCodeAt\s*\(/u,
  ].filter((pattern) => pattern.test(scriptText)).length;
  return apis >= 2 && hasLongBase64Run(html, 4000);
}

/** Target URL of a Windows Internet Shortcut (.url) or macOS .webloc file. */
export function shortcutTargets(text: string): string[] {
  const urls: string[] = [];
  // [ \t] rather than \s: with the m flag, \s could span lines and backtrack quadratically.
  for (const match of text.matchAll(/^[ \t]*URL[ \t]*=[ \t]*(\S{1,4096})[ \t]*\r?$/gimu)) {
    if (match[1]) urls.push(match[1]);
  }
  for (const match of text.matchAll(/<key>URL<\/key>\s{0,64}<string>([^<]{1,4096})<\/string>/giu)) {
    if (match[1]) urls.push(match[1].trim());
  }
  return urls.slice(0, 10);
}

/** Declared types of HTML content, including the AMP for Email alternative. */
const HTML_TYPES: ReadonlySet<string> = new Set(['text/html', 'image/svg+xml', 'text/x-amp-html']);
const TEXT_TYPES = /^text\/(?:plain|calendar|csv|x-vcard|vcard)\b/u;
const TEXT_EXTENSIONS: ReadonlySet<string> = new Set(['txt', 'ics', 'ical', 'csv', 'vcf', 'eml']);
const HTML_EXTENSIONS: ReadonlySet<string> = new Set([
  'htm',
  'html',
  'shtml',
  'xhtml',
  'xht',
  'svg',
  'hta',
  'mht',
  'mhtml',
]);
const OOXML_EXTENSIONS: ReadonlySet<string> = new Set([
  'docx',
  'docm',
  'dotx',
  'dotm',
  'xlsx',
  'xlsm',
  'xltx',
  'xltm',
  'xlsb',
  'xlam',
  'pptx',
  'pptm',
  'potm',
  'ppsm',
  'ppsx',
  'sldm',
  'ppam',
]);

export interface InspectOptions {
  bytes: Uint8Array;
  name: string;
  extension: string | null;
  declaredType: string;
  signature: string | null;
  /** Classifies an archive entry name; returns a short risk description or null. */
  classifyEntry: (name: string) => string | null;
}

export function emptyContents(): AttachmentContents {
  return {
    archive: null,
    pdfKeywords: null,
    pdfEmbeddedFiles: null,
    html: null,
    macros: false,
    links: 0,
  };
}

export function inspectAttachment({
  bytes,
  name,
  extension,
  declaredType,
  signature,
  classifyEntry,
}: InspectOptions): InspectionResult {
  const contents = emptyContents();
  const occurrences: UrlOccurrence[] = [];
  const addLinks = (kind: UrlOccurrence['kind'], urls: string[], text?: string) => {
    for (const url of urls.slice(0, MAX_LINKS_PER_ATTACHMENT - occurrences.length)) {
      occurrences.push(
        text === undefined
          ? { kind, url, attachment: name }
          : { kind, url, text, attachment: name },
      );
    }
  };

  if (signature === 'zip') {
    const { entries, total } = listZipEntries(bytes);
    const names = entries.map((entry) => entry.name);
    const isOfficeOpenXml =
      names.includes('[Content_Types].xml') ||
      (extension !== null && OOXML_EXTENSIONS.has(extension));
    if (isOfficeOpenXml) {
      contents.macros = names.some((entryName) => /(?:^|\/)vbaProject\.bin$/iu.test(entryName));
    } else {
      const listed: ArchiveEntry[] = entries.map((entry) => ({
        name: entry.name,
        sizeBytes: entry.uncompressedSize,
        encrypted: entry.encrypted,
        risk: entry.name.endsWith('/') ? null : classifyEntry(entry.name),
      }));
      contents.archive = { entries: listed, totalEntries: total, truncated: total > listed.length };
    }
  } else if (signature === 'ole') {
    contents.macros = oleHasVbaProject(bytes);
  } else if (
    signature === 'html' ||
    signature === 'svg' ||
    (signature === null &&
      ((extension !== null && HTML_EXTENSIONS.has(extension)) || HTML_TYPES.has(declaredType)))
  ) {
    const html = utf8(bytes);
    const scan = scanHtml(html, MAX_SCAN_BYTES, MAX_LINKS_PER_ATTACHMENT);
    contents.html = {
      forms: scan.summary.forms.length,
      passwordFields: scan.summary.passwordInputs,
      scripts: scan.summary.scripts,
      smuggling: looksLikeHtmlSmuggling(scan.scriptText, html),
    };
    for (const occurrence of scan.occurrences) {
      if (occurrences.length >= MAX_LINKS_PER_ATTACHMENT) break;
      occurrences.push({ ...occurrence, attachment: name });
    }
    addLinks('html-text', extractTextUrls(scan.unlinkedText, MAX_LINKS_PER_ATTACHMENT));
  } else if (signature === 'pdf' || (signature === null && extension === 'pdf')) {
    const text = latin1(bytes);
    contents.pdfKeywords = pdfKeywordCounts(text);
    if (contents.pdfKeywords.some((entry) => entry.keyword === 'EmbeddedFile')) {
      contents.pdfEmbeddedFiles = pdfEmbeddedFileNames(text);
    }
    addLinks('pdf-link', pdfUris(text));
  } else if (extension === 'url' || extension === 'website' || extension === 'webloc') {
    addLinks('shortcut', shortcutTargets(utf8(bytes)));
  } else if (
    TEXT_TYPES.test(declaredType) ||
    (extension !== null && TEXT_EXTENSIONS.has(extension) && extension !== 'eml')
  ) {
    addLinks(
      'plain-text',
      extractTextUrls(utf8(bytes).replace(/\r?\n[ \t]/gu, ''), MAX_LINKS_PER_ATTACHMENT),
    );
  }

  contents.links = occurrences.length;
  return { contents, occurrences };
}
