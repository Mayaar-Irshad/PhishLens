import type { Attachment } from 'postal-mime';
import { emptyContents, inspectAttachment, PDF_ACTIVE_KEYWORDS } from './attachment-content';
import { flag } from './findings';
import { detectSignature, isEncryptedZip, SIGNATURE_LABELS } from './signatures';
import { hasSpoofingCharacters, revealHiddenCharacters, simulateRightToLeftOverride } from './text';
import type { ArchiveEntry, AttachmentRecord, FileSignatureKind, UrlFlag } from './types';
import type { UrlOccurrence } from './urls';

/**
 * Attachment heuristics. Attachments are never opened, rendered, unpacked or
 * executed. The only content access is reading the first bytes to compare the
 * file signature ("magic number") with the claimed type, and hashing the bytes
 * so the user can look the file up manually.
 */

const EXECUTABLE_EXTENSIONS: ReadonlySet<string> = new Set([
  'exe',
  'scr',
  'com',
  'pif',
  'cpl',
  'msi',
  'msp',
  'mst',
  'bat',
  'cmd',
  'vb',
  'vbs',
  'vbe',
  'js',
  'jse',
  'ws',
  'wsf',
  'wsh',
  'wsc',
  'ps1',
  'ps1xml',
  'ps2',
  'psc1',
  'psm1',
  'psd1',
  'hta',
  'jar',
  'lnk',
  'reg',
  'inf',
  'scf',
  'dll',
  'sys',
  'application',
  'appref-ms',
  'gadget',
  'msc',
  'msh',
  'sct',
  'url',
  'website',
  'library-ms',
  'search-ms',
  'searchconnector-ms',
  'settingcontent-ms',
  'xll',
  'chm',
  'hlp',
  'appx',
  'appxbundle',
  'msix',
  'msixbundle',
  'sh',
  'command',
  'pkg',
  'apk',
  'iqy',
  'slk',
  'xbap',
]);
const DISK_IMAGE_EXTENSIONS: ReadonlySet<string> = new Set([
  'iso',
  'img',
  'vhd',
  'vhdx',
  'dmg',
  'udf',
]);
const HTML_EXTENSIONS: ReadonlySet<string> = new Set([
  'htm',
  'html',
  'shtml',
  'xhtml',
  'xht',
  'mht',
  'mhtml',
  'svg',
  'svgz',
  'hta',
]);
const MACRO_EXTENSIONS: ReadonlySet<string> = new Set([
  'docm',
  'dotm',
  'xlsm',
  'xltm',
  'xlsb',
  'xlam',
  'pptm',
  'potm',
  'ppsm',
  'sldm',
  'ppam',
]);
const ONENOTE_EXTENSIONS: ReadonlySet<string> = new Set(['one', 'onepkg']);
const ARCHIVE_EXTENSIONS: ReadonlySet<string> = new Set([
  'zip',
  'zipx',
  'rar',
  '7z',
  'gz',
  'tgz',
  'bz2',
  'tbz',
  'xz',
  'txz',
  'tar',
  'ace',
  'arj',
  'lzh',
  'lha',
  'z',
  'uue',
  'xxe',
  'r00',
  'r01',
  'cab',
]);
/** Extensions attackers put in front of a risky one to look harmless. */
const DECOY_EXTENSIONS: ReadonlySet<string> = new Set([
  'pdf',
  'doc',
  'docx',
  'xls',
  'xlsx',
  'ppt',
  'pptx',
  'txt',
  'rtf',
  'csv',
  'odt',
  'jpg',
  'jpeg',
  'png',
  'gif',
  'bmp',
  'tif',
  'tiff',
  'mp3',
  'mp4',
  'mov',
  'avi',
  'wav',
  'wmv',
  'zip',
  'eml',
  'msg',
  'html',
  'htm',
]);

export function isRiskyFinalExtension(extension: string): boolean {
  return (
    EXECUTABLE_EXTENSIONS.has(extension) ||
    DISK_IMAGE_EXTENSIONS.has(extension) ||
    HTML_EXTENSIONS.has(extension)
  );
}

export { detectSignature, isEncryptedZip } from './signatures';

/** Signature kinds that are consistent with each extension. */
const EXPECTED_SIGNATURES: Record<string, readonly FileSignatureKind[]> = {
  pdf: ['pdf'],
  docx: ['zip'],
  xlsx: ['zip'],
  pptx: ['zip'],
  docm: ['zip'],
  xlsm: ['zip'],
  pptm: ['zip'],
  odt: ['zip'],
  ods: ['zip'],
  zip: ['zip'],
  jar: ['zip', 'macho-or-java'],
  apk: ['zip'],
  doc: ['ole', 'rtf', 'html'],
  xls: ['ole', 'html'],
  ppt: ['ole'],
  msg: ['ole'],
  msi: ['ole'],
  exe: ['pe-executable'],
  dll: ['pe-executable'],
  scr: ['pe-executable'],
  sys: ['pe-executable'],
  png: ['png'],
  jpg: ['jpeg'],
  jpeg: ['jpeg'],
  gif: ['gif'],
  webp: ['webp'],
  rar: ['rar'],
  '7z': ['7z'],
  gz: ['gzip'],
  tgz: ['gzip'],
  cab: ['cab'],
  iso: ['iso'],
  vhdx: ['vhdx'],
  lnk: ['lnk'],
  one: ['onenote'],
  rtf: ['rtf'],
  html: ['html', 'svg'],
  htm: ['html', 'svg'],
  svg: ['svg'],
  eml: ['email'],
};

const EXECUTABLE_SIGNATURES: ReadonlySet<FileSignatureKind> = new Set([
  'pe-executable',
  'elf-executable',
  'macho-or-java',
]);

/** MIME types that are consistent with each extension (prefix match). */
const EXPECTED_TYPES: Record<string, readonly string[]> = {
  pdf: ['application/pdf'],
  doc: ['application/msword'],
  docx: ['application/vnd.openxmlformats-officedocument.wordprocessingml'],
  xls: ['application/vnd.ms-excel'],
  xlsx: ['application/vnd.openxmlformats-officedocument.spreadsheetml'],
  ppt: ['application/vnd.ms-powerpoint'],
  pptx: ['application/vnd.openxmlformats-officedocument.presentationml'],
  png: ['image/png'],
  jpg: ['image/jpeg', 'image/jpg', 'image/pjpeg'],
  jpeg: ['image/jpeg', 'image/jpg', 'image/pjpeg'],
  gif: ['image/gif'],
  txt: ['text/plain'],
  csv: ['text/csv', 'text/plain', 'application/vnd.ms-excel'],
  html: ['text/html'],
  htm: ['text/html'],
  zip: ['application/zip', 'application/x-zip', 'application/x-zip-compressed'],
  ics: ['text/calendar', 'application/ics'],
};
/** Declared types that carry no information and never count as a mismatch. */
const GENERIC_TYPES: ReadonlySet<string> = new Set([
  'application/octet-stream',
  'application/unknown',
  'application/x-download',
  'application/force-download',
  'binary/octet-stream',
]);

// --------------------------------------------------------------- naming

export interface FilenameParts {
  /** Name with trailing dots and spaces removed, as Windows would treat it. */
  effective: string;
  extension: string | null;
  previousExtension: string | null;
  /** True when long runs of spaces or underscores pad the name before the extension. */
  padded: boolean;
}

const MAX_FILENAME_CHARS = 1024;

/** True when the name before the extension ends in a long run of spaces or underscores. */
function isPadded(stem: string): boolean {
  let spaces = 0;
  let underscores = 0;
  for (let i = stem.length - 1; i >= 0; i -= 1) {
    const char = stem[i] ?? '';
    if (/\s/u.test(char) && underscores === 0) spaces += 1;
    else if (char === '_' && spaces === 0) underscores += 1;
    else break;
  }
  return spaces >= 3 || underscores >= 6;
}

export function filenameParts(filename: string): FilenameParts {
  // Strip characters that do not change the effective name but hide it.
  const visible = filename
    .slice(0, MAX_FILENAME_CHARS)
    .replace(/[\u200B-\u200D\u2060\uFEFF\u202A-\u202E\u2066-\u2069]/gu, '');
  // Trailing dots and spaces are dropped by Windows. A manual scan avoids the
  // quadratic backtracking of /[.\s]+$/ on long runs of dots or spaces.
  let end = visible.length;
  while (end > 0 && /[.\s]/u.test(visible[end - 1] ?? '')) end -= 1;
  const effective = visible.slice(0, end);
  const base = effective.split(/[\\/]/u).pop() ?? effective;
  const parts = base.split('.');
  const extension = parts.length > 1 ? (parts.at(-1)?.trim().toLowerCase() ?? null) : null;
  const previousExtension = parts.length > 2 ? (parts.at(-2)?.trim().toLowerCase() ?? null) : null;
  return {
    effective,
    extension: extension || null,
    previousExtension: previousExtension || null,
    padded: isPadded(parts.length > 1 ? parts.slice(0, -1).join('.') : ''),
  };
}

// ------------------------------------------------------------- analysis

function bytesOf(content: Attachment['content']): Uint8Array {
  if (typeof content === 'string') return new TextEncoder().encode(content);
  if (content instanceof Uint8Array) return content;
  return new Uint8Array(content);
}

export async function sha256Hex(bytes: Uint8Array): Promise<string | null> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return null;
  try {
    const digest = await subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>);
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  } catch {
    return null;
  }
}

/** Classifies a file name found inside an archive. Returns a short risk label or null. */
export function classifyArchiveEntry(name: string): string | null {
  const parts = filenameParts(name);
  const extension = parts.extension;
  if (!extension) return null;
  if (hasSpoofingCharacters(name)) return 'hidden direction-changing characters';
  const previous = parts.previousExtension;
  if (
    previous &&
    DECOY_EXTENSIONS.has(previous) &&
    isRiskyFinalExtension(extension) &&
    previous !== extension
  ) {
    return `double extension (.${previous}.${extension})`;
  }
  if (EXECUTABLE_EXTENSIONS.has(extension)) return `executable or script (.${extension})`;
  if (DISK_IMAGE_EXTENSIONS.has(extension)) return `disk image (.${extension})`;
  if (HTML_EXTENSIONS.has(extension)) return `HTML page (.${extension})`;
  if (MACRO_EXTENSIONS.has(extension)) return `macro-enabled document (.${extension})`;
  if (ONENOTE_EXTENSIONS.has(extension)) return `OneNote file (.${extension})`;
  return null;
}

const ACTIVE_ENTRY_RISK = /^(?:HTML page|macro-enabled document|OneNote file)/u;

export interface AnalyzedAttachment {
  record: AttachmentRecord;
  /** Links found inside the attachment, to be analysed with the message's links. */
  links: UrlOccurrence[];
  /** Raw bytes for attached messages, so the UI can offer to analyze them. */
  embeddedMessage: Uint8Array | null;
}

export async function analyzeAttachment(
  attachment: Attachment,
  index: number,
): Promise<AnalyzedAttachment> {
  const bytes = bytesOf(attachment.content);
  const filename = attachment.filename;
  const declaredType = attachment.mimeType.trim().toLowerCase();
  const parts = filename ? filenameParts(filename) : null;
  const extension = parts?.extension ?? null;
  const signatureKind = detectSignature(bytes.subarray(0, 0x9010));
  const isEmbeddedMessage =
    declaredType === 'message/rfc822' ||
    extension === 'eml' ||
    (signatureKind === 'email' && !extension);
  const inspection = isEmbeddedMessage
    ? { contents: emptyContents(), occurrences: [] }
    : inspectAttachment({
        bytes,
        name: filename ?? `attachment ${index + 1}`,
        extension,
        declaredType,
        signature: signatureKind,
        classifyEntry: classifyArchiveEntry,
      });
  const { contents } = inspection;
  const encryptedArchive =
    isEncryptedZip(bytes) || (contents.archive?.entries.some((entry) => entry.encrypted) ?? false);
  const flags: UrlFlag[] = [];
  const shown = filename ? `"${revealHiddenCharacters(filename)}"` : 'Unnamed attachment';

  if (filename && hasSpoofingCharacters(filename)) {
    const displayed = simulateRightToLeftOverride(filename);
    flags.push(
      flag(
        'ATTACHMENT_BIDI_FILENAME',
        displayed
          ? `${shown} contains a right-to-left override and may display as "${displayed}"`
          : `${shown} contains hidden or direction-changing characters`,
      ),
    );
  }
  if (extension) {
    const previous = parts?.previousExtension ?? null;
    if (
      previous &&
      DECOY_EXTENSIONS.has(previous) &&
      isRiskyFinalExtension(extension) &&
      previous !== extension
    ) {
      flags.push(
        flag(
          'ATTACHMENT_DOUBLE_EXTENSION',
          `${shown} looks like .${previous} but ends in .${extension}`,
        ),
      );
    } else if (parts?.padded && isRiskyFinalExtension(extension)) {
      flags.push(
        flag(
          'ATTACHMENT_DOUBLE_EXTENSION',
          `${shown} pads the name with spaces before .${extension}`,
        ),
      );
    }
    if (EXECUTABLE_EXTENSIONS.has(extension)) {
      flags.push(flag('ATTACHMENT_EXECUTABLE', `${shown} has the extension .${extension}`));
    } else if (DISK_IMAGE_EXTENSIONS.has(extension)) {
      flags.push(flag('ATTACHMENT_DISK_IMAGE', `${shown} has the extension .${extension}`));
    } else if (HTML_EXTENSIONS.has(extension)) {
      flags.push(flag('ATTACHMENT_HTML', `${shown} has the extension .${extension}`));
    } else if (MACRO_EXTENSIONS.has(extension)) {
      flags.push(flag('ATTACHMENT_MACRO_DOCUMENT', `${shown} has the extension .${extension}`));
    } else if (ONENOTE_EXTENSIONS.has(extension)) {
      flags.push(flag('ATTACHMENT_ONENOTE', `${shown} has the extension .${extension}`));
    } else if (ARCHIVE_EXTENSIONS.has(extension)) {
      flags.push(flag('ATTACHMENT_ARCHIVE', `${shown} has the extension .${extension}`));
    }
  } else if (
    (signatureKind === 'html' || signatureKind === 'svg') &&
    declaredType !== 'text/x-amp-html'
  ) {
    flags.push(flag('ATTACHMENT_HTML', `${shown} contains ${signatureKind.toUpperCase()} content`));
  }

  if (encryptedArchive)
    flags.push(flag('ATTACHMENT_ENCRYPTED_ARCHIVE', `${shown} is an encrypted ZIP archive`));

  if (signatureKind) {
    const expected = extension ? EXPECTED_SIGNATURES[extension] : undefined;
    const executableExtension = extension !== null && EXECUTABLE_EXTENSIONS.has(extension);
    if (EXECUTABLE_SIGNATURES.has(signatureKind) && !executableExtension) {
      flags.push(
        flag(
          'ATTACHMENT_DISGUISED_EXECUTABLE',
          `${shown} starts with the signature of a ${SIGNATURE_LABELS[signatureKind]}`,
        ),
      );
    } else if (expected && !expected.includes(signatureKind)) {
      flags.push(
        flag(
          'ATTACHMENT_SIGNATURE_MISMATCH',
          `${shown} is named .${extension ?? ''} but its content looks like a ${SIGNATURE_LABELS[signatureKind]}`,
        ),
      );
    }
  }

  if (extension && !GENERIC_TYPES.has(declaredType)) {
    const expectedTypes = EXPECTED_TYPES[extension];
    const executableType =
      /x-msdownload|x-msdos-program|x-executable|x-dosexec|vnd\.microsoft\.portable-executable/u.test(
        declaredType,
      );
    if (
      (expectedTypes && !expectedTypes.some((type) => declaredType.startsWith(type))) ||
      (executableType && !EXECUTABLE_EXTENSIONS.has(extension))
    ) {
      flags.push(
        flag(
          'ATTACHMENT_TYPE_MISMATCH',
          `${shown} is declared as ${declaredType || 'no type'}, which does not match .${extension}`,
        ),
      );
    }
  }

  if (contents.archive) {
    const risky = contents.archive.entries.filter((entry) => entry.risk !== null);
    const executable = risky.filter((entry) => !ACTIVE_ENTRY_RISK.test(entry.risk ?? ''));
    const active = risky.filter((entry) => ACTIVE_ENTRY_RISK.test(entry.risk ?? ''));
    const describe = (entries: ArchiveEntry[]) =>
      entries
        .slice(0, 5)
        .map((entry) => `"${revealHiddenCharacters(entry.name)}" (${entry.risk ?? ''})`)
        .join(', ') + (entries.length > 5 ? ` and ${entries.length - 5} more` : '');
    if (executable.length > 0) {
      flags.push(
        flag('ATTACHMENT_ARCHIVE_EXECUTABLE', `${shown} contains ${describe(executable)}`),
      );
    }
    if (active.length > 0) {
      flags.push(
        flag('ATTACHMENT_ARCHIVE_ACTIVE_CONTENT', `${shown} contains ${describe(active)}`),
      );
    }
  }
  if (contents.macros && !flags.some((entry) => entry.ruleId === 'ATTACHMENT_MACRO_DOCUMENT')) {
    flags.push(flag('ATTACHMENT_MACRO_DOCUMENT', `${shown} contains a VBA macro project`));
  }
  // E-invoices (Factur-X, ZUGFeRD, XRechnung) embed an XML file; data-only attachments are not active content.
  const embeddedDataOnly =
    (contents.pdfEmbeddedFiles?.length ?? 0) > 0 &&
    (contents.pdfEmbeddedFiles ?? []).every((name) =>
      /\.(?:xml|pdf|txt|csv|json|png|jpe?g|gif)$/iu.test(name),
    );
  const activePdf = (contents.pdfKeywords ?? []).filter(
    (entry) =>
      PDF_ACTIVE_KEYWORDS.has(entry.keyword) &&
      !(entry.keyword === 'EmbeddedFile' && embeddedDataOnly),
  );
  if (activePdf.length > 0) {
    flags.push(
      flag(
        'ATTACHMENT_PDF_ACTIVE',
        `${shown} declares ${activePdf.map((entry) => `/${entry.keyword} (${entry.count})`).join(', ')}`,
      ),
    );
  }
  if (contents.html && contents.html.passwordFields > 0) {
    flags.push(
      flag(
        'ATTACHMENT_CREDENTIAL_FORM',
        `${shown} contains ${contents.html.passwordFields} password field${contents.html.passwordFields === 1 ? '' : 's'}`,
      ),
    );
  }
  if (contents.html?.smuggling) {
    flags.push(
      flag('ATTACHMENT_HTML_SMUGGLING', `${shown} decodes a large embedded payload in script`),
    );
  }

  if (isEmbeddedMessage)
    flags.push(flag('ATTACHMENT_EMBEDDED_MESSAGE', `${shown} is an attached email message`));

  return {
    record: {
      index,
      filename,
      extension,
      declaredType,
      disposition: attachment.disposition,
      sizeBytes: bytes.byteLength,
      sha256: await sha256Hex(bytes),
      signature: signatureKind
        ? { kind: signatureKind, label: SIGNATURE_LABELS[signatureKind] }
        : null,
      encryptedArchive,
      inline: attachment.disposition === 'inline' || attachment.related === true,
      isEmbeddedMessage,
      contents,
      flags,
    },
    links: inspection.occurrences,
    embeddedMessage: isEmbeddedMessage ? bytes : null,
  };
}
