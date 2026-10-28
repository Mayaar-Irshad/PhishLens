import type { FileSignatureKind } from './types';

/**
 * File-format detection from leading bytes ("magic numbers"). Dependency-free
 * so the main thread can use it for input validation without loading the
 * analysis libraries.
 */

export const SIGNATURE_LABELS: Record<FileSignatureKind, string> = {
  'pe-executable': 'Windows executable (PE, "MZ")',
  'elf-executable': 'Linux executable (ELF)',
  'macho-or-java': 'macOS executable (Mach-O) or Java class',
  pdf: 'PDF document',
  zip: 'ZIP container (also used by .docx, .xlsx, .jar, .apk)',
  ole: 'OLE compound file (legacy Office, .msg, .msi)',
  rar: 'RAR archive',
  '7z': '7-Zip archive',
  gzip: 'gzip archive',
  cab: 'Windows cabinet archive',
  iso: 'ISO 9660 disk image',
  vhdx: 'VHDX virtual disk',
  lnk: 'Windows shortcut (LNK)',
  onenote: 'OneNote section',
  png: 'PNG image',
  jpeg: 'JPEG image',
  gif: 'GIF image',
  webp: 'WebP image',
  rtf: 'Rich Text Format document',
  html: 'HTML document',
  svg: 'SVG image (can contain scripts)',
  email: 'Email message',
};

function startsWith(bytes: Uint8Array, signature: readonly number[], offset = 0): boolean {
  if (bytes.length < offset + signature.length) return false;
  return signature.every((byte, i) => bytes[offset + i] === byte);
}

function ascii(bytes: Uint8Array, start: number, length: number): string {
  let out = '';
  for (let i = start; i < Math.min(bytes.length, start + length); i += 1)
    out += String.fromCharCode(bytes[i] ?? 0);
  return out;
}

const ONENOTE_GUID = [
  0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d, 0xae, 0xb1, 0x53, 0x78, 0xd0, 0x29, 0x96, 0xd3,
];
const LNK_HEADER = [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00];

/**
 * Drops leading whitespace and HTML comments, so a page that starts with, for
 * example, `<!-- saved from url=(0014)about:internet -->` is still recognised.
 */
function skipLeadingComments(text: string): string {
  let rest = text.trimStart();
  for (let i = 0; i < 10 && rest.startsWith('<!--'); i += 1) {
    const end = rest.indexOf('-->');
    if (end === -1) return rest;
    rest = rest.slice(end + 3).trimStart();
  }
  return rest;
}

/** Identifies a file format from its leading bytes. Never interprets the content further. */
export function detectSignature(bytes: Uint8Array): FileSignatureKind | null {
  if (startsWith(bytes, [0x4d, 0x5a])) return 'pe-executable';
  if (startsWith(bytes, [0x7f, 0x45, 0x4c, 0x46])) return 'elf-executable';
  if (
    startsWith(bytes, [0xcf, 0xfa, 0xed, 0xfe]) ||
    startsWith(bytes, [0xce, 0xfa, 0xed, 0xfe]) ||
    startsWith(bytes, [0xfe, 0xed, 0xfa, 0xcf]) ||
    startsWith(bytes, [0xca, 0xfe, 0xba, 0xbe])
  ) {
    return 'macho-or-java';
  }
  if (startsWith(bytes, [0x25, 0x50, 0x44, 0x46, 0x2d])) return 'pdf';
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04]) || startsWith(bytes, [0x50, 0x4b, 0x05, 0x06]))
    return 'zip';
  if (startsWith(bytes, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return 'ole';
  if (startsWith(bytes, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07])) return 'rar';
  if (startsWith(bytes, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return '7z';
  if (startsWith(bytes, [0x1f, 0x8b])) return 'gzip';
  if (startsWith(bytes, [0x4d, 0x53, 0x43, 0x46])) return 'cab';
  if (startsWith(bytes, LNK_HEADER)) return 'lnk';
  if (startsWith(bytes, ONENOTE_GUID)) return 'onenote';
  if (ascii(bytes, 0, 8) === 'vhdxfile') return 'vhdx';
  if ([0x8001, 0x8801, 0x9001].some((offset) => ascii(bytes, offset, 5) === 'CD001')) return 'iso';
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47])) return 'png';
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return 'jpeg';
  if (ascii(bytes, 0, 4) === 'GIF8') return 'gif';
  if (ascii(bytes, 0, 4) === 'RIFF' && ascii(bytes, 8, 4) === 'WEBP') return 'webp';
  if (ascii(bytes, 0, 5) === '{\\rtf') return 'rtf';

  const head = skipLeadingComments(
    ascii(bytes, 0, 2048)
      .replace(/^\uFEFF|^\xEF\xBB\xBF/u, '')
      .toLowerCase(),
  );
  if (head.startsWith('<svg') || (head.startsWith('<?xml') && head.includes('<svg'))) return 'svg';
  if (
    /^(?:<!doctype html|<html|<head|<body|<script|<meta|<iframe|<form|<div|<table|<input|<style|<title)/u.test(
      head,
    )
  )
    return 'html';
  if (/^(?:received|return-path|from|delivered-to|message-id|mime-version|x-[a-z-]+):/u.test(head))
    return 'email';
  return null;
}

/** True when the first ZIP entry has the "encrypted" general-purpose flag set. */
export function isEncryptedZip(bytes: Uint8Array): boolean {
  if (!startsWith(bytes, [0x50, 0x4b, 0x03, 0x04]) || bytes.length < 8) return false;
  return ((bytes[6] ?? 0) & 0x01) === 0x01;
}
