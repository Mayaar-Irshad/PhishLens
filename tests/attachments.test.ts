import type { Attachment } from 'postal-mime';
import { describe, expect, it } from 'vitest';
import {
  analyzeAttachment,
  detectSignature,
  filenameParts,
  isEncryptedZip,
  sha256Hex,
} from '../src/core/attachments';
import { analyze, buildEmail, ruleIds } from './helpers';

const bytes = (...values: number[]) => new Uint8Array(values);
const text = (value: string) => new TextEncoder().encode(value);

function attachment(filename: string | null, mimeType: string, content: Uint8Array): Attachment {
  return { filename, mimeType, disposition: 'attachment', content: content.slice().buffer };
}

async function flagsFor(
  filename: string | null,
  mimeType: string,
  content: Uint8Array = text('plain content'),
) {
  const { record } = await analyzeAttachment(attachment(filename, mimeType, content), 0);
  return record.flags.map((flag) => flag.ruleId);
}

describe('file signatures', () => {
  it('recognises common formats from their leading bytes', () => {
    expect(detectSignature(bytes(0x4d, 0x5a, 0x90, 0))).toBe('pe-executable');
    expect(detectSignature(bytes(0x7f, 0x45, 0x4c, 0x46))).toBe('elf-executable');
    expect(detectSignature(text('%PDF-1.7'))).toBe('pdf');
    expect(detectSignature(bytes(0x50, 0x4b, 0x03, 0x04))).toBe('zip');
    expect(detectSignature(bytes(0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1))).toBe('ole');
    expect(detectSignature(bytes(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0))).toBe('rar');
    expect(detectSignature(bytes(0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0))).toBe('lnk');
    expect(detectSignature(bytes(0x89, 0x50, 0x4e, 0x47))).toBe('png');
    expect(detectSignature(text('  <!DOCTYPE html><html>'))).toBe('html');
    expect(detectSignature(text('<?xml version="1.0"?><svg xmlns="x">'))).toBe('svg');
    expect(detectSignature(text('plain text'))).toBeNull();
  });

  it('recognises ISO images by their volume descriptor', () => {
    const iso = new Uint8Array(0x8010);
    iso.set(text('CD001'), 0x8001);
    expect(detectSignature(iso)).toBe('iso');
  });

  it('detects encrypted ZIP entries from the general-purpose flag', () => {
    expect(isEncryptedZip(bytes(0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0x01, 0))).toBe(true);
    expect(isEncryptedZip(bytes(0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0x00, 0))).toBe(false);
  });

  it('hashes content with SHA-256', async () => {
    expect(await sha256Hex(text('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});

describe('filename heuristics', () => {
  it('splits extensions the way Windows treats the name', () => {
    expect(filenameParts('report.pdf.exe')).toMatchObject({
      extension: 'exe',
      previousExtension: 'pdf',
    });
    expect(filenameParts('report.exe. . ')).toMatchObject({ extension: 'exe' });
    expect(filenameParts('noextension').extension).toBeNull();
    expect(filenameParts('invoice.pdf            .exe').padded).toBe(true);
  });

  it('flags executables, scripts and shortcuts', async () => {
    for (const name of [
      'setup.exe',
      'update.js',
      'run.ps1',
      'doc.lnk',
      'page.hta',
      'x.scr',
      'macro.vbs',
      'query.iqy',
    ]) {
      expect(await flagsFor(name, 'application/octet-stream'), name).toContain(
        'ATTACHMENT_EXECUTABLE',
      );
    }
  });

  it('flags double extensions and padded names', async () => {
    expect(await flagsFor('Invoice.pdf.exe', 'application/pdf')).toContain(
      'ATTACHMENT_DOUBLE_EXTENSION',
    );
    expect(await flagsFor('Scan.jpg.html', 'text/html')).toContain('ATTACHMENT_DOUBLE_EXTENSION');
    expect(await flagsFor('Invoice                         .js', 'text/plain')).toContain(
      'ATTACHMENT_DOUBLE_EXTENSION',
    );
  });

  it('flags right-to-left overrides and explains how the name may appear', async () => {
    const { record } = await analyzeAttachment(
      attachment('Remittance\u202Efdp.html', 'text/html', text('<html>')),
      0,
    );
    const bidi = record.flags.find((flag) => flag.ruleId === 'ATTACHMENT_BIDI_FILENAME');
    expect(bidi?.label).toContain('may display as "Remittancelmth.pdf"');
    expect(bidi?.label).toContain('[U+202E]');
  });

  it('flags disk images, HTML/SVG, macro documents, OneNote and archives at their own severity', async () => {
    expect(await flagsFor('disk.iso', 'application/octet-stream')).toContain(
      'ATTACHMENT_DISK_IMAGE',
    );
    expect(await flagsFor('voicemail.svg', 'image/svg+xml')).toContain('ATTACHMENT_HTML');
    expect(
      await flagsFor(
        'budget.xlsm',
        'application/vnd.ms-excel.sheet.macroEnabled.12',
        bytes(0x50, 0x4b, 3, 4),
      ),
    ).toContain('ATTACHMENT_MACRO_DOCUMENT');
    expect(await flagsFor('notes.one', 'application/octet-stream')).toContain('ATTACHMENT_ONENOTE');
    expect(
      await flagsFor('photos.zip', 'application/zip', bytes(0x50, 0x4b, 3, 4, 0x14, 0, 0, 0)),
    ).toEqual(['ATTACHMENT_ARCHIVE']);
  });

  it('flags encrypted archives', async () => {
    expect(
      await flagsFor('statement.zip', 'application/zip', bytes(0x50, 0x4b, 3, 4, 0x14, 0, 1, 0)),
    ).toContain('ATTACHMENT_ENCRYPTED_ARCHIVE');
  });

  it('flags executable content behind a harmless-looking name', async () => {
    const flags = await flagsFor(
      'invoice.pdf',
      'application/pdf',
      bytes(0x4d, 0x5a, 0x90, 0, 3, 0),
    );
    expect(flags).toContain('ATTACHMENT_DISGUISED_EXECUTABLE');
  });

  it('flags content that does not match its extension', async () => {
    expect(await flagsFor('photo.jpg', 'image/jpeg', text('%PDF-1.4'))).toContain(
      'ATTACHMENT_SIGNATURE_MISMATCH',
    );
  });

  it('flags declared types that contradict the extension, but not generic types', async () => {
    expect(await flagsFor('report.pdf', 'application/x-msdownload', text('%PDF-1.4'))).toContain(
      'ATTACHMENT_TYPE_MISMATCH',
    );
    expect(await flagsFor('report.pdf', 'image/png', text('%PDF-1.4'))).toContain(
      'ATTACHMENT_TYPE_MISMATCH',
    );
    expect(await flagsFor('report.pdf', 'application/octet-stream', text('%PDF-1.4'))).toEqual([]);
  });

  it('treats metadata as untrusted text', async () => {
    const { record } = await analyzeAttachment(
      attachment('../../etc/passwd<script>.txt', 'text/plain; x="<b>"', text('x')),
      0,
    );
    expect(record.filename).toBe('../../etc/passwd<script>.txt');
    expect(record.flags).toEqual([]);
  });

  it('does not flag ordinary documents and images', async () => {
    expect(await flagsFor('Quarterly report.pdf', 'application/pdf', text('%PDF-1.7'))).toEqual([]);
    expect(await flagsFor('photo.jpeg', 'image/jpeg', bytes(0xff, 0xd8, 0xff, 0xe0))).toEqual([]);
    expect(
      await flagsFor(
        'notes.docx',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        bytes(0x50, 0x4b, 3, 4, 0x14, 0, 0, 0),
      ),
    ).toEqual([]);
    expect(await flagsFor('backup.tar.gz', 'application/gzip', bytes(0x1f, 0x8b, 8, 0))).toEqual([
      'ATTACHMENT_ARCHIVE',
    ]);
  });
});

describe('attachments in a full analysis', () => {
  it('lists name, size, declared type and hash, and explains the heuristic nature', async () => {
    const raw = buildEmail({
      headers: ['Content-Type: multipart/mixed; boundary="m"'],
      body: [
        '--m',
        'Content-Type: text/plain',
        '',
        'Please see the attachment.',
        '--m',
        'Content-Type: application/octet-stream; name="Payment.pdf.exe"',
        'Content-Disposition: attachment; filename="Payment.pdf.exe"',
        'Content-Transfer-Encoding: base64',
        '',
        Buffer.from('MZ\x90\x00not really a program', 'latin1').toString('base64'),
        '--m--',
        '',
      ].join('\r\n'),
    });
    const result = await analyze(raw);
    expect(result.attachments[0]).toMatchObject({
      filename: 'Payment.pdf.exe',
      declaredType: 'application/octet-stream',
      sizeBytes: 24,
      signature: { kind: 'pe-executable' },
    });
    expect(result.attachments[0]?.sha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(ruleIds(result)).toEqual(
      expect.arrayContaining(['ATTACHMENT_EXECUTABLE', 'ATTACHMENT_DOUBLE_EXTENSION']),
    );
    const executable = result.findings.find((entry) => entry.ruleId === 'ATTACHMENT_EXECUTABLE');
    expect(executable?.recommendation).toContain('Do not open the attachment');
  });
});
