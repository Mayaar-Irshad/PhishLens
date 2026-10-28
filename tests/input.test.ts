import { describe, expect, it } from 'vitest';
import { resolveMaxInputBytes } from '../src/config';
import { AnalysisError } from '../src/core/errors';
import { checkFileMetadata, checkSize, prepareInput } from '../src/core/input';
import { DEFAULT_LIMITS, MEGABYTE, ABSOLUTE_MAX_INPUT_BYTES } from '../src/core/limits';
import { analyze, buildEmail, encode, NOW, ruleIds } from './helpers';
import { analyzeEmail } from '../src/core/analyze';

function errorCode(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (error) {
    return error instanceof AnalysisError ? error.code : 'unexpected';
  }
  return undefined;
}

async function asyncErrorCode(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
  } catch (error) {
    return error instanceof AnalysisError ? error.code : 'unexpected';
  }
  return undefined;
}

describe('file-size limit', () => {
  it('defaults to 10 MB', () => {
    expect(DEFAULT_LIMITS.maxInputBytes).toBe(10 * MEGABYTE);
  });

  it('accepts a message exactly at the limit and rejects one byte more', () => {
    expect(errorCode(() => checkSize(10 * MEGABYTE, 10 * MEGABYTE))).toBeUndefined();
    expect(errorCode(() => checkSize(10 * MEGABYTE + 1, 10 * MEGABYTE))).toBe('FILE_TOO_LARGE');
  });

  it('checks file size before reading the file', () => {
    expect(errorCode(() => checkFileMetadata('big.eml', 11 * MEGABYTE, 10 * MEGABYTE))).toBe(
      'FILE_TOO_LARGE',
    );
  });

  it('enforces the limit inside the analysis pipeline as well', async () => {
    const raw = encode(buildEmail({ body: 'x'.repeat(2048) }));
    const code = await asyncErrorCode(
      analyzeEmail(raw, {
        source: { kind: 'paste' },
        now: NOW,
        limits: { ...DEFAULT_LIMITS, maxInputBytes: 1024 },
      }),
    );
    expect(code).toBe('FILE_TOO_LARGE');
  });

  it('is configurable through VITE_MAX_EMAIL_MB with safe fallbacks and a hard cap', () => {
    expect(resolveMaxInputBytes(undefined)).toBe(10 * MEGABYTE);
    expect(resolveMaxInputBytes('')).toBe(10 * MEGABYTE);
    expect(resolveMaxInputBytes('25')).toBe(25 * MEGABYTE);
    expect(resolveMaxInputBytes('0.5')).toBe(MEGABYTE / 2);
    expect(resolveMaxInputBytes('-3')).toBe(10 * MEGABYTE);
    expect(resolveMaxInputBytes('lots')).toBe(10 * MEGABYTE);
    expect(resolveMaxInputBytes('100000')).toBe(ABSOLUTE_MAX_INPUT_BYTES);
  });
});

describe('file type checks', () => {
  it('accepts .eml and .txt files', () => {
    expect(errorCode(() => checkFileMetadata('message.eml', 100, MEGABYTE))).toBeUndefined();
    expect(errorCode(() => checkFileMetadata('HEADERS.TXT', 100, MEGABYTE))).toBeUndefined();
  });

  it('explains that Outlook .msg files are unsupported', () => {
    expect(errorCode(() => checkFileMetadata('message.msg', 100, MEGABYTE))).toBe('OUTLOOK_MSG');
  });

  it('rejects other file types', () => {
    expect(errorCode(() => checkFileMetadata('invoice.pdf', 100, MEGABYTE))).toBe(
      'UNSUPPORTED_FILE_TYPE',
    );
    expect(errorCode(() => checkFileMetadata('no-extension', 100, MEGABYTE))).toBe(
      'UNSUPPORTED_FILE_TYPE',
    );
    expect(errorCode(() => checkFileMetadata('message.eml.exe', 100, MEGABYTE))).toBe(
      'UNSUPPORTED_FILE_TYPE',
    );
  });
});

describe('content validation', () => {
  const prepare = (value: string | Uint8Array) =>
    prepareInput(typeof value === 'string' ? encode(value) : value, MEGABYTE);

  it('rejects empty and whitespace-only input', () => {
    expect(errorCode(() => prepare(''))).toBe('EMPTY_INPUT');
    expect(errorCode(() => prepare('  \r\n\t\n'))).toBe('EMPTY_INPUT');
  });

  it('rejects text that does not start with a header', () => {
    expect(
      errorCode(() => prepare('Hello, this is a normal paragraph of text.\nNothing else.')),
    ).toBe('NO_HEADERS');
  });

  it('rejects header-shaped text with no recognisable email headers', () => {
    expect(errorCode(() => prepare('Ingredients: flour, sugar\nMethod: mix\n'))).toBe('NO_HEADERS');
  });

  it('detects Outlook .msg content even with a misleading name', () => {
    const ole = new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0, 0, 0, 0]);
    expect(errorCode(() => prepare(ole))).toBe('OUTLOOK_MSG');
  });

  it('rejects binary files such as PDFs, ZIPs and executables', () => {
    expect(errorCode(() => prepare('%PDF-1.7\n%binary'))).toBe('BINARY_CONTENT');
    expect(errorCode(() => prepare(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 1, 2])))).toBe(
      'BINARY_CONTENT',
    );
    expect(errorCode(() => prepare(new Uint8Array([0x4d, 0x5a, 0x90, 0])))).toBe('BINARY_CONTENT');
  });

  it('rejects binary data that does not start with headers', () => {
    expect(errorCode(() => prepare(encode('\u0000\u0001binary blob \u0000 with NULs')))).toBe(
      'BINARY_CONTENT',
    );
  });

  it('does not let body content force a binary rejection of a real message', () => {
    // A NUL byte or the ISO 9660 signature at offset 32 KiB must not make a message unanalysable.
    const withNul = buildEmail({ body: 'Hello\u0000world' });
    expect(errorCode(() => prepare(withNul))).toBeUndefined();
    const padding = 'x'.repeat(0x8001 - buildEmail({ body: '' }).length);
    const withIsoMagic = buildEmail({ body: `${padding}CD001 more text` });
    expect(new TextDecoder().decode(encode(withIsoMagic).subarray(0x8001, 0x8006))).toBe('CD001');
    expect(errorCode(() => prepare(withIsoMagic))).toBeUndefined();
  });

  it('strips a UTF-8 BOM, leading blank lines and an mbox separator', () => {
    const raw = `\uFEFF\r\n\r\nFrom MAILER-DAEMON Tue Oct 20 10:00:00 2026\r\n${buildEmail()}`;
    const prepared = prepare(raw);
    expect(new TextDecoder().decode(prepared.bytes).startsWith('Received:')).toBe(true);
  });

  it('detects headers-only input', () => {
    expect(prepare(buildEmail({ headersOnly: true })).headersOnly).toBe(true);
    expect(prepare(buildEmail()).headersOnly).toBe(false);
  });

  it('counts malformed lines inside the header block', () => {
    const raw = 'From: a@sender.example\r\nthis line is not a header\r\nSubject: hi\r\n\r\nbody';
    expect(prepare(raw).malformedHeaderLines).toBe(1);
  });
});

describe('error handling through the pipeline', () => {
  it('reports a malformed header block as a finding instead of failing', async () => {
    const result = await analyze(
      'From: a@sender.example\r\nnot a header\r\nSubject: hi\r\nDate: Tue, 20 Oct 2026 10:00:00 +0000\r\n\r\nbody',
    );
    expect(ruleIds(result)).toContain('INPUT_MALFORMED_HEADER_LINES');
  });

  it('adds a headers-only note', async () => {
    const result = await analyze(buildEmail({ headersOnly: true }));
    expect(result.meta.headersOnly).toBe(true);
    expect(ruleIds(result)).toContain('INPUT_HEADERS_ONLY');
    expect(result.urls).toHaveLength(0);
  });

  it('never echoes message content in error messages', async () => {
    const secret = 'TOP-SECRET-CONTENT-<script>alert(1)</script>';
    try {
      await analyze(`${secret}\nmore text`);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AnalysisError);
      const serialized = JSON.stringify((error as AnalysisError).toJSON());
      expect(serialized).not.toContain('TOP-SECRET');
      expect(serialized).not.toContain('<script>');
    }
  });
});
