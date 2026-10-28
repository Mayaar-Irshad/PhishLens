import { readFileSync } from 'node:fs';
import { analyzeEmail } from '../src/core/analyze';
import type { AnalysisOutput, AnalysisResult, Finding } from '../src/core/types';

/** Fixed analysis time so date-based rules are deterministic. */
export const NOW = new Date('2026-10-27T12:00:00Z');

export interface EmailParts {
  headers?: string[];
  body?: string;
  /** Omit the blank line and body entirely (headers-only input). */
  headersOnly?: boolean;
}

const DEFAULT_HEADERS = [
  'Received: from mx.recipient.example (mx.recipient.example [192.0.2.10]) by mail.recipient.example; Tue, 20 Oct 2026 10:00:05 +0000',
  'From: Alice Example <alice@sender.example>',
  'To: bob@recipient.example',
  'Subject: Quarterly report',
  'Date: Tue, 20 Oct 2026 10:00:00 +0000',
  'Message-ID: <msg-1@sender.example>',
  'MIME-Version: 1.0',
];

/**
 * Builds an RFC 5322 message. Headers given in `headers` replace defaults with
 * the same name (case-insensitive); pass `Name:` with no value to drop one.
 */
export function buildEmail({
  headers = [],
  body = 'Hello,\r\n\r\nSee you soon.\r\n',
  headersOnly = false,
}: EmailParts = {}): string {
  const names = new Set(
    headers.map((header) => header.slice(0, header.indexOf(':')).toLowerCase()),
  );
  const merged = [
    ...DEFAULT_HEADERS.filter(
      (header) => !names.has(header.slice(0, header.indexOf(':')).toLowerCase()),
    ),
    ...headers.filter((header) => header.slice(header.indexOf(':') + 1).trim() !== ''),
  ];
  const head = merged.join('\r\n');
  return headersOnly ? `${head}\r\n` : `${head}\r\n\r\n${body}`;
}

export function htmlEmail(html: string, headers: string[] = []): string {
  return buildEmail({
    headers: ['Content-Type: text/html; charset=utf-8', ...headers],
    body: html,
  });
}

export const encode = (value: string): Uint8Array => new TextEncoder().encode(value);

export async function analyzeRaw(raw: string | Uint8Array): Promise<AnalysisOutput> {
  return analyzeEmail(typeof raw === 'string' ? encode(raw) : raw, {
    source: { kind: 'paste' },
    now: NOW,
  });
}

export async function analyze(raw: string | Uint8Array): Promise<AnalysisResult> {
  return (await analyzeRaw(raw)).result;
}

export function ruleIds(result: AnalysisResult): string[] {
  return result.findings.map((finding) => finding.ruleId);
}

export function finding(result: AnalysisResult, ruleId: string): Finding | undefined {
  return result.findings.find((entry) => entry.ruleId === ruleId);
}

export function readSample(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(`../src/samples/${name}.eml`, import.meta.url)));
}

export function readFixture(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(`./fixtures/${name}`, import.meta.url)));
}
