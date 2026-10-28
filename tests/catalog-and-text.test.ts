import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { RULES, RULE_LIST } from '../src/core/rules';
import {
  formatBytes,
  hasBidiControls,
  hasInvisibleCharacters,
  revealHiddenCharacters,
  segmentHiddenCharacters,
  simulateRightToLeftOverride,
  truncate,
} from '../src/core/text';
import { TOOL_VERSION } from '../src/core/version';
import { analyze, readSample, ruleIds } from './helpers';

describe('rule catalogue', () => {
  it('has unique, consistent and complete rules', () => {
    const ids = RULE_LIST.map((rule) => rule.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const [key, rule] of Object.entries(RULES)) {
      expect(rule.id).toBe(key);
      expect(['high', 'medium', 'low', 'info']).toContain(rule.severity);
      for (const text of [rule.title, rule.rationale, rule.benignCauses, rule.recommendation]) {
        expect(text.trim().length, key).toBeGreaterThan(10);
        expect(hasBidiControls(text) || hasInvisibleCharacters(text), key).toBe(false);
      }
    }
  });

  it('never phrases a heuristic as proof', () => {
    for (const rule of RULE_LIST) {
      const text = `${rule.title} ${rule.rationale}`.toLowerCase();
      expect(text, rule.id).not.toMatch(
        /\b(?:is|proves|confirms) (?:phishing|malicious|malware|safe)\b/u,
      );
    }
  });

  it('matches the package version', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      version: string;
    };
    expect(TOOL_VERSION).toBe(pkg.version);
  });
});

describe('hidden character helpers', () => {
  it('detects and reveals bidi, zero-width and control characters', () => {
    const value = 'pay\u200Bpal\u202Etxt.exe\u0007';
    expect(hasBidiControls(value)).toBe(true);
    expect(hasInvisibleCharacters(value)).toBe(true);
    expect(revealHiddenCharacters(value)).toBe('pay[U+200B]pal[U+202E]txt.exe[U+0007]');
    expect(segmentHiddenCharacters('a\u202Eb')).toEqual([
      { kind: 'text', value: 'a' },
      { kind: 'hidden', value: 'U+202E' },
      { kind: 'text', value: 'b' },
    ]);
    expect(hasBidiControls('plain text')).toBe(false);
  });

  it('simulates how a right-to-left override reorders a name', () => {
    expect(simulateRightToLeftOverride('invoice\u202Efdp.exe')).toBe('invoiceexe.pdf');
    expect(simulateRightToLeftOverride('a\u202Ecba\u202Cz')).toBe('aabcz');
    expect(simulateRightToLeftOverride('normal.pdf')).toBeNull();
  });

  it('formats sizes and truncates text', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(10 * 1024 * 1024)).toBe('10 MB');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(truncate('abcdef', 4)).toBe('abc\u2026');
    expect(truncate('abc', 4)).toBe('abc');
  });
});

describe('bundled samples (regression)', () => {
  it('credential phishing sample', async () => {
    const result = await analyze(readSample('credential-phish'));
    expect(result.assessment.level).toBe('high');
    expect(ruleIds(result)).toEqual(
      expect.arrayContaining([
        'SENDER_LOOKALIKE_DOMAIN',
        'AUTH_REPORTED_DMARC_FAIL',
        'URL_TEXT_BRAND_MISMATCH',
        'URL_BRAND_IN_SUBDOMAIN',
        'URL_MIXED_SCRIPT',
        'URL_IP_HOST',
        'HTML_PASSWORD_FIELD',
        'HTML_ACTIVE_CONTENT',
        'CONTENT_CREDENTIAL_REQUEST',
      ]),
    );
  });

  it('attachment lure sample', async () => {
    const result = await analyze(readSample('attachment-lure'));
    expect(result.assessment.level).toBe('high');
    expect(ruleIds(result)).toEqual(
      expect.arrayContaining([
        'ATTACHMENT_DOUBLE_EXTENSION',
        'ATTACHMENT_EXECUTABLE',
        'ATTACHMENT_BIDI_FILENAME',
        'ATTACHMENT_ENCRYPTED_ARCHIVE',
        'SENDER_REPLY_TO_FREEMAIL',
        'AUTH_DKIM_BODY_LENGTH',
        'AUTH_REPORTED_PASS',
      ]),
    );
  });

  it('newsletter sample produces only informational notes', async () => {
    const result = await analyze(readSample('newsletter'));
    expect(result.assessment.level).toBe('none');
    expect(result.findings.every((entry) => entry.severity === 'info')).toBe(true);
    expect(result.urls.every((url) => url.flags.length === 0)).toBe(true);
  });
});
