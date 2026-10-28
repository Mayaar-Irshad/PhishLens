import { describe, expect, it } from 'vitest';
import { assess } from '../src/core/assessment';
import { RULES } from '../src/core/rules';
import { buildReport, reportFileName, serializeReport } from '../src/core/report';
import type { Finding, Severity } from '../src/core/types';
import { analyze, buildEmail, htmlEmail, NOW, readSample } from './helpers';

function fakeFindings(counts: Partial<Record<Severity, number>>): Finding[] {
  const out: Finding[] = [];
  for (const [severity, count] of Object.entries(counts) as [Severity, number][]) {
    for (let i = 0; i < count; i += 1) {
      out.push({
        ...RULES.URL_SHORTENER,
        ruleId: 'URL_SHORTENER',
        severity,
        occurrences: 1,
        instances: [],
      });
    }
  }
  return out;
}

describe('assessment thresholds', () => {
  it.each([
    [{}, 'none'],
    [{ info: 9 }, 'none'],
    [{ low: 1 }, 'low'],
    [{ low: 3 }, 'low'],
    [{ low: 4 }, 'elevated'],
    [{ medium: 1 }, 'elevated'],
    [{ medium: 2, low: 3 }, 'elevated'],
    [{ medium: 3 }, 'high'],
    [{ high: 1 }, 'high'],
  ] as const)('%o -> %s', (counts, level) => {
    expect(assess(fakeFindings(counts)).level).toBe(level);
  });

  it('never calls a message safe and explains the absence of indicators', () => {
    const assessment = assess([]);
    expect(assessment.label).toBe('No indicators matched');
    expect(assessment.label.toLowerCase()).not.toMatch(/safe|clean|legitimate/u);
    expect(assessment.summary).toContain('does not mean the message is safe');
    // Apart from that explicit negation, the summary must not describe the message as safe.
    const rest = assessment.summary.replace('does not mean the message is safe', '').toLowerCase();
    expect(rest).not.toMatch(/\bsafe\b|\bclean\b|\blegitimate\b/u);
  });

  it('explains which thresholds produced the level', () => {
    expect(assess(fakeFindings({ high: 2, medium: 3 })).reasons).toEqual([
      '2 high-severity rules matched (one is enough for High concern)',
      '3 medium-severity rules matched (three are enough for High concern)',
    ]);
    expect(assess(fakeFindings({ low: 1 })).reasons).toEqual(['1 low-severity rule matched']);
    expect(assess([]).reasons).toEqual(['no high, medium or low rules matched']);
  });
});

describe('JSON report', () => {
  const generatedAt = new Date('2026-10-27T13:00:00Z');

  it('has a stable schema and never includes bodies, raw headers or attachment contents', async () => {
    const result = await analyze(readSample('attachment-lure'));
    const report = buildReport(result, {
      includeRecipients: false,
      redactEmailsInUrls: true,
      generatedAt,
    });
    const json = serializeReport(report);
    expect(report.schema).toBe('phishlens-report/1');
    expect(report.generatedAt).toBe('2026-10-27T13:00:00.000Z');
    expect(report.privacy).toEqual({
      recipientsIncluded: false,
      emailsInUrlsRedacted: true,
      bodyIncluded: false,
      rawHeadersIncluded: false,
    });
    // Short phrases that matched a rule are evidence; ordinary body text is never included.
    expect(json).not.toContain('Please find the overdue invoice attached');
    expect(json).not.toContain('PHISHLENS SYNTHETIC SAMPLE');
    expect(json).not.toContain('bh=c2FtcGxl');
    expect(json).not.toContain(
      Buffer.from('PHISHLENS SYNTHETIC SAMPLE - NOT AN EXECUTABLE').toString('base64').slice(0, 20),
    );
    expect(report.attachments).toHaveLength(3);
    expect(report.attachments[0]).toMatchObject({
      filename: 'Invoice_2026-104.pdf.exe',
      sha256: expect.stringMatching(/^[0-9a-f]{64}$/u) as unknown,
    });
    expect(report.attachments[1]?.['filename']).toBe('Remittance[U+202E]fdp.html');
    expect(JSON.parse(json)).toEqual(report);
  });

  it('marks authentication values as reported and unverified', async () => {
    const report = buildReport(await analyze(readSample('credential-phish')), {
      includeRecipients: false,
      redactEmailsInUrls: true,
    });
    expect(report.authentication['independentlyVerified']).toBe(false);
    expect(String(report.authentication['note'])).toContain('Not verified');
    expect(report.limitations.join(' ')).toContain('did not verify SPF, DKIM or DMARC');
  });

  it('redacts recipient addresses everywhere by default, including inside URLs', async () => {
    const result = await analyze(readSample('credential-phish'));
    const json = serializeReport(
      buildReport(result, { includeRecipients: false, redactEmailsInUrls: false }),
    );
    expect(json).not.toMatch(/jane\.doe/iu);
    expect(json).toContain('[recipient]');
    expect(json).toContain('"count": 1');
  });

  it('includes recipients only when asked to', async () => {
    const result = await analyze(readSample('credential-phish'));
    const report = buildReport(result, { includeRecipients: true, redactEmailsInUrls: false });
    // Included addresses are defanged like every other address in the report.
    expect(serializeReport(report)).toContain('jane[.]doe[@]recipient[.]example');
  });

  it('redacts any email address embedded in links when asked to', async () => {
    const result = await analyze(
      htmlEmail(
        '<a href="https://evil.example/login?victim=someone.else%40corp.example&x=a@b.example">x</a>',
      ),
    );
    const json = serializeReport(
      buildReport(result, { includeRecipients: true, redactEmailsInUrls: true }),
    );
    expect(json).not.toContain('someone.else');
    expect(json).not.toContain('a@b.example');
    expect(json).toContain('[email]');
  });

  it('contains no clickable URLs anywhere', async () => {
    for (const sample of ['credential-phish', 'attachment-lure', 'newsletter']) {
      const json = serializeReport(
        buildReport(await analyze(readSample(sample)), {
          includeRecipients: true,
          redactEmailsInUrls: false,
        }),
      );
      // A clickable URL needs a host right after "://"; defanged ones use "[://]".
      expect(json, sample).not.toMatch(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"\]]/iu);
      expect(json, sample).not.toMatch(/\bwww\.[a-z]/iu);
    }
  });

  it('includes findings, rationale and recommended steps', async () => {
    const report = buildReport(await analyze(readSample('credential-phish')), {
      includeRecipients: false,
      redactEmailsInUrls: true,
    });
    expect(report.findings.length).toBeGreaterThan(5);
    expect(report.findings[0]).toHaveProperty('rationale');
    expect(report.recommendedSteps[0]).toContain('Do not click links');
  });

  it('names report files after the date and hash, never the subject or sender', async () => {
    const result = await analyze(buildEmail({ headers: ['Subject: Secret <project> name'] }));
    const name = reportFileName({
      ...result,
      meta: { ...result.meta, analyzedAt: NOW.toISOString() },
    });
    expect(name).toMatch(/^phishlens-report-2026-10-27-[0-9a-f]{12}\.json$/u);
  });
});
