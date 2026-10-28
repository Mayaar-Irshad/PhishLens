import { describe, expect, it } from 'vitest';
import { hostsFromDisplayText } from '../src/core/domain';
import { collectIndicators, indicatorsAsText } from '../src/core/indicators';
import { isPublicIp } from '../src/core/ip';
import { analystSteps } from '../src/core/recommendations';
import { buildReport, reportAsText, serializeReport } from '../src/core/report';
import {
  analyze,
  analyzeRaw,
  buildEmail,
  finding,
  htmlEmail,
  readSample,
  ruleIds,
} from './helpers';

describe('link text comparison', () => {
  it('compares addresses mentioned inside longer link text', async () => {
    expect(hostsFromDisplayText('Visit www.paypal.com today')).toEqual(['www.paypal.com']);
    expect(hostsFromDisplayText('Read the full report')).toEqual([]);
    expect(hostsFromDisplayText('Questions? See file.txt')).toEqual([]);
    const result = await analyze(
      htmlEmail('<a href="https://login.evil.example/">Sign in at www.paypal.com now</a>'),
    );
    expect(ruleIds(result)).toContain('URL_TEXT_BRAND_MISMATCH');
  });

  it('flags mailto links whose text shows a different address', async () => {
    const result = await analyze(
      htmlEmail('<a href="mailto:helpdesk@attacker.example">support@paypal.com</a>'),
    );
    expect(finding(result, 'URL_TEXT_BRAND_MISMATCH')?.instances[0]?.message).toContain(
      'support[@]paypal[.]com',
    );
    const same = await analyze(
      htmlEmail('<a href="mailto:help@shop.example?subject=Hi">help@shop.example</a>'),
    );
    expect(ruleIds(same)).not.toContain('URL_TEXT_MISMATCH');
  });

  it('defangs hosts and IPs inside flag labels', async () => {
    const result = await analyze(htmlEmail('<a href="http://198.51.100.23/x">pay</a>'));
    expect(result.urls[0]?.flags.find((flag) => flag.ruleId === 'URL_IP_HOST')?.label).toBe(
      'Host is the IP address 198[.]51[.]100[.]23',
    );
  });
});

describe('new sender and content rules', () => {
  it('flags look-alike Reply-To domains', async () => {
    const result = await analyze(
      buildEmail({ headers: ['Reply-To: billing@paypa1-support.example'] }),
    );
    expect(finding(result, 'SENDER_LOOKALIKE_DOMAIN')?.instances[0]?.message).toContain(
      'Reply-To domain',
    );
  });

  it('flags payment diversion wording typical of business email compromise', async () => {
    const result = await analyze(
      buildEmail({
        body: 'Hi, please note our bank details have changed. Use the new account for the wire transfer today.',
      }),
    );
    expect(finding(result, 'CONTENT_PAYMENT_DIVERSION')?.severity).toBe('medium');
    const normal = await analyze(
      buildEmail({ body: 'The quarterly report is attached. Thanks for your help.' }),
    );
    expect(ruleIds(normal)).not.toContain('CONTENT_PAYMENT_DIVERSION');
  });

  it('flags image-only bodies but not image-rich newsletters with text', async () => {
    const imageOnly = await analyze(
      htmlEmail('<a href="https://x.example/"><img src="cid:qr@x" alt=""></a><p>Scan me</p>'),
    );
    expect(ruleIds(imageOnly)).toContain('CONTENT_IMAGE_ONLY');
    const newsletter = await analyze(readSample('newsletter'));
    expect(ruleIds(newsletter)).not.toContain('CONTENT_IMAGE_ONLY');
  });

  it('flags large amounts of hidden text but not a short preheader', async () => {
    const salted = await analyze(
      htmlEmail(`<p>Pay now</p><div style="display:none">${'lorem ipsum '.repeat(60)}</div>`),
    );
    expect(ruleIds(salted)).toContain('HTML_HIDDEN_TEXT');
    expect(salted.body.html.hiddenTextChars).toBeGreaterThan(300);
    const preheader = await analyze(
      htmlEmail(
        '<span style="display: none; max-height: 0">Your October update is here</span><p>Hello and welcome to the update.</p>',
      ),
    );
    expect(ruleIds(preheader)).not.toContain('HTML_HIDDEN_TEXT');
  });

  it('excludes hidden text from the visible text used by content rules', async () => {
    const result = await analyze(
      htmlEmail(
        '<p>Monthly newsletter</p><div style="font-size:0">your account has been suspended</div>',
      ),
    );
    expect(ruleIds(result)).not.toContain('CONTENT_URGENCY_LANGUAGE');
    expect(result.body.preview.visibleText).not.toContain('suspended');
  });

  it('flags password inputs outside a form', async () => {
    const result = await analyze(htmlEmail('<p>Confirm:</p><input type="password" name="p">'));
    expect(ruleIds(result)).toContain('HTML_PASSWORD_FIELD');
  });
});

describe('pasted text with a preamble', () => {
  const gmailPage = [
    'Original message',
    'Message ID\t<abc@sender.example>',
    'Created at:\tTue, Oct 20, 2026 at 10:00 AM',
    'From:\tAlice <alice@sender.example>',
    'To:\tbob@recipient.example',
    'Subject:\tQuarterly report',
    'SPF:\tPASS with IP 203.0.113.5 Learn more',
    'Download original',
    'Copy to clipboard',
  ].join('\n');

  it("skips a mail client's summary before the headers", async () => {
    const result = await analyze(`${gmailPage}\n${buildEmail()}`);
    expect(result.headers.subject).toBe('Quarterly report');
    expect(result.headers.counts['received']).toBe(1);
    expect(result.meta.warnings.join(' ')).toContain('Ignored 9 lines');
  });

  it('still rejects text without any header block', async () => {
    await expect(
      analyze('Just a note.\nNothing else here.\nFrom memory: nothing.'),
    ).rejects.toMatchObject({ code: 'NO_HEADERS' });
  });
});

describe('origin IP and notable headers', () => {
  it('reports the earliest public IP and skips private ones', async () => {
    const result = await analyze(
      buildEmail({
        headers: [
          'Received: from mx.example (mx.example [192.0.2.10]) by mail.example; Tue, 20 Oct 2026 10:00:09 +0000\r\nReceived: from origin.example (origin.example [203.0.113.77]) by mx.example; Tue, 20 Oct 2026 10:00:05 +0000\r\nReceived: from laptop (10.0.0.5) by origin.example; Tue, 20 Oct 2026 10:00:01 +0000',
          'X-Mailer: PHPMailer 6.9.1',
        ],
      }),
    );
    expect(result.headers.originIp).toMatchObject({ ip: '203.0.113.77', source: 'received' });
    expect(result.headers.notable.map((field) => field.label)).toContain('X-Mailer');
    expect(isPublicIp('10.1.2.3')).toBe(false);
    expect(isPublicIp('172.20.1.1')).toBe(false);
    expect(isPublicIp('fd00::1')).toBe(false);
    expect(isPublicIp('2001:db8::1')).toBe(true);
  });

  it('falls back to X-Originating-IP', async () => {
    const result = await analyze(
      buildEmail({ headers: ['Received:', 'X-Originating-IP: [198.51.100.40]'] }),
    );
    expect(result.headers.originIp).toMatchObject({
      ip: '198.51.100.40',
      source: 'x-originating-ip',
    });
  });
});

describe('indicators, summaries and previews', () => {
  it('collects defanged indicators without recipient addresses', async () => {
    const result = await analyze(readSample('credential-phish'));
    const indicators = collectIndicators(result);
    expect(indicators.senderAddresses).toContain('service[@]paypa1-account-security[.]example');
    expect(indicators.ips).toEqual(
      expect.arrayContaining(['203[.]0[.]113[.]45', '198[.]51[.]100[.]23']),
    );
    expect(indicators.urls.every((url) => !/^[a-z]+:\/\//iu.test(url))).toBe(true);
    const text = indicatorsAsText(indicators);
    expect(text).not.toContain('jane.doe@');
    expect(text).toContain('URLs');
  });

  it('redacts a spoofed recipient address that also appears as the sender', async () => {
    const result = await analyze(
      buildEmail({ headers: ['From: Bob <bob@recipient.example>', 'To: bob@recipient.example'] }),
    );
    const json = serializeReport(
      buildReport(result, { includeRecipients: false, redactEmailsInUrls: true }),
    );
    expect(json).not.toMatch(/bob(?:@|\[@\])recipient/iu);
  });

  it('produces a ticket summary with the same privacy guarantees as the report', async () => {
    const result = await analyze(readSample('credential-phish'));
    const summary = reportAsText(
      buildReport(result, { includeRecipients: false, redactEmailsInUrls: true }),
    );
    expect(summary).toContain('Assessment: High concern');
    expect(summary).toContain('Reported authentication (not verified)');
    expect(summary).not.toMatch(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"\]]/iu);
    expect(summary).not.toContain('jane.doe');
    expect(summary).not.toContain('Dear customer');
  });

  it('keeps body previews for the Content tab but never exports them', async () => {
    const result = await analyze(readSample('credential-phish'));
    expect(result.body.preview.visibleText).toContain('Dear customer');
    expect(result.body.preview.htmlSource).toContain('<form action=');
    const json = serializeReport(buildReport(result));
    expect(json).not.toContain('Dear customer');
    expect(json).not.toContain('<form');
  });

  it('gives analysts concrete next steps', async () => {
    const steps = analystSteps(await analyze(readSample('credential-phish')));
    expect(steps[0]).toContain('Message-ID');
    expect(steps.join(' ')).toContain('proxy, DNS and endpoint logs');
  });

  it('still finds every link in the samples after the attachment changes', async () => {
    const { result } = await analyzeRaw(readSample('attachment-lure'));
    expect(result.attachments.map((attachment) => attachment.contents.links)).toEqual([0, 0, 0]);
    expect(ruleIds(result)).toContain('CONTENT_PAYMENT_DIVERSION');
  });
});
