import { describe, expect, it } from 'vitest';
import { analyzeAuthentication } from '../src/core/auth';
import { scanHtml } from '../src/core/html';
import { analyzeHeaders, parseReceived } from '../src/core/headers';
import { collectIndicators } from '../src/core/indicators';
import { buildReport, reportAsText, serializeReport } from '../src/core/report';
import { analyzeOccurrences, extractTextUrls } from '../src/core/urls';
import { analyze, buildEmail, finding, htmlEmail, readSample, ruleIds } from './helpers';

/**
 * Regression tests for findings from an independent adversarial review:
 * denial of service, evasion, false negatives, false positives and report
 * privacy. Each case was first reproduced against the earlier code.
 */

const linkFlags = (url: string, text?: string) =>
  analyzeOccurrences(
    [text === undefined ? { kind: 'html-link', url } : { kind: 'html-link', url, text }],
    50,
    null,
  ).records.flatMap((record) => record.flags.map((flag) => flag.ruleId));

function attachment(filename: string, type: string, content: string | Buffer): string {
  return buildEmail({
    headers: ['Content-Type: multipart/mixed; boundary="r"'],
    body: [
      '--r',
      'Content-Type: text/plain',
      '',
      'See attached.',
      '--r',
      `Content-Type: ${type}; name="${filename}"`,
      `Content-Disposition: attachment; filename="${filename}"`,
      'Content-Transfer-Encoding: base64',
      '',
      Buffer.from(content).toString('base64'),
      '--r--',
      '',
    ].join('\r\n'),
  });
}

async function timed(fn: () => Promise<unknown>): Promise<number> {
  const started = performance.now();
  await fn();
  return performance.now() - started;
}

describe('denial of service and crashes', () => {
  it('handles elements with hundreds of thousands of children', async () => {
    const wide = `<a href="https://x.example/"><span>${'<i></i>'.repeat(200_000)}</span></a><form><div>${'<input>'.repeat(50_000)}</div></form>`;
    await expect(analyze(htmlEmail(wide))).resolves.toBeDefined();
  });

  it.each([
    [
      'attachment name of underscores',
      attachment(`${'_'.repeat(4000)}x.pdf`, 'application/pdf', '%PDF-1.4'),
    ],
    ['unterminated CSS url(', htmlEmail(`<div style="${'url('.repeat(15_000)}">x</div>`)],
    ['repeated ms- prefixes', buildEmail({ body: 'ms-'.repeat(60_000) })],
    ['unterminated tags', htmlEmail('<a '.repeat(60_000))],
    [
      'URL followed by closing parentheses',
      buildEmail({ body: `https://x.example/${')'.repeat(60_000)}` }),
    ],
    [
      'huge area alt text',
      htmlEmail(`<map><area href="https://x.example/" alt="${'a.'.repeat(30_000)}"></map>`),
    ],
    [
      'spaces in Authentication-Results',
      buildEmail({
        headers: [`Authentication-Results: mx.example; spf${' '.repeat(15_000)}=pass`],
      }),
    ],
    ['long display name', buildEmail({ headers: [`From: "${'a'.repeat(15_000)}" <a@b.example>`] })],
  ])('stays fast with %s', async (_label, raw) => {
    expect(await timed(() => analyze(raw))).toBeLessThan(3000);
  });

  it('builds reports quickly for many long dotted links', async () => {
    const links = Array.from(
      { length: 300 },
      (_, i) => `<a href="https://h${i}.example/${'a.'.repeat(2000)}">x</a>`,
    ).join('');
    const result = await analyze(htmlEmail(links));
    const started = performance.now();
    serializeReport(buildReport(result));
    expect(performance.now() - started).toBeLessThan(3000);
  });
});

describe('evasion', () => {
  it('flags several mailboxes in one From header and checks DMARC against the displayed one', async () => {
    const result = await analyze(
      buildEmail({
        headers: [
          'From: service@paypal.com, attacker@evil.example',
          'Authentication-Results: mx.recipient.example; dmarc=pass header.from=evil.example',
        ],
      }),
    );
    expect(finding(result, 'SENDER_MULTIPLE_FROM_ADDRESSES')?.severity).toBe('high');
    expect(ruleIds(result)).toContain('AUTH_RESULTS_DOMAIN_MISMATCH');
  });

  it('flags a From header that is only a name', async () => {
    const result = await analyze(buildEmail({ headers: ['From: PayPal Security Team:;'] }));
    expect(ruleIds(result)).toEqual(
      expect.arrayContaining(['SENDER_INVALID_ADDRESS', 'SENDER_DISPLAY_NAME_BRAND']),
    );
  });

  it('does not treat full-width look-alike sender domains as the real brand', async () => {
    const result = await analyze(
      buildEmail({
        headers: ['From: PayPal Service <service@\uFF50\uFF41\uFF59\uFF50\uFF41\uFF4C.com>'],
      }),
    );
    expect(result.headers.from[0]?.domainWrittenAs).toBe(
      '\uFF50\uFF41\uFF59\uFF50\uFF41\uFF4C.com',
    );
    expect(ruleIds(result)).toContain('SENDER_LOOKALIKE_DOMAIN');
    expect(result.assessment.level).toBe('high');
  });

  it('inspects HTML login pages disguised as documents', async () => {
    const page =
      '<!-- saved from url=(0014)about:internet -->\n<html><body><form><input type="password"></form></body></html>';
    const result = await analyze(attachment('Remittance_Advice.pdf', 'application/pdf', page));
    expect(ruleIds(result)).toEqual(
      expect.arrayContaining(['ATTACHMENT_CREDENTIAL_FORM', 'ATTACHMENT_SIGNATURE_MISMATCH']),
    );
  });

  it('finds links hidden in Outlook conditional comments, atob redirects and event handlers', () => {
    const encoded = btoa('https://hidden.example/a');
    const scan = scanHtml(
      `<!--[if mso]><a href="https://mso.example/login">x</a><![endif]--><script>location.href = atob("${encoded}")</script><div onclick="window.location='https://click.example/'">x</div>`,
      100_000,
      100,
    );
    expect(scan.occurrences.map((entry) => entry.url)).toEqual(
      expect.arrayContaining([
        'https://mso.example/login',
        'https://hidden.example/a',
        'https://click.example/',
      ]),
    );
  });

  it('keeps OpenDKIM comments containing semicolons intact', () => {
    const auth = analyzeAuthentication(
      analyzeHeaders([
        {
          key: 'authentication-results',
          originalKey: 'Authentication-Results',
          value:
            'mx.example; dkim=pass (2048-bit key; unprotected) header.d=sender.example header.i=@sender.example',
        },
      ]).all,
      [],
    );
    expect(
      auth.authenticationResults[0]?.results[0]?.properties.map((property) => property.key),
    ).toContain('header.d');
    expect(auth.authenticationResults[0]?.parseWarnings).toEqual([]);
  });
});

describe('false negatives', () => {
  it('keeps a brand mismatch even when a redirect parameter points at the brand', () => {
    expect(
      linkFlags(
        'https://login.evil.example/signin?continue=https://www.paypal.com/',
        'https://www.paypal.com/',
      ),
    ).toContain('URL_TEXT_BRAND_MISMATCH');
  });

  it('analyses redirect destinations, including Google AMP and Bing click-through links', () => {
    expect(linkFlags('https://www.google.com/url?q=https://paypa1-secure.example/login')).toContain(
      'URL_LOOKALIKE_DOMAIN',
    );
    expect(linkFlags('https://www.google.com/amp/s/paypa1-secure.example/login')).toContain(
      'URL_LOOKALIKE_DOMAIN',
    );
    const bing = `https://www.bing.com/ck/a?!&&p=1&u=a1${btoa('https://paypa1-secure.example/').replace(/=+$/u, '')}`;
    expect(linkFlags(bing)).toContain('URL_LOOKALIKE_DOMAIN');
  });

  it('finds brand names used as subdomains of unrelated sites, but not on SaaS tenants', () => {
    expect(linkFlags('https://paypal.account-verify.example/')).toContain('URL_BRAND_KEYWORD');
    expect(linkFlags('https://login.microsoftonline.auth-portal.example/')).toContain(
      'URL_BRAND_KEYWORD',
    );
    expect(linkFlags('https://microsoft.zendesk.com/hc')).not.toContain('URL_BRAND_KEYWORD');
  });

  it('does not treat generic-use ccTLDs or customer storage as brand domains', () => {
    expect(linkFlags('https://www.paypal.co/')).toContain('URL_BRAND_KEYWORD');
    expect(linkFlags('https://www.amazon.cm/')).toContain('URL_BRAND_KEYWORD');
    expect(linkFlags('https://phish.s3.amazonaws.com/index.html', 'www.amazon.com')).toContain(
      'URL_TEXT_BRAND_MISMATCH',
    );
    expect(linkFlags('https://contoso.sharepoint.com/sites/x', 'https://www.paypal.com')).toContain(
      'URL_TEXT_BRAND_MISMATCH',
    );
    expect(linkFlags('https://www.google.de/')).toEqual([]);
  });

  it('catches transpositions and more brand keywords', () => {
    for (const host of [
      'micorsoft.example',
      'paypla.example',
      'amzaon.example',
      'netlfix.example',
      'appleid-verify.example',
      'o365-login.example',
    ]) {
      expect(linkFlags(`https://${host}/`).join(' '), host).toMatch(
        /URL_(?:LOOKALIKE_DOMAIN|BRAND_KEYWORD)/u,
      );
    }
  });

  it('reads a capital I posing as a lowercase l in display names', async () => {
    const result = await analyze(
      buildEmail({ headers: ['From: "PaypaI Security" <alerts@billing-help.example>'] }),
    );
    expect(ruleIds(result)).toContain('SENDER_DISPLAY_NAME_BRAND');
  });

  it('detects cousin domains of the recipient and of the sender', async () => {
    const lookalike = await analyze(
      buildEmail({
        headers: ['From: Dana <dana@acrne-corp.example>', 'To: bob@acme-corp.example'],
      }),
    );
    expect(finding(lookalike, 'SENDER_COUSIN_DOMAIN')?.severity).toBe('high');
    const reply = await analyze(
      buildEmail({
        headers: ['From: Jane <jane@vendorco.example>', 'Reply-To: jane@vend0rco.example'],
      }),
    );
    expect(ruleIds(reply)).toContain('SENDER_COUSIN_DOMAIN');
    const internal = await analyze(
      buildEmail({ headers: ['From: Dana <dana@acme-corp.example>', 'To: bob@acme-corp.example'] }),
    );
    expect(ruleIds(internal)).not.toContain('SENDER_COUSIN_DOMAIN');
  });

  it('reports Microsoft compauth failures and does not call bestguesspass a pass', async () => {
    const result = await analyze(
      buildEmail({
        headers: [
          'Authentication-Results: spf=none smtp.mailfrom=x.example; dmarc=bestguesspass action=none header.from=sender.example;compauth=fail reason=001',
        ],
      }),
    );
    expect(finding(result, 'AUTH_REPORTED_COMPAUTH_FAIL')?.severity).toBe('medium');
    expect(result.authentication.reported.dmarc?.status).toBe('none');
    expect(ruleIds(result)).not.toContain('AUTH_REPORTED_PASS');
  });

  it('extracts bare domains that mail clients turn into links', () => {
    expect(
      extractTextUrls('Visit paypa1-secure.example/verify now, or https://a.example/x.', 10),
    ).toEqual(['https://a.example/x', '//paypa1-secure.example/verify']);
    expect(
      extractTextUrls('Email bob@company.example, see README.md, ASP.NET, v1.2.3 and node.js', 10),
    ).toEqual([]);
  });

  it('flags QR-code lures tied to account access', async () => {
    const result = await analyze(
      buildEmail({
        body: 'Scan the QR code below to re-enrol your Microsoft authenticator before Friday.',
      }),
    );
    expect(finding(result, 'CONTENT_QR_CODE_LURE')?.severity).toBe('medium');
    const ticket = await analyze(
      buildEmail({ body: 'Show the QR code on your ticket at the gate.' }),
    );
    expect(ruleIds(ticket)).not.toContain('CONTENT_QR_CODE_LURE');
  });
});

describe('false positives on legitimate mail', () => {
  it.each([
    ['one-time code', 'Your verification code is 482913. Do not share this code with anyone.'],
    ['password reset', 'Click below to update your password. The link expires soon.'],
    ['invoice payment method', 'Invoice 42. Payment method: Bank transfer. Thank you.'],
    ['account notification', 'Your payment information has been updated successfully.'],
    ['newsletter', 'Holiday gift cards are now available in all our stores.'],
  ])('does not flag a %s', async (_label, body) => {
    const ids = ruleIds(await analyze(buildEmail({ body })));
    expect(ids).not.toContain('CONTENT_CREDENTIAL_REQUEST');
    expect(ids).not.toContain('CONTENT_PAYMENT_DIVERSION');
  });

  it('accepts emoji, Persian ZWNJ and Hebrew direction marks', async () => {
    const result = await analyze(
      buildEmail({
        headers: [
          'Subject: =?UTF-8?Q?Dev_team_=F0=9F=91=A9=E2=80=8D=F0=9F=92=BB_=D9=85=DB=8C=E2=80=8C=D8=AE=D9=88=D8=A7=D9=87=D9=85_=E2=80=8F=D7=A9=D7=9C=D7=95=D7=9D?=',
        ],
      }),
    );
    expect(ruleIds(result)).not.toContain('HEADER_SUBJECT_BIDI');
    const zwsp = await analyze(
      buildEmail({ headers: ['Subject: =?UTF-8?Q?Reset_your_pass=E2=80=8Bword?='] }),
    );
    expect(ruleIds(zwsp)).toContain('HEADER_SUBJECT_BIDI');
  });

  it('does not flag click tracking, file names or security gateways as mismatches', () => {
    expect(
      linkFlags('https://example.us1.list-manage.com/track/click?u=1&id=2', 'www.shop.example'),
    ).not.toContain('URL_TEXT_MISMATCH');
    expect(linkFlags('https://github.com/org/repo/blob/main/README.md', 'README.md')).not.toContain(
      'URL_TEXT_MISMATCH',
    );
    expect(
      linkFlags('https://protect-eu.mimecast.com/s/AbCdEf?domain=shop.example', 'www.shop.example'),
    ).not.toContain('URL_TEXT_MISMATCH');
    expect(linkFlags('https://shop.example/review/www.shop.com')).not.toContain(
      'URL_RISKY_DOWNLOAD',
    );
  });

  it('handles platform senders correctly', async () => {
    const sharepoint = await analyze(
      buildEmail({ headers: ['From: "SharePoint Online" <no-reply@sharepointonline.com>'] }),
    );
    expect(sharepoint.findings.filter((entry) => entry.category === 'sender')).toEqual([]);
    const tenant = await analyze(
      buildEmail({ headers: ['From: Microsoft 365 <admin@contoso.onmicrosoft.com>'] }),
    );
    expect(ruleIds(tenant)).toContain('SENDER_TENANT_DOMAIN');
    expect(ruleIds(tenant)).not.toContain('SENDER_BRAND_IN_DOMAIN');
    const newspaper = await analyze(
      buildEmail({ headers: ['From: The Daily Messenger <news@dailymessenger.example>'] }),
    );
    expect(ruleIds(newspaper)).not.toContain('SENDER_DISPLAY_NAME_BRAND');
    const list = await analyze(
      buildEmail({
        headers: [
          'From: "Alice via Group" <group@lists.example>',
          'Reply-To: alice.person@gmail.com',
          'List-Id: <group.lists.example>',
        ],
      }),
    );
    expect(ruleIds(list)).not.toContain('SENDER_REPLY_TO_FREEMAIL');
  });

  it('accepts e-invoice PDFs, JSON-LD markup and AMP parts', async () => {
    const facturX = await analyze(
      attachment(
        'invoice.pdf',
        'application/pdf',
        '%PDF-1.7\n<< /Type /EmbeddedFile >> << /Type /Filespec /F (factur-x.xml) /UF (factur-x.xml) >>\n%%EOF',
      ),
    );
    expect(ruleIds(facturX)).not.toContain('ATTACHMENT_PDF_ACTIVE');
    const jsonLd = await analyze(
      htmlEmail(
        '<script type="application/ld+json">{"@type":"Order"}</script><p>Order shipped</p>',
      ),
    );
    expect(ruleIds(jsonLd)).not.toContain('HTML_ACTIVE_CONTENT');
    const amp = await analyze(
      buildEmail({
        headers: ['Content-Type: multipart/alternative; boundary="amp"'],
        body: '--amp\r\nContent-Type: text/plain\r\n\r\nHello\r\n--amp\r\nContent-Type: text/x-amp-html\r\n\r\n<!doctype html><html amp4email><body>Hi</body></html>\r\n--amp\r\nContent-Type: text/html\r\n\r\n<p>Hello</p>\r\n--amp--\r\n',
      }),
    );
    expect(ruleIds(amp)).not.toContain('ATTACHMENT_HTML');
  });
});

describe('report privacy and indicators', () => {
  it('redacts base64 and userinfo forms of the recipient address', async () => {
    const encoded = btoa('bob@recipient.example');
    const result = await analyze(
      htmlEmail(
        `<a href="https://evil.example/#${encoded}">a</a><a href="https://bob%40recipient.example@evil.example/">b</a>`,
        ['To: bob@recipient.example'],
      ),
    );
    const json = serializeReport(
      buildReport(result, { includeRecipients: false, redactEmailsInUrls: false }),
    );
    expect(json).not.toContain(encoded.slice(0, 16));
    expect(json).not.toMatch(/bob(?:%40|@|\[@\])recipient/iu);
  });

  it('defangs every exported domain, address and IP', async () => {
    const report = buildReport(await analyze(readSample('credential-phish')));
    const message = report.message as { from: { address: string; domain: string }[] };
    expect(message.from[0]?.address).toBe('service[@]paypa1-account-security[.]example');
    expect(message.from[0]?.domain).toBe('paypa1-account-security[.]example');
    expect(JSON.stringify(report.authentication)).not.toMatch(/=[a-z0-9-]+\.[a-z]{2,}\b/iu);
    expect(report.transit.originIp?.ip).toBe('203[.]0[.]113[.]45');
    expect(reportAsText(report)).toContain('<service[@]paypa1-account-security[.]example>');
  });

  it('keeps provider relays and gateway hosts out of the indicators', async () => {
    const result = await analyze(
      htmlEmail(
        '<a href="https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2F">x</a>',
        [
          'Received: from relay.example (relay.example [209.85.220.41]) by mx.example; Tue, 20 Oct 2026 10:00:09 +0000\r\nReceived: from origin (origin [203.0.113.7]) by relay.example; Tue, 20 Oct 2026 10:00:05 +0000',
        ],
      ),
    );
    const indicators = collectIndicators(result);
    expect(indicators.ips).toEqual(['203[.]0[.]113[.]7']);
    expect([...indicators.domains, ...indicators.otherDomains]).not.toContain('outlook[.]com');
    expect(indicators.otherDomains).toContain('evil[.]example');
  });

  it('reads only enclosed IPs from Received headers, including bare IPv6', () => {
    expect(
      parseReceived(
        'from EXCH01 (10.0.0.5) by EXCH02 (10.0.0.6) with Microsoft SMTP Server id 14.3.235.1; Tue, 20 Oct 2026 10:00:00 +0000',
        0,
      ).ips,
    ).toEqual(['10.0.0.5', '10.0.0.6']);
    expect(
      parseReceived(
        'from AM6PR05.prod.outlook.com (2603:10a6:208:6e::31) by x.example; Tue, 20 Oct 2026 10:00:00 +0000',
        0,
      ).ips,
    ).toEqual(['2603:10a6:208:6e::31']);
  });

  it('rejects dates without a date shape', async () => {
    const result = await analyze(buildEmail({ headers: ['Date: 1'] }));
    expect(ruleIds(result)).toContain('HEADER_DATE_INVALID');
  });
});
