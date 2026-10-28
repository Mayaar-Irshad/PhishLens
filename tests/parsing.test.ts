import { describe, expect, it } from 'vitest';
import { AnalysisError } from '../src/core/errors';
import { analyzeHeaders, parseAddressList, parseReceived } from '../src/core/headers';
import { parseMime } from '../src/core/parse';
import { analyze, analyzeRaw, buildEmail, encode, ruleIds } from './helpers';

describe('MIME parsing with PostalMime', () => {
  it('parses a multipart/alternative message into text and HTML bodies', async () => {
    const raw = buildEmail({
      headers: ['Content-Type: multipart/alternative; boundary="b1"'],
      body: [
        '--b1',
        'Content-Type: text/plain; charset=utf-8',
        '',
        'Plain version https://plain.example/a',
        '--b1',
        'Content-Type: text/html; charset=utf-8',
        'Content-Transfer-Encoding: quoted-printable',
        '',
        '<p>HTML version <a href=3D"https://html.example/b">link</a></p>',
        '--b1--',
        '',
      ].join('\r\n'),
    });
    const email = await parseMime(encode(raw));
    expect(email.text).toContain('Plain version');
    expect(email.html).toContain('href="https://html.example/b"');
  });

  it('decodes base64 attachments without executing or rendering them', async () => {
    const raw = buildEmail({
      headers: ['Content-Type: multipart/mixed; boundary="b2"'],
      body: [
        '--b2',
        'Content-Type: text/plain',
        '',
        'See attached.',
        '--b2',
        'Content-Type: application/pdf; name="report.pdf"',
        'Content-Disposition: attachment; filename="report.pdf"',
        'Content-Transfer-Encoding: base64',
        '',
        Buffer.from('%PDF-1.7\n% sample').toString('base64'),
        '--b2--',
        '',
      ].join('\r\n'),
    });
    const result = await analyze(raw);
    expect(result.attachments).toHaveLength(1);
    expect(result.attachments[0]).toMatchObject({
      filename: 'report.pdf',
      declaredType: 'application/pdf',
      signature: { kind: 'pdf' },
      flags: [],
    });
  });

  it('keeps forwarded messages as attachments instead of mixing them into the outer message', async () => {
    const inner =
      'From: inner@inner.example\r\nSubject: Inner\r\n\r\nInner body https://inner.example/x\r\n';
    const raw = buildEmail({
      headers: ['Content-Type: multipart/mixed; boundary="b3"'],
      body: `--b3\r\nContent-Type: text/plain\r\n\r\nForwarding this.\r\n--b3\r\nContent-Type: message/rfc822\r\n\r\n${inner}--b3--\r\n`,
    });
    const output = await analyzeRaw(raw);
    expect(output.result.urls.map((url) => url.host)).not.toContain('inner.example');
    expect(output.result.attachments[0]?.isEmbeddedMessage).toBe(true);
    expect(ruleIds(output.result)).toContain('ATTACHMENT_EMBEDDED_MESSAGE');
    expect(new TextDecoder().decode(output.embeddedMessages[0]?.bytes)).toContain(
      'inner@inner.example',
    );
  });

  it('rejects messages that exceed parser safety limits', async () => {
    // Built from the innermost level outwards, so the outermost part uses boundary n0.
    let body = 'innermost';
    for (let depth = 79; depth >= 0; depth -= 1) {
      body = `--n${depth}\r\nContent-Type: multipart/mixed; boundary="n${depth + 1}"\r\n\r\n${body}\r\n--n${depth}--`;
    }
    const raw = buildEmail({ headers: ['Content-Type: multipart/mixed; boundary="n0"'], body });
    await expect(parseMime(encode(raw))).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    await expect(parseMime(encode(raw))).rejects.toBeInstanceOf(AnalysisError);
  });

  it('copes with a truncated multipart message', async () => {
    const raw = buildEmail({
      headers: ['Content-Type: multipart/mixed; boundary="cut"'],
      body: '--cut\r\nContent-Type: text/plain\r\n\r\nThe message stops here without a closing boundary https://cut.example/',
    });
    const result = await analyze(raw);
    expect(result.urls.map((url) => url.host)).toContain('cut.example');
  });

  it('copes with a declared but missing boundary', async () => {
    const raw = buildEmail({
      headers: ['Content-Type: multipart/mixed'],
      body: 'No boundary parameter at all.',
    });
    const result = await analyze(raw);
    expect(result.headers.subject).toBe('Quarterly report');
  });
});

describe('header handling', () => {
  it('unfolds folded headers', async () => {
    const raw = buildEmail({
      headers: ['Subject: A subject that is\r\n folded across\r\n\tthree lines'],
    });
    const result = await analyze(raw);
    expect(result.headers.subject).toBe('A subject that is folded across three lines');
  });

  it('keeps every repeated header in order', async () => {
    const raw = [
      'Received: from c.example by d.example; Tue, 20 Oct 2026 10:00:09 +0000',
      'Received: from a.example by c.example; Tue, 20 Oct 2026 10:00:05 +0000',
      'From: first@one.example',
      'From: second@two.example',
      'Subject: duplicates',
      'Date: Tue, 20 Oct 2026 10:00:00 +0000',
      '',
      'body',
    ].join('\r\n');
    const result = await analyze(raw);
    const from = result.headers.fields.find((field) => field.key === 'from');
    expect(from?.values).toEqual(['first@one.example', 'second@two.example']);
    expect(result.headers.from.map((address) => address.address)).toEqual([
      'first@one.example',
      'second@two.example',
    ]);
    expect(result.headers.received.map((hop) => hop.by)).toEqual(['d.example', 'c.example']);
    expect(result.headers.counts['received']).toBe(2);
    expect(ruleIds(result)).toContain('SENDER_MULTIPLE_FROM_HEADERS');
  });

  it('decodes RFC 2047 encoded words', async () => {
    const result = await analyze(
      buildEmail({ headers: ['Subject: =?UTF-8?B?Q2Fmw6kgbWVudQ==?='] }),
    );
    expect(result.headers.subject).toBe('Caf\u00E9 menu');
  });

  it('reports missing fields without failing', async () => {
    const result = await analyze('Subject: only a subject\r\n\r\nbody');
    expect(result.headers.from).toEqual([]);
    expect(result.headers.messageId).toBeNull();
    expect(result.headers.date).toEqual({ raw: null, iso: null, valid: false });
    expect(ruleIds(result)).toEqual(
      expect.arrayContaining([
        'SENDER_FROM_MISSING',
        'HEADER_MESSAGE_ID_MISSING',
        'HEADER_DATE_MISSING',
        'HEADER_NO_RECEIVED',
      ]),
    );
  });

  it('flags invalid and far-future dates', async () => {
    const invalid = await analyze(buildEmail({ headers: ['Date: sometime last week'] }));
    expect(ruleIds(invalid)).toContain('HEADER_DATE_INVALID');
    const future = await analyze(
      buildEmail({ headers: ['Date: Fri, 01 Jan 2049 00:00:00 +0000'] }),
    );
    expect(ruleIds(future)).toContain('HEADER_DATE_FUTURE');
    const normal = await analyze(buildEmail());
    expect(ruleIds(normal)).not.toContain('HEADER_DATE_FUTURE');
  });

  it('parses address lists with display names, quoted commas and groups', () => {
    const addresses = parseAddressList(
      '"Doe, Jane" <jane@a.example>, bob@b.example, Team: carol@c.example, dan@d.example;',
    );
    expect(addresses.map((address) => address.address)).toEqual([
      'jane@a.example',
      'bob@b.example',
      'carol@c.example',
      'dan@d.example',
    ]);
    expect(addresses[0]?.name).toBe('Doe, Jane');
    expect(addresses[2]?.group).toBe('Team');
  });

  it('marks addresses without a usable domain as invalid', () => {
    expect(parseAddressList('not an address')[0]?.valid).toBe(false);
    expect(parseAddressList('user@')[0]?.valid ?? false).toBe(false);
  });

  it('treats a null Return-Path as empty', () => {
    const headers = analyzeHeaders([
      { key: 'return-path', originalKey: 'Return-Path', value: '<>' },
    ]);
    expect(headers.returnPath).toEqual([]);
  });
});

describe('Received header parsing', () => {
  it('extracts hosts, protocol, IPv4 and IPv6 addresses and the date', () => {
    const hop = parseReceived(
      'from mail.sender.example (mail.sender.example [203.0.113.7]) by mx.recipient.example (Postfix) with ESMTPS id ABC123 for <bob@recipient.example>; Tue, 20 Oct 2026 10:00:05 +0000 (UTC)',
      0,
    );
    expect(hop).toMatchObject({
      from: 'mail.sender.example',
      by: 'mx.recipient.example',
      with: 'ESMTPS',
      ips: ['203.0.113.7'],
    });
    expect(hop.dateIso).toBe('2026-10-20T10:00:05.000Z');

    const v6 = parseReceived(
      'from x.example ([IPv6:2001:db8::25]) by y.example; Tue, 20 Oct 2026 10:00:05 +0000',
      1,
    );
    expect(v6.ips).toEqual(['2001:db8::25']);
  });

  it('ignores invalid IPv4-looking numbers', () => {
    expect(
      parseReceived('from x (999.1.1.1) by y; Tue, 20 Oct 2026 10:00:05 +0000', 0).ips,
    ).toEqual([]);
  });

  it('flags timestamps that go backwards along the transit path', async () => {
    const raw = buildEmail({
      headers: [
        'Received: from b.example by c.example; Tue, 20 Oct 2026 08:00:00 +0000\r\nReceived: from a.example by b.example; Tue, 20 Oct 2026 10:00:00 +0000',
      ],
    });
    const result = await analyze(raw);
    expect(ruleIds(result)).toContain('HEADER_RECEIVED_TIME_ORDER');
  });

  it('does not flag small clock skew', async () => {
    const raw = buildEmail({
      headers: [
        'Received: from b.example by c.example; Tue, 20 Oct 2026 09:58:00 +0000\r\nReceived: from a.example by b.example; Tue, 20 Oct 2026 10:00:00 +0000',
      ],
    });
    expect(ruleIds(await analyze(raw))).not.toContain('HEADER_RECEIVED_TIME_ORDER');
  });
});
