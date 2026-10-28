import { describe, expect, it } from 'vitest';
import {
  extractComments,
  parseAuthenticationResults,
  parseDkimSignature,
  parseReceivedSpf,
  statusOf,
} from '../src/core/auth';
import { analyze, buildEmail, finding, ruleIds } from './helpers';

describe('Authentication-Results parsing (RFC 8601)', () => {
  it('parses a Gmail-style header with comments and properties', () => {
    const header = parseAuthenticationResults(
      'mx.google.com; dkim=pass header.i=@sender.example header.s=s1 header.b=AbCdEf; spf=pass (google.com: domain of bounce@sender.example designates 203.0.113.5 as permitted sender) smtp.mailfrom=bounce@sender.example; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sender.example',
      3,
    );
    expect(header.authservId).toBe('mx.google.com');
    expect(header.results.map((result) => `${result.method}=${result.result}`)).toEqual([
      'dkim=pass',
      'spf=pass',
      'dmarc=pass',
    ]);
    const spf = header.results[1];
    expect(spf?.properties).toContainEqual({
      key: 'smtp.mailfrom',
      value: 'bounce@sender.example',
    });
    expect(spf?.comments[0]).toContain('designates 203.0.113.5');
    expect(header.results[2]?.comments[0]).toBe('p=REJECT sp=REJECT dis=NONE');
  });

  it('parses Microsoft 365 headers that omit the authserv-id', () => {
    const header = parseAuthenticationResults(
      'spf=pass (sender IP is 203.0.113.9) smtp.mailfrom=sender.example; dkim=pass (signature was verified) header.d=sender.example;dmarc=pass action=none header.from=sender.example;compauth=pass reason=100',
      0,
    );
    expect(header.authservId).toBeNull();
    expect(header.parseWarnings.join(' ')).toContain('No authserv-id');
    expect(header.results.map((result) => result.method)).toEqual([
      'spf',
      'dkim',
      'dmarc',
      'compauth',
    ]);
    expect(header.results[3]).toMatchObject({ result: 'pass', reason: '100' });
  });

  it('handles a version number, "none" and quoted values', () => {
    const none = parseAuthenticationResults('example.org 1; none', 0);
    expect(none.authservId).toBe('example.org');
    expect(none.results).toEqual([]);

    const quoted = parseAuthenticationResults(
      'mx.example; dkim=fail reason="signature verification; failed" header.d=x.example',
      0,
    );
    expect(quoted.results).toHaveLength(1);
    expect(quoted.results[0]?.reason).toBe('signature verification; failed');
  });

  it('ignores semicolons and parentheses inside comments', () => {
    const header = parseAuthenticationResults(
      'mx.example; spf=fail (a; b (nested; deeper)) smtp.mailfrom=x.example; dmarc=fail header.from=x.example',
      0,
    );
    expect(header.results.map((result) => result.method)).toEqual(['spf', 'dmarc']);
    expect(extractComments('a (b (c) d) e').comments).toEqual(['b (c) d']);
  });

  it('parses ARC-Authentication-Results instance numbers', () => {
    const arc = parseAuthenticationResults(
      'i=2; lists.example; dkim=pass header.d=sender.example',
      0,
      'ARC-Authentication-Results',
    );
    expect(arc.arcInstance).toBe(2);
    expect(arc.authservId).toBe('lists.example');
  });

  it('maps result keywords to statuses', () => {
    expect(statusOf('PASS')).toBe('pass');
    expect(statusOf('hardfail')).toBe('fail');
    expect(statusOf('softfail')).toBe('softfail');
    expect(statusOf('temperror')).toBe('error');
    expect(statusOf('permerror')).toBe('error');
    // Microsoft: no DMARC record exists, so this is not a pass.
    expect(statusOf('bestguesspass')).toBe('none');
    expect(statusOf('something-new')).toBe('other');
  });

  it('parses Received-SPF', () => {
    const spf = parseReceivedSpf(
      'softfail (mx.example: domain of transitioning x@y.example does not designate 203.0.113.1 as permitted sender) client-ip=203.0.113.1; envelope-from=x@y.example; helo=mail.y.example;',
      0,
    );
    expect(spf.result).toBe('softfail');
    expect(spf.properties).toContainEqual({ key: 'client-ip', value: '203.0.113.1' });
    expect(spf.comment).toContain('does not designate');
  });
});

describe('DKIM-Signature parsing (not verification)', () => {
  const signature =
    'v=1; a=rsa-sha256; c=relaxed/relaxed; d=mail.sender.example; s=sel1; t=1792490400;\r\n h=From:To:Subject:Date; bh=AAAA; b=BBBB';

  it('extracts tags and checks alignment with the From organisational domain', () => {
    const parsed = parseDkimSignature(signature, 0, new Set(['sender.example']));
    expect(parsed).toMatchObject({
      version: '1',
      algorithm: 'rsa-sha256',
      domain: 'mail.sender.example',
      selector: 'sel1',
      signedHeaders: ['from', 'to', 'subject', 'date'],
      alignedWithFrom: true,
      bodyLengthLimit: null,
      hasSignature: true,
      parseWarnings: [],
    });
    expect(parsed.timestamp).toBe('2026-10-20T10:00:00.000Z');
  });

  it('reports missing tags and an unsigned From header', () => {
    const parsed = parseDkimSignature('v=1; d=x.example; h=to:subject', 0, new Set());
    expect(parsed.parseWarnings.join(' ')).toContain('Missing required tag b=');
    expect(parsed.parseWarnings.join(' ')).toContain('From header is not listed');
  });

  it('reads the body-length limit', () => {
    expect(parseDkimSignature(`${signature}; l=200`, 0, new Set()).bodyLengthLimit).toBe(200);
  });
});

describe('authentication findings', () => {
  const withAuth = (...headers: string[]) =>
    analyze(buildEmail({ headers: ['From: Alice <alice@sender.example>', ...headers] }));

  it('never claims independent verification', async () => {
    const result = await withAuth(
      'Authentication-Results: mx.recipient.example; spf=pass smtp.mailfrom=sender.example; dkim=pass header.d=sender.example; dmarc=pass header.from=sender.example',
    );
    expect(result.authentication.independentlyVerified).toBe(false);
    const pass = finding(result, 'AUTH_REPORTED_PASS');
    expect(pass?.severity).toBe('info');
    expect(pass?.instances[0]?.message).toContain('PhishLens did not verify this');
    expect(pass?.rationale).toMatch(/can be forged/u);
  });

  it('does not let reported passes produce a "safe" assessment', async () => {
    const result = await withAuth(
      'Authentication-Results: mx.recipient.example; spf=pass smtp.mailfrom=sender.example; dkim=pass header.d=sender.example; dmarc=pass header.from=sender.example',
    );
    expect(result.assessment.level).toBe('none');
    expect(result.assessment.label.toLowerCase()).not.toContain('safe');
    expect(result.assessment.summary).toContain('does not mean the message is safe');
  });

  it('turns a reported DMARC failure into a high-severity finding that names the reporter', async () => {
    const result = await withAuth(
      'Authentication-Results: mx.recipient.example; spf=fail smtp.mailfrom=sender.example; dkim=fail header.d=sender.example; dmarc=fail header.from=sender.example',
    );
    expect(finding(result, 'AUTH_REPORTED_DMARC_FAIL')?.instances[0]?.message).toContain(
      'reported by "mx.recipient.example"',
    );
    expect(ruleIds(result)).toEqual(
      expect.arrayContaining(['AUTH_REPORTED_SPF_FAIL', 'AUTH_REPORTED_DKIM_FAIL']),
    );
    expect(result.assessment.level).toBe('high');
  });

  it('uses the topmost header for the summary', async () => {
    const result = await withAuth(
      'Authentication-Results: mx.recipient.example; dmarc=fail header.from=sender.example',
      'Authentication-Results: attacker-added.example; dmarc=pass header.from=sender.example',
    );
    expect(result.authentication.reported.dmarc).toMatchObject({
      result: 'fail',
      authservId: 'mx.recipient.example',
    });
    expect(ruleIds(result)).toContain('AUTH_MULTIPLE_AUTHSERV');
  });

  it('prefers a passing DKIM result when one of several signatures passes', async () => {
    const result = await withAuth(
      'Authentication-Results: mx.recipient.example; dkim=fail header.d=old.example; dkim=pass header.d=sender.example',
    );
    expect(result.authentication.reported.dkim?.status).toBe('pass');
    expect(ruleIds(result)).not.toContain('AUTH_REPORTED_DKIM_FAIL');
  });

  it('flags reported results that refer to another domain', async () => {
    const result = await withAuth(
      'Authentication-Results: mx.recipient.example; dmarc=pass header.from=some-other.example',
    );
    expect(ruleIds(result)).toContain('AUTH_RESULTS_DOMAIN_MISMATCH');
  });

  it('falls back to Received-SPF when no Authentication-Results header exists', async () => {
    const result = await withAuth(
      'Received-SPF: fail (mx.example: domain does not designate 203.0.113.1) client-ip=203.0.113.1;',
    );
    expect(finding(result, 'AUTH_REPORTED_SPF_FAIL')?.instances[0]?.message).toContain(
      'Received-SPF',
    );
    expect(ruleIds(result)).not.toContain('AUTH_RESULTS_ABSENT');
  });

  it('notes the absence of authentication results without penalising it', async () => {
    const result = await withAuth();
    expect(finding(result, 'AUTH_RESULTS_ABSENT')?.severity).toBe('info');
  });

  it('flags DKIM l= and unaligned or malformed signatures', async () => {
    const result = await withAuth(
      'DKIM-Signature: v=1; a=rsa-sha256; d=esp.example; s=k1; h=from:subject; l=100; bh=AA; b=BB',
      'DKIM-Signature: v=1; d=broken.example',
    );
    expect(ruleIds(result)).toEqual(
      expect.arrayContaining([
        'AUTH_DKIM_BODY_LENGTH',
        'AUTH_DKIM_NOT_ALIGNED',
        'AUTH_DKIM_MALFORMED',
      ]),
    );
  });

  it('labels every authentication finding as reported rather than verified', async () => {
    const result = await withAuth(
      'Authentication-Results: mx.recipient.example; spf=softfail smtp.mailfrom=x.example; dkim=temperror; dmarc=fail header.from=sender.example',
    );
    const auth = result.findings.filter((entry) => entry.category === 'authentication');
    expect(auth.length).toBeGreaterThan(0);
    for (const entry of auth) {
      const text = `${entry.title} ${entry.rationale} ${entry.instances.map((instance) => instance.message).join(' ')}`;
      expect(text, entry.ruleId).toMatch(
        /report|claim|not verif|did not verify|PhishLens did not|unverified/iu,
      );
      expect(text, entry.ruleId).not.toMatch(/\bverified (pass|fail)\b/iu);
    }
  });
});
