import { describe, expect, it } from 'vitest';
import { brandsInDisplayName } from '../src/core/domain';
import { analyze, buildEmail, finding, ruleIds } from './helpers';

const withFrom = (...headers: string[]) => analyze(buildEmail({ headers }));

describe('sender and reply-to analysis', () => {
  it('flags Reply-To on a different organisational domain as low severity only', async () => {
    const result = await withFrom(
      'From: Alice <alice@sender.example>',
      'Reply-To: replies@other.example',
    );
    const match = finding(result, 'SENDER_REPLY_TO_DIFFERENT_DOMAIN');
    expect(match?.severity).toBe('low');
    // Domains in messages are defanged so they stay inert when pasted into tickets.
    expect(match?.instances[0]?.message).toContain('sender[.]example');
    expect(match?.instances[0]?.message).toContain('other[.]example');
  });

  it('does not flag Reply-To on a subdomain of the same organisation', async () => {
    const result = await withFrom(
      'From: News <news@mail.shop.example.co.uk>',
      'Reply-To: help@support.shop.example.co.uk',
    );
    expect(ruleIds(result)).not.toContain('SENDER_REPLY_TO_DIFFERENT_DOMAIN');
  });

  it('treats replies redirected to a free webmail account as medium severity', async () => {
    const result = await withFrom(
      'From: CFO <cfo@company.example>',
      'Reply-To: cfo.private.mailbox@gmail.com',
    );
    expect(finding(result, 'SENDER_REPLY_TO_FREEMAIL')?.severity).toBe('medium');
    expect(ruleIds(result)).not.toContain('SENDER_REPLY_TO_DIFFERENT_DOMAIN');
  });

  it('flags a different Gmail mailbox even though both are on gmail.com', async () => {
    const result = await withFrom(
      'From: alice.sender@gmail.com',
      'Reply-To: someone.else@gmail.com',
    );
    expect(ruleIds(result)).toContain('SENDER_REPLY_TO_FREEMAIL');
  });

  it('does not flag a Reply-To that matches From', async () => {
    const result = await withFrom(
      'From: alice.sender@gmail.com',
      'Reply-To: Alice <Alice.Sender@gmail.com>',
    );
    expect(ruleIds(result)).not.toContain('SENDER_REPLY_TO_FREEMAIL');
  });

  it('records a Return-Path mismatch only as information', async () => {
    const result = await withFrom('Return-Path: <bounce-123@bounces.esp.example>');
    expect(finding(result, 'SENDER_RETURN_PATH_DIFFERENT_DOMAIN')?.severity).toBe('info');
  });

  it('flags a display name that contains a different email address', async () => {
    const result = await withFrom('From: "security@bank.example" <alerts@unrelated.example>');
    expect(ruleIds(result)).toContain('SENDER_DISPLAY_NAME_ADDRESS');
  });

  it('does not flag a display name that repeats the real address', async () => {
    const result = await withFrom('From: "alice@sender.example" <alice@sender.example>');
    expect(ruleIds(result)).not.toContain('SENDER_DISPLAY_NAME_ADDRESS');
  });

  it('flags a brand in the display name sent from an unrelated domain', async () => {
    const result = await withFrom('From: "PayPal Service" <noreply@billing-center.example>');
    expect(finding(result, 'SENDER_DISPLAY_NAME_BRAND')?.severity).toBe('medium');
  });

  it('flags a brand name sent from a free webmail account as high severity', async () => {
    const result = await withFrom('From: "Netflix Billing" <netflix.billing.team@gmail.com>');
    expect(finding(result, 'SENDER_FREEMAIL_BRAND')?.severity).toBe('high');
  });

  it('uses medium severity when the free mailbox belongs to the named brand', async () => {
    const result = await withFrom('From: "Microsoft account team" <ms.account.team@outlook.com>');
    expect(ruleIds(result)).toContain('SENDER_DISPLAY_NAME_BRAND');
    expect(ruleIds(result)).not.toContain('SENDER_FREEMAIL_BRAND');
  });

  it('flags look-alike sender domains', async () => {
    for (const domain of [
      'paypa1.com',
      'rnicrosoft.com',
      'g00gle-security.com',
      'arnazon.co',
      'dropb0x.com',
    ]) {
      const result = await withFrom(`From: Support <support@${domain}>`);
      expect(ruleIds(result), domain).toContain('SENDER_LOOKALIKE_DOMAIN');
    }
  });

  it('flags brand names embedded in unrelated sender domains', async () => {
    const result = await withFrom('From: Support <support@paypal-billing-help.com>');
    expect(ruleIds(result)).toContain('SENDER_BRAND_IN_DOMAIN');
  });

  it('flags internationalized and mixed-script sender domains', async () => {
    const idn = await withFrom('From: Info <info@xn--mnchen-3ya.example>');
    expect(ruleIds(idn)).toContain('SENDER_IDN_DOMAIN');
    expect(ruleIds(idn)).not.toContain('SENDER_MIXED_SCRIPT_DOMAIN');

    const mixed = await withFrom('From: Support <support@xn--pypal-4ve.com>');
    expect(ruleIds(mixed)).toContain('SENDER_MIXED_SCRIPT_DOMAIN');
    expect(ruleIds(mixed)).toContain('SENDER_LOOKALIKE_DOMAIN');
  });

  it('flags hidden direction-changing characters in the subject', async () => {
    const result = await withFrom('Subject: =?UTF-8?Q?Invoice_=E2=80=AEfdp.exe?=');
    expect(ruleIds(result)).toContain('HEADER_SUBJECT_BIDI');
  });

  it('flags a Sender header from another organisation as information', async () => {
    const result = await withFrom('Sender: assistant@delegate.example');
    expect(finding(result, 'SENDER_HEADER_DIFFERS')?.severity).toBe('info');
  });

  it('flags an unparseable From address', async () => {
    const result = await withFrom('From: Totally not an address');
    expect(ruleIds(result)).toContain('SENDER_INVALID_ADDRESS');
  });
});

describe('sender false positives', () => {
  it('does not flag official brand senders', async () => {
    const cases = [
      'From: "PayPal" <service@paypal.com>',
      'From: "Microsoft account team" <account-security-noreply@accountprotection.microsoft.com>',
      'From: "Google" <no-reply@accounts.google.com>',
      'From: "Amazon.co.uk" <shipment-tracking@amazon.co.uk>',
      'From: "Apple" <no_reply@email.apple.com>',
      'From: "Facebook" <security@facebookmail.com>',
      'From: "DHL Express" <noreply@dhl.de>',
    ];
    for (const from of cases) {
      const ids = ruleIds(await withFrom(from));
      expect(ids, from).not.toContain('SENDER_DISPLAY_NAME_BRAND');
      expect(ids, from).not.toContain('SENDER_FREEMAIL_BRAND');
      expect(ids, from).not.toContain('SENDER_LOOKALIKE_DOMAIN');
      expect(ids, from).not.toContain('SENDER_BRAND_IN_DOMAIN');
    }
  });

  it('does not treat people who share a name with a brand as impersonation', () => {
    expect(brandsInDisplayName('Chase Miller')).toEqual([]);
    expect(brandsInDisplayName('Apple Martin')).toEqual([]);
    expect(brandsInDisplayName('Zoom Photography Studio')).toEqual([]);
    expect(brandsInDisplayName('Chase Bank Security').map((brand) => brand.name)).toContain(
      'Chase',
    );
  });

  it('does not flag ordinary words that contain a brand name', async () => {
    for (const domain of [
      'purchase-orders.example',
      'pineapple.example',
      'groups.example',
      'finance-team.example',
      'cloud.example',
    ]) {
      const ids = ruleIds(await withFrom(`From: Team <team@${domain}>`));
      expect(ids, domain).not.toContain('SENDER_LOOKALIKE_DOMAIN');
      expect(ids, domain).not.toContain('SENDER_BRAND_IN_DOMAIN');
    }
  });

  it('produces no sender findings for an ordinary message', async () => {
    const result = await analyze(buildEmail());
    expect(result.findings.filter((entry) => entry.category === 'sender')).toEqual([]);
  });
});
