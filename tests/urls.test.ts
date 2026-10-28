import { describe, expect, it } from 'vitest';
import { defangEmail, defangUrl, defangUrlsInText, refangUrl } from '../src/core/defang';
import type { UrlRecord } from '../src/core/types';
import { analyzeOccurrences, extractTextUrls, type UrlOccurrence } from '../src/core/urls';
import { analyze, buildEmail, htmlEmail, ruleIds } from './helpers';

function analyzeLinks(occurrences: UrlOccurrence[], baseHref: string | null = null): UrlRecord[] {
  return analyzeOccurrences(occurrences, 100, baseHref).records;
}

function link(url: string, text?: string): UrlRecord {
  const records = analyzeLinks([
    text === undefined ? { kind: 'html-link', url } : { kind: 'html-link', url, text },
  ]);
  const first = records[0];
  if (!first) throw new Error(`no record for ${url}`);
  return first;
}

const flagsOf = (record: UrlRecord) => record.flags.map((flag) => flag.ruleId);

describe('URL extraction from plain text', () => {
  it('finds http(s), www and dangerous schemes and trims trailing punctuation', () => {
    const text =
      'Visit https://a.example/path?x=1. Or (see https://b.example/wiki/Foo_(bar)), www.c.example/login! javascript:alert(1) and "https://d.example/q".';
    expect(extractTextUrls(text, 50)).toEqual([
      'https://a.example/path?x=1',
      'https://b.example/wiki/Foo_(bar)',
      'www.c.example/login',
      'javascript:alert(1)',
      'https://d.example/q',
    ]);
  });

  it('does not treat ordinary words followed by a colon as URLs', () => {
    expect(extractTextUrls('Profile: John. File: report.pdf. Data: 42. metadata:none', 10)).toEqual(
      [],
    );
  });

  it('respects the extraction cap', () => {
    const many = Array.from({ length: 50 }, (_, i) => `https://h${i}.example/`).join(' ');
    expect(extractTextUrls(many, 10)).toHaveLength(10);
  });

  it('finds links in plain-text and HTML bodies and records where they came from', async () => {
    const result = await analyze(
      buildEmail({
        headers: ['Content-Type: multipart/alternative; boundary="x"'],
        body:
          '--x\r\nContent-Type: text/plain\r\n\r\nPlain https://plain.example/a\r\n' +
          '--x\r\nContent-Type: text/html\r\n\r\n<a href="https://anchor.example/b">Read more</a> <p>Unlinked https://unlinked.example/c</p>\r\n--x--\r\n',
      }),
    );
    const byHost = new Map(
      result.urls.map((url) => [url.host, url.sources.map((source) => source.kind)]),
    );
    expect(byHost.get('plain.example')).toContain('plain-text');
    expect(byHost.get('anchor.example')).toEqual(['html-link']);
    expect(byHost.get('unlinked.example')).toContain('html-text');
  });

  it('does not list text inside an anchor as a separate link', async () => {
    const result = await analyze(
      htmlEmail('<a href="https://evil.example/">https://www.bank.example/</a>'),
    );
    expect(result.urls.map((url) => url.host)).toEqual(['evil.example']);
  });
});

describe('defanging', () => {
  it('defangs web URLs, IPs, userinfo and opaque schemes', () => {
    expect(defangUrl('https://evil.example/a.b?c=d.e')).toBe('hxxps[://]evil[.]example/a.b?c=d.e');
    expect(defangUrl('http://198.51.100.7:8080/x')).toBe('hxxp[://]198[.]51[.]100[.]7:8080/x');
    expect(defangUrl('https://trusted.example@evil.example/')).toBe(
      'hxxps[://]trusted[.]example[@]evil[.]example/',
    );
    expect(defangUrl('ftp://files.example/f')).toBe('fxp[://]files[.]example/f');
    expect(defangUrl('mailto:a@b.example')).toBe('mailto[:]a[@]b[.]example');
    expect(defangUrl('javascript:alert(document.cookie)')).toBe(
      'javascript[:]alert(document[.]cookie)',
    );
    expect(defangUrl('www.example.com/x')).toBe('www[.]example[.]com/x');
    expect(defangEmail('a.b@c.example')).toBe('a[.]b[@]c[.]example');
  });

  it('is reversible, so defanging never loses information', () => {
    for (const url of [
      'https://evil.example/path?x=1#y',
      'http://198.51.100.7/',
      'https://user@host.example/',
    ]) {
      expect(refangUrl(defangUrl(url))).toBe(url);
    }
  });

  it('defangs every URL inside free text', () => {
    expect(defangUrlsInText('Go to https://a.example/x or www.b.example now')).toBe(
      'Go to hxxps[://]a[.]example/x or www[.]b[.]example now',
    );
  });

  it('never leaves a clickable URL in any analysed record', async () => {
    const result = await analyze(
      htmlEmail(
        '<a href="https://a.example/x">https://b.example/</a><a href="http://198.51.100.1/">x</a>',
      ),
    );
    for (const url of result.urls) {
      expect(url.defanged).not.toMatch(/^[a-z]+:\/\//iu);
      expect(url.defanged).toContain('[');
    }
  });
});

describe('URL heuristics', () => {
  it('flags raw and obfuscated IP hosts', () => {
    expect(flagsOf(link('http://198.51.100.23/login'))).toContain('URL_IP_HOST');
    expect(flagsOf(link('http://[2001:db8::1]/'))).toContain('URL_IP_HOST');
    for (const obfuscated of [
      'http://3325256727/',
      'http://0xc6.0x33.0x64.0x17/',
      'http://0306.063.0144.027/',
    ]) {
      const record = link(obfuscated);
      expect(flagsOf(record), obfuscated).toContain('URL_OBFUSCATED_IP');
      expect(record.host).toBe('198.51.100.23');
    }
  });

  it('flags userinfo that disguises the real host', () => {
    const record = link('https://www.bank.example@evil.example/login');
    expect(record.host).toBe('evil.example');
    expect(flagsOf(record)).toContain('URL_USERINFO');
  });

  it('flags dangerous and unusual schemes, including obfuscated ones', () => {
    expect(flagsOf(link('javascript:alert(1)'))).toContain('URL_DANGEROUS_SCHEME');
    expect(flagsOf(link('java\tscript:alert(1)'))).toContain('URL_DANGEROUS_SCHEME');
    expect(flagsOf(link('data:text/html;base64,PHNjcmlwdD4='))).toContain('URL_DANGEROUS_SCHEME');
    expect(flagsOf(link('VBScript:msgbox'))).toContain('URL_DANGEROUS_SCHEME');
    expect(flagsOf(link('file:///C:/Windows/System32/calc.exe'))).toContain('URL_UNUSUAL_SCHEME');
    expect(
      flagsOf(link('search-ms:query=invoice&crumb=location:\\\\198.51.100.5\\share')),
    ).toContain('URL_UNUSUAL_SCHEME');
  });

  it('does not flag mailto and tel links', () => {
    expect(link('mailto:help@company.example').flags).toEqual([]);
    expect(link('tel:+15550100').flags).toEqual([]);
  });

  it('flags punycode, mixed scripts and homographs', () => {
    const homograph = link('https://xn--pypal-4ve.com/');
    expect(homograph.hostUnicode).toBe('p\u0430ypal.com');
    expect(flagsOf(homograph)).toEqual(
      expect.arrayContaining(['URL_PUNYCODE', 'URL_MIXED_SCRIPT', 'URL_LOOKALIKE_DOMAIN']),
    );

    const legitimateIdn = link('https://xn--mnchen-3ya.example/');
    expect(flagsOf(legitimateIdn)).toContain('URL_PUNYCODE');
    expect(flagsOf(legitimateIdn)).not.toContain('URL_MIXED_SCRIPT');
  });

  it('flags look-alike and brand-abusing domains', () => {
    expect(flagsOf(link('https://paypa1.com/'))).toContain('URL_LOOKALIKE_DOMAIN');
    expect(flagsOf(link('https://micros0ft-login.com/'))).toContain('URL_LOOKALIKE_DOMAIN');
    expect(flagsOf(link('https://linkedln.com/'))).toContain('URL_LOOKALIKE_DOMAIN');
    expect(flagsOf(link('https://paypal.com.secure-login.example/'))).toContain(
      'URL_BRAND_IN_SUBDOMAIN',
    );
    expect(flagsOf(link('https://docusign-review.example/'))).toContain('URL_BRAND_KEYWORD');
  });

  it('flags shorteners, insecure HTTP, odd ports, encoded hosts, risky TLDs and long hosts', () => {
    expect(flagsOf(link('https://bit.ly/abc'))).toContain('URL_SHORTENER');
    expect(flagsOf(link('http://plain.example/'))).toContain('URL_INSECURE_HTTP');
    expect(flagsOf(link('https://shop.example:8443/'))).toContain('URL_NONSTANDARD_PORT');
    const encoded = link('https://%65vil.example/');
    expect(encoded.host).toBe('evil.example');
    expect(flagsOf(encoded)).toContain('URL_ENCODED_HOST');
    expect(flagsOf(link('https://invoice.zip/'))).toContain('URL_RISKY_TLD');
    expect(flagsOf(link('https://a.b.c.d.e.f.example.com/'))).toContain('URL_COMPLEX_HOSTNAME');
  });

  it('flags shared hosting, tunnels and IPFS gateways', () => {
    expect(flagsOf(link('https://login-portal.web.app/'))).toContain('URL_SHARED_HOSTING');
    expect(flagsOf(link('https://abc123.ngrok-free.app/'))).toContain('URL_TUNNEL_OR_DYNAMIC_DNS');
    expect(
      flagsOf(
        link('https://ipfs.io/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi'),
      ),
    ).toContain('URL_IPFS');
  });

  it('flags links to risky downloads', () => {
    expect(flagsOf(link('https://files.example/Invoice%20Q3.exe'))).toContain('URL_RISKY_DOWNLOAD');
    expect(flagsOf(link('https://files.example/report.pdf'))).not.toContain('URL_RISKY_DOWNLOAD');
  });

  it('unwraps Microsoft Safe Links and analyses the original destination with its link text', () => {
    const wrapped =
      'https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin&data=05%7C01&reserved=0';
    const records = analyzeLinks([
      { kind: 'html-link', url: wrapped, text: 'https://www.paypal.com/' },
    ]);
    const outer = records.find((record) =>
      record.host?.endsWith('safelinks.protection.outlook.com'),
    );
    const inner = records.find((record) => record.host === 'evil.example');
    expect(flagsOf(outer!)).toEqual(['URL_SECURITY_WRAPPER']);
    expect(flagsOf(inner!)).toContain('URL_TEXT_BRAND_MISMATCH');
  });

  it('decodes Proofpoint URL Defense v2 links', () => {
    const records = analyzeLinks([
      {
        kind: 'html-link',
        url: 'https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_path&d=DwMF&c=x',
      },
    ]);
    expect(records.map((record) => record.normalized)).toContain('https://evil.example/path');
  });

  it('records redirect parameters that point to another domain', () => {
    const record = link('https://tracker.example/r?url=https%3A%2F%2Fdestination.example%2Fx');
    expect(record.embedded[0]).toMatchObject({
      kind: 'redirect-parameter',
      registrableDomain: 'destination.example',
    });
    expect(flagsOf(record)).toContain('URL_EMBEDDED_REDIRECT');
  });

  it('ignores relative links unless a base URL is set', () => {
    expect(
      analyzeLinks([
        { kind: 'html-link', url: '#top' },
        { kind: 'html-link', url: '/path' },
      ]),
    ).toEqual([]);
    const based = analyzeLinks([{ kind: 'html-link', url: '/login' }], 'https://evil.example/');
    expect(based[0]?.normalized).toBe('https://evil.example/login');
  });

  it('flags unparseable links', () => {
    expect(flagsOf(link('https://exa mple.com/'))).toContain('URL_UNPARSEABLE');
  });

  it('de-duplicates links and merges their sources', () => {
    const records = analyzeLinks([
      { kind: 'html-link', url: 'https://a.example/x', text: 'one' },
      { kind: 'html-link', url: 'HTTPS://A.EXAMPLE/x', text: 'two' },
      { kind: 'plain-text', url: 'https://a.example/x' },
    ]);
    expect(records).toHaveLength(1);
    expect(records[0]?.sources).toHaveLength(3);
  });
});

describe('link text versus destination', () => {
  it('flags text that shows a different domain', () => {
    expect(flagsOf(link('https://evil.example/login', 'www.shop.example/account'))).toContain(
      'URL_TEXT_MISMATCH',
    );
  });

  it('escalates when the displayed domain belongs to a known brand', () => {
    const record = link('http://login.evil.example/', 'https://www.paypal.com/signin');
    expect(flagsOf(record)).toContain('URL_TEXT_BRAND_MISMATCH');
    expect(flagsOf(record)).not.toContain('URL_TEXT_MISMATCH');
  });

  it('does not flag matching domains, subdomains or descriptive text', () => {
    expect(flagsOf(link('https://www.shop.example/a', 'shop.example'))).not.toContain(
      'URL_TEXT_MISMATCH',
    );
    expect(flagsOf(link('https://mail.shop.example/a', 'https://www.shop.example'))).not.toContain(
      'URL_TEXT_MISMATCH',
    );
    expect(flagsOf(link('https://evil.example/', 'Click here'))).not.toContain('URL_TEXT_MISMATCH');
    expect(flagsOf(link('https://evil.example/', 'Download invoice.pdf'))).not.toContain(
      'URL_TEXT_MISMATCH',
    );
  });

  it('does not flag tracking redirects that end at the displayed domain', () => {
    const record = link(
      'https://click.esp.example/c?url=https%3A%2F%2Fwww.shop.example%2Fsale',
      'www.shop.example/sale',
    );
    expect(flagsOf(record)).not.toContain('URL_TEXT_MISMATCH');
  });

  it('does not flag an http link whose scheme PhishLens assumed', () => {
    const records = analyzeLinks([{ kind: 'plain-text', url: 'www.shop.example/help' }]);
    expect(flagsOf(records[0]!)).not.toContain('URL_INSECURE_HTTP');
  });
});

describe('URL false positives on brand-owned infrastructure', () => {
  it('does not flag brand-owned CDN and service domains', () => {
    for (const url of [
      'https://fonts.googleapis.com/css',
      'https://m.media-amazon.com/images/x.jpg',
      'https://login.microsoftonline.com/common/oauth2',
      'https://tenant.sharepoint.com/sites/x',
      'https://www.google.co.uk/',
      'https://www.amazon.de/',
      'https://connect.facebook.net/sdk.js',
      'https://www.linkedin.com/in/someone',
    ]) {
      const flags = flagsOf(link(url));
      expect(flags, url).not.toContain('URL_BRAND_KEYWORD');
      expect(flags, url).not.toContain('URL_LOOKALIKE_DOMAIN');
    }
  });

  it('does not flag ordinary words that happen to contain or resemble brand names', () => {
    for (const url of [
      'https://finance.example/',
      'https://pineapple.example/',
      'https://purchase.example/',
      'https://mycloud.example/',
    ]) {
      expect(link(url).flags, url).toEqual([]);
    }
  });

  it('produces no link findings for well-formed HTTPS links with descriptive text', async () => {
    const result = await analyze(
      htmlEmail('<p><a href="https://www.shop.example/sale">See the sale</a></p>'),
    );
    expect(ruleIds(result).filter((id) => id.startsWith('URL_'))).toEqual([]);
  });
});
