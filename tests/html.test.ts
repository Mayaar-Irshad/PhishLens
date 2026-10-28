import { afterEach, describe, expect, it, vi } from 'vitest';
import { flattenExcessiveNesting, refreshTarget, scanHtml } from '../src/core/html';
import { analyze, htmlEmail, ruleIds } from './helpers';

const scan = (html: string) => scanHtml(html, 1_000_000, 1000);

describe('HTML scanning with parse5', () => {
  it('extracts anchors with their visible text, including image alt text', () => {
    const result = scan(
      '<a href="https://a.example/">Sign <b>in</b></a><a href="https://b.example/"><img src="cid:x" alt="Bank logo"></a>',
    );
    expect(result.occurrences).toEqual([
      { kind: 'html-link', url: 'https://a.example/', text: 'Sign in' },
      { kind: 'html-link', url: 'https://b.example/', text: 'Bank logo' },
    ]);
  });

  it('decodes entities the way a browser would', () => {
    const result = scan('<a href="https&#58;//evil&#46;example/?a=1&amp;b=2">x</a>');
    expect(result.occurrences[0]?.url).toBe('https://evil.example/?a=1&b=2');
  });

  it('collects forms, password fields and form actions', () => {
    const result = scan(
      '<form action="https://collect.example/post" method="POST"><input name="u"><input type="PASSWORD" name="p"><button formaction="https://other.example/x">Go</button></form>',
    );
    expect(result.summary.forms).toEqual([
      { action: 'https://collect.example/post', method: 'post', hasPassword: true, inputCount: 2 },
    ]);
    expect(result.occurrences.map((entry) => entry.url)).toEqual([
      'https://collect.example/post',
      'https://other.example/x',
    ]);
  });

  it('counts active content without running it', () => {
    const result = scan(
      '<script>window.pwned = 1</script><iframe src="https://frame.example/"></iframe><object data="x.swf"></object><embed src="y"><div onclick="steal()" onmouseover="x()">t</div><meta http-equiv="refresh" content="0; url=https://redirect.example/">',
    );
    expect(result.summary).toMatchObject({
      scripts: 1,
      frames: 1,
      embeddedObjects: 2,
      eventHandlerAttributes: 2,
      metaRefresh: 1,
    });
    expect(result.occurrences.map((entry) => entry.kind)).toEqual(['html-frame', 'html-refresh']);
  });

  it('counts remote images and resources and remembers their hosts', () => {
    const result = scan(
      '<img src="https://pixel.example/t.gif"><img srcset="https://cdn.example/a.png 1x, https://cdn.example/b.png 2x"><div style="background:url(\'https://bg.example/i.png\')"></div><style>.x{background:url(https://css.example/i.png)}</style><table background="https://tbl.example/bg.png"></table><img src="cid:inline@x">',
    );
    expect(result.summary.remoteImages).toBe(4);
    expect(result.summary.remoteResources).toBe(2);
    expect(result.summary.remoteHosts).toEqual(
      expect.arrayContaining([
        'pixel.example',
        'cdn.example',
        'bg.example',
        'css.example',
        'tbl.example',
      ]),
    );
  });

  it('reads links inside <template> and <noscript>, which a mail client could display', () => {
    const result = scan(
      '<template><a href="https://tpl.example/">t</a></template><noscript><a href="https://ns.example/">n</a></noscript>',
    );
    expect(result.occurrences.map((entry) => entry.url)).toEqual([
      'https://tpl.example/',
      'https://ns.example/',
    ]);
  });

  it('records the <base> href', () => {
    expect(scan('<base href="https://base.example/"><a href="/x">x</a>').summary.baseHref).toBe(
      'https://base.example/',
    );
  });

  it('excludes script, style and title text from visible text', () => {
    const result = scan(
      '<title>Hidden title</title><style>.a{}</style><script>var secret</script><p>Visible <a href="#">linked</a> text</p>',
    );
    expect(result.visibleText).toContain('Visible');
    expect(result.visibleText).toContain('linked');
    expect(result.visibleText).not.toMatch(/Hidden title|secret|\.a\{/u);
    expect(result.unlinkedText).not.toContain('linked');
  });

  it('parses refresh targets', () => {
    expect(refreshTarget("5; URL='https://a.example/x'")).toBe('https://a.example/x');
    expect(refreshTarget('0;url=https://b.example')).toBe('https://b.example');
    expect(refreshTarget('30')).toBeNull();
  });

  it('flattens hostile nesting quickly without losing deeply buried links', () => {
    const deep =
      '<div><span>'.repeat(50_000) +
      '<a href="https://deep.example/">deep</a>' +
      '</span></div>'.repeat(50_000);
    const started = performance.now();
    const result = scan(deep);
    expect(performance.now() - started).toBeLessThan(3000);
    expect(result.occurrences).toEqual([
      { kind: 'html-link', url: 'https://deep.example/', text: 'deep' },
    ]);
    expect(result.summary.flattenedTags).toBeGreaterThan(90_000);
  });

  it('leaves normal nesting untouched', () => {
    const normal =
      '<table><tr><td><div><p><a href="https://a.example/">a</a></p></div></td></tr></table>';
    expect(flattenExcessiveNesting(normal)).toEqual({ html: normal, removed: 0 });
  });

  it('survives malformed markup', () => {
    const broken =
      '<a href="https://ok.example/">unclosed <b><i></table></td><<<>>> <a href=https://second.example/>2';
    expect(scan(broken).occurrences.map((entry) => entry.url)).toEqual([
      'https://ok.example/',
      'https://second.example/',
    ]);
  });

  it('truncates oversized HTML and reports it', () => {
    const result = scanHtml(
      `<p>${'a'.repeat(5000)}</p><a href="https://late.example/">late</a>`,
      1000,
      100,
    );
    expect(result.summary.truncated).toBe(true);
    expect(result.occurrences).toEqual([]);
  });
});

describe('HTML analysis safety', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete (globalThis as Record<string, unknown>)['pwned'];
  });

  it('never executes scripts or event handlers in the analysed HTML', async () => {
    const payload =
      '<script>globalThis.pwned = "script"</script><img src=x onerror="globalThis.pwned=\'onerror\'"><svg onload="globalThis.pwned=\'svg\'"></svg><body onload="globalThis.pwned=\'body\'">';
    await analyze(htmlEmail(payload));
    expect((globalThis as Record<string, unknown>)['pwned']).toBeUndefined();
  });

  it('never makes network requests, even for messages full of remote content', async () => {
    const fetchSpy = vi.fn(() => Promise.reject(new Error('network access is forbidden')));
    const xhrSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    vi.stubGlobal('XMLHttpRequest', xhrSpy);
    vi.stubGlobal('WebSocket', xhrSpy);
    vi.stubGlobal('Image', xhrSpy);
    const html =
      '<img src="https://tracker.example/p.gif"><link rel="stylesheet" href="https://css.example/s.css"><script src="https://js.example/a.js"></script><iframe src="https://frame.example/"></iframe><a href="https://bit.ly/x">x</a><meta http-equiv="refresh" content="0;url=https://r.example/">';
    const result = await analyze(htmlEmail(html));
    expect(result.urls.length).toBeGreaterThan(0);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(xhrSpy).not.toHaveBeenCalled();
  });

  it('reports forms, password fields and active content as findings', async () => {
    const result = await analyze(
      htmlEmail(
        '<form action="https://c.example/"><input type="password"></form><script>x()</script><base href="https://b.example/">',
      ),
    );
    expect(ruleIds(result)).toEqual(
      expect.arrayContaining([
        'HTML_FORM',
        'HTML_PASSWORD_FIELD',
        'HTML_ACTIVE_CONTENT',
        'HTML_BASE_TAG',
      ]),
    );
  });
});
