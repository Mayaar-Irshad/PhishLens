# Security policy

PhishLens analyses messages that are hostile by assumption. This document describes what it protects against, how, and where its protection ends.

## Reporting a vulnerability

Please report security problems privately through GitHub's **Report a vulnerability** button on the repository's _Security_ tab (private vulnerability reporting), not in a public issue. Include:

- the PhishLens version (shown in the page footer),
- your browser and version,
- a minimal `.eml` or input that reproduces the problem, using reserved domains such as `example.com` and no real personal data.

You should receive an acknowledgement within a week. Fixes are released through the normal deployment and noted in the advisory.

### In scope

- Script execution, HTML or markup injection, or style injection from message content (headers, bodies, link text, filenames, MIME parameters).
- Any network request caused by analysing a message (fetching links, images, fonts, DNS-revealing behaviour).
- Persistence of message content in browser storage.
- Denial of service where a message under the size limit makes analysis hang beyond the timeout, or crashes the page rather than the worker.
- Report export leaking content the documentation says is excluded (bodies, raw headers, attachment contents, recipients when redaction is on).
- Misleading output: anything presented as verified or as proof when it is not.

### Out of scope

- Missed detections or false positives in the heuristics. Please open a normal issue with a sanitised sample.
- Attacks that require a compromised browser, malicious browser extension or compromised operating system.
- Vulnerabilities in GitHub Pages itself.

## Threat model

| Asset                         | Threat                                                                                | Mitigation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ----------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The analyst's browser session | Script or markup in the message executes in the PhishLens page                        | The HTML body is parsed with parse5 into an inert object tree and never rendered. All message-derived strings are rendered as React text nodes. ESLint bans `dangerouslySetInnerHTML`, `innerHTML`/`outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function` and `javascript:` URLs in `src/`. Tests render injection payloads through the real UI and assert that no `script`, `img`, `iframe`, `object` or `embed` elements and no event-handler attributes appear.                                                                                                                       |
| The analyst's privacy         | Tracking pixels, remote images or link prefetching reveal that the message was opened | Remote images and resources are only counted, never loaded. Links are never opened, fetched or resolved. The production Content Security Policy sets `connect-src 'none'`, `img-src 'self'` and `default-src 'none'`. Tests stub `fetch`, `XMLHttpRequest`, `WebSocket` and `Image` and assert they are never called.                                                                                                                                                                                                                                                                                         |
| The analyst                   | Accidentally clicking a malicious link                                                | Extracted URLs are never rendered as anchors and are always displayed and copied defanged (`hxxps[://]host[.]tld`). The exported report is swept so it contains no clickable URLs.                                                                                                                                                                                                                                                                                                                                                                                                                            |
| The analyst                   | Visual spoofing with bidirectional overrides, zero-width characters or homographs     | Hidden and direction-changing characters are replaced by visible `U+XXXX` markers. Untrusted text is isolated with `<bdi>`. Non-ASCII letters in domains, addresses and findings are highlighted. Right-to-left-override filenames get a preview of how they display.                                                                                                                                                                                                                                                                                                                                         |
| Availability                  | Oversized, deeply nested or crafted messages exhaust memory or CPU                    | Size limit before reading (10 MB by default, hard cap 50 MB). PostalMime limits on nesting depth (64), part count (2,000) and header size (1 MB), with forwarded messages not parsed inline. HTML nesting deeper than 512 levels is flattened in linear time before parsing (parse5 is quadratic in depth). Caps on links (1,000), attachments (200) and evidence per finding. Attachment inspection reads at most 8 MB per file and lists at most 500 archive entries without decompressing anything. All parsing runs in a Web Worker that is terminated after each analysis and after a 30-second timeout. |
| Integrity of conclusions      | Forged `Authentication-Results` headers make a message look trustworthy               | Results are always labelled as reported, with the reporting server named. PhishLens never claims verification (`independentlyVerified: false` in the data model). Passes produce only an informational note explaining they are not proof, and multiple reporting servers or results for a different domain are flagged. The assessment never says a message is safe.                                                                                                                                                                                                                                         |
| Shared reports                | Personal data leaks when a report is forwarded                                        | Reports exclude bodies, raw headers and attachment contents. Recipient addresses are redacted everywhere by default, including URL-encoded forms inside links, and other email addresses inside links are redacted by default.                                                                                                                                                                                                                                                                                                                                                                                |
| Supply chain                  | Compromised dependency or CI action                                                   | Few runtime dependencies (React, PostalMime, parse5, tldts, punycode, fonts), all pinned to exact versions with a lockfile. CI installs with `npm ci --ignore-scripts`, runs `npm audit`, and pins GitHub Actions to commit SHAs. Dependabot is configured. Nothing is loaded from a CDN at runtime.                                                                                                                                                                                                                                                                                                          |

## Content Security Policy

The production `index.html` carries this policy (injected at build time by `vite.config.ts`):

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self';
connect-src 'none'; worker-src 'self'; manifest-src 'self'; base-uri 'none';
form-action 'none'; object-src 'none'
```

Known limitations of delivering CSP through a `<meta>` tag, which GitHub Pages requires because it cannot set response headers:

- `frame-ancestors` cannot be set by a meta tag, so the page could be framed by another site. PhishLens has no authenticated state or sensitive actions to clickjack.
- A dedicated worker loaded from a URL takes its CSP from its own HTTP response, so the meta policy does not cover the worker script. The worker contains no network code (enforced by lint) and imports only bundled modules.
- The development server (`npm run dev`) runs without the policy because Vite's hot reloading needs inline scripts and a WebSocket. Do not use the dev server to analyse real phishing messages.

## Attachment inspection

Attachments are inspected as bytes, never as documents. ZIP archives are listed from their directory records; entry data is never decompressed or extracted. PDFs are searched for dictionary keywords and `/URI` strings; nothing is rendered. HTML and SVG attachments are parsed by parse5 into an inert tree, exactly like the message body. Shortcut and calendar files are read as text. Attached messages are only parsed when you choose to analyse them.

A file dragged onto the page is always intercepted, even while an analysis is running, so a missed drop can never make the browser open the file itself (which would render an HTML attachment).

## Residual risks

- **Browser and extension trust.** Browser extensions with page access can read anything shown on the page. Analyse sensitive messages in a browser profile without extensions.
- **Parser bugs.** A vulnerability in PostalMime, parse5, tldts, the WHATWG URL parser or the browser itself could be triggered by crafted input. The worker isolation and the absence of rendering limit the impact, but cannot rule it out.
- **Heuristic evasion.** Determined attackers can avoid every rule. PhishLens is an investigation aid, not a security control.
- **Copying indicators.** Defanged links can be refanged by hand. Treat original URLs as dangerous wherever you paste them.
