# Privacy

PhishLens is designed so that the messages you analyse never leave your device. This page explains exactly what happens to your data and where those guarantees stop.

## What PhishLens processes

When you choose a file, drop one, paste text or load a built-in sample, PhishLens reads the raw message: its headers, bodies and attachments. Everything is processed:

- **in memory**, inside the browser tab you are using,
- **in a Web Worker** that is created for one analysis and terminated as soon as the result is ready, which releases the parser's copy of the message,
- **without any network request** caused by the message.

The analysis result (findings, parsed headers, defanged links, attachment metadata and hashes, plus bounded text previews of the body for the Content tab) stays in the page's memory until you start a new analysis, reload, or close the tab. If you analyse an attached message, the parent message is kept in memory so you can go back to it. The browser's Back button is supported without putting any message data in the URL or browser history.

## What PhishLens never does

- Upload the message or any part of it to a server.
- Write messages or results to `localStorage`, `sessionStorage`, IndexedDB, cookies or the Cache API. This is enforced by lint rules and checked by tests.
- Open, prefetch or resolve links found in the message, or perform DNS lookups.
- Load the message's remote images, stylesheets or tracking pixels.
- Send data to analytics, telemetry, error-reporting or reputation services. There are none.
- Load remote fonts or third-party scripts. All code and fonts are served from the same origin as the page.

The production build enforces the network part with a Content Security Policy that includes `connect-src 'none'`, so the page cannot make fetch, XHR or WebSocket requests even if a bug tried to.

## Exported reports

**Export report** builds a JSON file in memory and hands it to your browser's download mechanism. Nothing is sent anywhere. By default the report:

- **includes** findings and their evidence, sender addresses (From, Reply-To, Return-Path, Sender), the subject, date and Message-ID, reported authentication results, the claimed origin IP and transit hops (server names and IP addresses), defanged links and indicators, attachment names, types, sizes and SHA-256 hashes, and the SHA-256 of the input;
- **excludes** message bodies, raw header text and attachment contents;
- **redacts** recipient addresses (To, Cc, Delivered-To) everywhere they appear, including inside links in plain, percent-encoded, defanged and base64-encoded form, and replaces any other email address found inside links with `[email]`;
- **defangs** every domain, address and IP address, so pasting the report into chat or ticket tools cannot create clickable links.

You can include recipient addresses, or turn off link redaction, in the export panel. Review a report before sharing it: subjects, sender addresses and server names can still identify people or organisations.

**Copy summary** places a plain-text version of the same report on your clipboard, built with the same options and redaction. The other **Copy** buttons place defanged links, indicators or hashes on your clipboard, where other applications can read them.

## Hosting

When PhishLens is served from GitHub Pages, loading the page sends a normal web request to GitHub, which, like any web host, may log your IP address and browser details under the [GitHub Privacy Statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement). The page's own files (HTML, JavaScript, CSS, fonts and icon) are the only requests. Analysing a message causes no further requests. You can also run PhishLens entirely offline from a local build (`npm run build && npm run preview`).

## Limits of these guarantees

- **Browser extensions** with permission to read pages can see everything displayed by PhishLens. Use a profile without extensions for sensitive messages.
- **Your operating system** may write memory to swap or crash dumps, and your browser may keep its own diagnostics. PhishLens cannot clear memory on demand; JavaScript has no way to securely wipe it.
- **The file you selected** stays wherever it already is on your disk; PhishLens neither copies nor deletes it.
- **Development mode** (`npm run dev`) is not covered by the Content Security Policy. Use a production build for real messages.

If you find behaviour that contradicts this document, please report it as described in [SECURITY.md](SECURITY.md).
