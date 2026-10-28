import { defangHost as d, defangUrl, defangUrlsInText } from './defang';
import {
  analyzeHost,
  areCousinLabels,
  brandsInDisplayName,
  domainOfAddress,
  isOfficialBrandDomain,
  matchBrandImpersonation,
  mixedScriptLabels,
  officialBrandFor,
  tenantPlatformOf,
} from './domain';
import { FREEMAIL_DOMAINS } from './data/lists';
import { parseAddressList } from './headers';
import type { FindingCollector } from './findings';
import { describeSource } from './labels';
import type { HtmlScan } from './html';
import { hasSpoofingCharacters, pluralize, revealHiddenCharacters, truncate } from './text';
import type {
  AddressInfo,
  AttachmentRecord,
  AuthenticationAnalysis,
  Evidence,
  HeaderAnalysis,
  HtmlSummary,
  UrlRecord,
} from './types';

const DAY_MS = 24 * 60 * 60 * 1000;
const RECEIVED_SKEW_MS = 10 * 60 * 1000;

function describeAddress(address: AddressInfo): string {
  const name = address.name ? `"${revealHiddenCharacters(address.name)}" ` : '';
  return `${name}<${address.address}>`;
}

function orgOf(address: AddressInfo): string | null {
  return address.registrableDomain ?? address.domain;
}

// --------------------------------------------------------------- sender

const EMAIL_IN_TEXT = /[^\s<>"'@(),;:]{1,64}@[^\s<>"'@(),;:]{1,253}\.[^\s<>"'@(),;:]{2,24}/gu;

function checkReplyToLookalike(replyTo: AddressInfo, findings: FindingCollector): void {
  if (!replyTo.domain || replyTo.domain.startsWith('[')) return;
  const info = analyzeHost(replyTo.domain);
  const match = matchBrandImpersonation(info);
  if (!match || match.kind === 'keyword') return;
  findings.add(
    'SENDER_LOOKALIKE_DOMAIN',
    `The Reply-To domain ${d(info.hostUnicode ?? info.host)} resembles ${match.brand.name} ("${match.keyword}").`,
    [{ label: 'Reply-To', value: describeAddress(replyTo) }],
  );
}

/** Organisations the message was addressed to, used to spot cousin domains. */
function recipientOrganisations(headers: HeaderAnalysis): Set<string> {
  const deliveredTo = headers.all
    .filter((entry) => entry.key === 'delivered-to' || entry.key === 'x-original-to')
    .flatMap((entry) => parseAddressList(entry.value));
  return new Set(
    [...headers.to, ...headers.cc, ...deliveredTo]
      .map(orgOf)
      .filter((org): org is string => Boolean(org) && !FREEMAIL_DOMAINS.has(org ?? '')),
  );
}

export function checkSender(headers: HeaderAnalysis, findings: FindingCollector): void {
  const recipientOrgs = recipientOrganisations(headers);
  for (const replyTo of headers.replyTo) checkReplyToLookalike(replyTo, findings);
  const fromCount = headers.counts['from'] ?? 0;
  if (fromCount === 0) {
    findings.add('SENDER_FROM_MISSING', 'The message has no From header.');
  } else if (fromCount > 1) {
    const values = headers.fields.find((field) => field.key === 'from')?.decoded ?? [];
    findings.add(
      'SENDER_MULTIPLE_FROM_HEADERS',
      `The message has ${fromCount} From headers.`,
      values.map((value, i) => ({
        label: `From #${i + 1}`,
        value: truncate(revealHiddenCharacters(value), 300),
      })),
    );
  }

  const fromValues = headers.fields.find((field) => field.key === 'from')?.decoded ?? [];
  for (const value of fromValues) {
    const mailboxes = parseAddressList(value);
    if (mailboxes.length > 1) {
      findings.add(
        'SENDER_MULTIPLE_FROM_ADDRESSES',
        `One From header lists ${mailboxes.length} addresses; mail clients usually show only the first (${mailboxes[0]?.address ?? ''}).`,
        mailboxes.slice(0, 5).map((mailbox, index) => ({
          label: `Address ${index + 1}`,
          value: describeAddress(mailbox),
        })),
      );
    } else if (mailboxes.length === 0) {
      // For example an empty group ("PayPal Security Team:;"), which clients show as a name only.
      findings.add('SENDER_INVALID_ADDRESS', 'The From header names no email address.', [
        { label: 'From', value: truncate(revealHiddenCharacters(value), 300) },
      ]);
      for (const brand of brandsInDisplayName(value.replace(/[:;]/gu, ' '))) {
        findings.add(
          'SENDER_DISPLAY_NAME_BRAND',
          `The From header shows only the name "${truncate(value, 80)}", which mentions ${brand.name}, with no address.`,
        );
      }
    }
  }

  for (const from of headers.from) {
    const evidence: Evidence[] = [{ label: 'From', value: describeAddress(from) }];
    if (from.domainWrittenAs) {
      findings.add(
        'SENDER_LOOKALIKE_DOMAIN',
        `The address domain is written as "${from.domainWrittenAs}" with look-alike characters that software converts to ${d(from.domain ?? '')}.`,
        evidence,
      );
    }
    if (!from.valid) {
      findings.add(
        'SENDER_INVALID_ADDRESS',
        `"${truncate(from.address, 200)}" is not a well-formed address.`,
        evidence,
      );
      continue;
    }
    const fromOrg = orgOf(from);

    const shownName = from.name.slice(0, 1000);
    for (const match of shownName.includes('@') ? shownName.matchAll(EMAIL_IN_TEXT) : []) {
      const shownDomain = domainOfAddress(match[0]);
      const shownOrg = shownDomain
        ? (analyzeHost(shownDomain).registrableDomain ?? shownDomain)
        : null;
      if (shownOrg && shownOrg !== fromOrg) {
        findings.add(
          'SENDER_DISPLAY_NAME_ADDRESS',
          `The name shows ${match[0]}, but the message was sent from ${from.address}.`,
          evidence,
        );
        break;
      }
    }

    const info = from.domain && !from.domain.startsWith('[') ? analyzeHost(from.domain) : null;
    if (from.name) {
      for (const brand of brandsInDisplayName(from.name)) {
        const isFreemail = fromOrg !== null && FREEMAIL_DOMAINS.has(fromOrg);
        // A domain written with look-alike characters is never treated as the brand's own.
        const brandOwnsMailbox =
          info !== null && !from.domainWrittenAs && isOfficialBrandDomain(brand, info);
        if (isFreemail && !brandOwnsMailbox) {
          findings.add(
            'SENDER_FREEMAIL_BRAND',
            `The name mentions ${brand.name}, but the address is on the free webmail service ${d(fromOrg ?? '')}.`,
            evidence,
          );
        } else if (!info || !brandOwnsMailbox || isFreemail) {
          findings.add(
            'SENDER_DISPLAY_NAME_BRAND',
            isFreemail
              ? `The name mentions ${brand.name} and the address is a free ${d(fromOrg ?? '')} mailbox, which anyone can register.`
              : `The name mentions ${brand.name}, but ${fromOrg ? d(fromOrg) : 'the sending domain'} is not a domain PhishLens associates with ${brand.name}.`,
            evidence,
          );
        }
      }
    }

    if (info) {
      if (info.hostUnicode) {
        const mixed = mixedScriptLabels(info.hostUnicode);
        if (mixed.length > 0) {
          findings.add(
            'SENDER_MIXED_SCRIPT_DOMAIN',
            `"${d(info.hostUnicode)}" mixes alphabets in "${mixed[0] ?? ''}".`,
            [...evidence, { label: 'Punycode', value: d(info.host) }],
          );
        } else {
          findings.add(
            'SENDER_IDN_DOMAIN',
            `The sending domain displays as "${d(info.hostUnicode)}".`,
            [...evidence, { label: 'Punycode', value: d(info.host) }],
          );
        }
      }
      const brandMatch = matchBrandImpersonation(info);
      if (brandMatch?.kind === 'keyword') {
        findings.add(
          'SENDER_BRAND_IN_DOMAIN',
          `${d(info.registrableDomain ?? info.host)} contains "${brandMatch.keyword}" (${brandMatch.brand.name}) but is not a domain PhishLens associates with ${brandMatch.brand.name}.`,
          evidence,
        );
      } else if (brandMatch) {
        findings.add(
          'SENDER_LOOKALIKE_DOMAIN',
          `${d(info.hostUnicode ?? info.host)} resembles ${brandMatch.brand.name} ("${brandMatch.keyword}").`,
          evidence,
        );
      }
    }

    if (info) {
      const tenant = tenantPlatformOf(info);
      if (tenant) {
        findings.add(
          'SENDER_TENANT_DOMAIN',
          `${d(info.host)} is a ${tenant} default tenant domain, which anyone can create.`,
          evidence,
        );
      }
      const fromLabel = info.label ?? '';
      for (const recipientOrg of recipientOrgs) {
        const recipientLabel = analyzeHost(recipientOrg).label ?? '';
        if (fromOrg !== recipientOrg && areCousinLabels(fromLabel, recipientLabel)) {
          findings.add(
            'SENDER_COUSIN_DOMAIN',
            `The sender's domain ${d(fromOrg ?? '')} is a near-copy of the recipient's domain ${d(recipientOrg)}.`,
            evidence,
          );
        }
      }
    }

    // Mailing lists and notifications from a brand's own domain set Reply-To by design.
    const fromIsBrand =
      info !== null &&
      fromOrg !== null &&
      !FREEMAIL_DOMAINS.has(fromOrg) &&
      officialBrandFor(info) !== null;
    const isMailingList = (headers.counts['list-id'] ?? 0) + (headers.counts['list-post'] ?? 0) > 0;
    for (const replyTo of headers.replyTo) {
      const replyOrg = orgOf(replyTo);
      if (!replyOrg || !fromOrg) continue;
      const replyEvidence = [...evidence, { label: 'Reply-To', value: describeAddress(replyTo) }];
      const differentMailbox = replyTo.address.toLowerCase() !== from.address.toLowerCase();
      const replyLabel = replyTo.domain ? (analyzeHost(replyTo.domain).label ?? '') : '';
      if (replyOrg !== fromOrg && info?.label && areCousinLabels(replyLabel, info.label)) {
        findings.add(
          'SENDER_COUSIN_DOMAIN',
          `The Reply-To domain ${d(replyOrg)} is a near-copy of the From domain ${d(fromOrg)}.`,
          replyEvidence,
        );
        continue;
      }
      if (isMailingList || fromIsBrand) continue;
      if (
        FREEMAIL_DOMAINS.has(replyOrg) &&
        differentMailbox &&
        (replyOrg !== fromOrg || FREEMAIL_DOMAINS.has(fromOrg))
      ) {
        findings.add(
          'SENDER_REPLY_TO_FREEMAIL',
          `Replies would go to ${replyTo.address}, a free ${d(replyOrg)} mailbox.`,
          replyEvidence,
        );
      } else if (replyOrg !== fromOrg) {
        findings.add(
          'SENDER_REPLY_TO_DIFFERENT_DOMAIN',
          `From is on ${d(fromOrg)}, but replies go to ${d(replyOrg)}.`,
          replyEvidence,
        );
      }
    }

    for (const returnPath of headers.returnPath) {
      const returnOrg = orgOf(returnPath);
      if (returnOrg && fromOrg && returnOrg !== fromOrg) {
        findings.add(
          'SENDER_RETURN_PATH_DIFFERENT_DOMAIN',
          `From is on ${d(fromOrg)}, but the envelope sender is on ${d(returnOrg)}.`,
          [...evidence, { label: 'Return-Path', value: returnPath.address }],
        );
      }
    }

    for (const sender of headers.sender) {
      const senderOrg = orgOf(sender);
      if (senderOrg && fromOrg && senderOrg !== fromOrg) {
        findings.add(
          'SENDER_HEADER_DIFFERS',
          `Sent by ${sender.address} on behalf of ${from.address}.`,
          [...evidence, { label: 'Sender', value: describeAddress(sender) }],
        );
      }
    }
  }
}

// -------------------------------------------------------------- headers

export function checkHeaders(headers: HeaderAnalysis, now: Date, findings: FindingCollector): void {
  if (!headers.messageId)
    findings.add('HEADER_MESSAGE_ID_MISSING', 'The message has no Message-ID header.');

  if (!headers.date.raw) {
    findings.add('HEADER_DATE_MISSING', 'The message has no Date header.');
  } else if (!headers.date.iso) {
    findings.add('HEADER_DATE_INVALID', 'The Date header could not be interpreted.', [
      { label: 'Date', value: truncate(headers.date.raw, 200) },
    ]);
  } else if (Date.parse(headers.date.iso) - now.getTime() > DAY_MS) {
    findings.add('HEADER_DATE_FUTURE', `The message is dated ${headers.date.iso}.`, [
      { label: 'Date', value: headers.date.raw },
    ]);
  }

  const spoofable = [
    ...headers.from.map((address) => ({ label: 'From name', value: address.name })),
    { label: 'Subject', value: headers.subject ?? '' },
  ];
  for (const { label, value } of spoofable) {
    if (value && hasSpoofingCharacters(value)) {
      findings.add(
        'HEADER_SUBJECT_BIDI',
        `The ${label.toLowerCase()} contains hidden or direction-changing characters.`,
        [{ label, value: truncate(revealHiddenCharacters(value), 300) }],
      );
    }
  }

  if (headers.received.length === 0) {
    findings.add('HEADER_NO_RECEIVED', 'The message contains no Received headers.');
    return;
  }
  // Received headers are prepended, so reverse them to get chronological order.
  const chronological = [...headers.received].reverse();
  for (let i = 1; i < chronological.length; i += 1) {
    const earlier = chronological[i - 1];
    const later = chronological[i];
    if (!earlier?.dateIso || !later?.dateIso) continue;
    const delta = Date.parse(later.dateIso) - Date.parse(earlier.dateIso);
    if (delta < -RECEIVED_SKEW_MS) {
      findings.add(
        'HEADER_RECEIVED_TIME_ORDER',
        `Hop ${i + 1} is timestamped ${Math.round(-delta / 60000)} minutes before hop ${i}.`,
        [
          { label: `Hop ${i}`, value: `${earlier.by ?? 'unknown'} at ${earlier.dateIso}` },
          { label: `Hop ${i + 1}`, value: `${later.by ?? 'unknown'} at ${later.dateIso}` },
        ],
      );
    }
  }
}

// ------------------------------------------------------- authentication

export function checkAuthentication(
  auth: AuthenticationAnalysis,
  headers: HeaderAnalysis,
  findings: FindingCollector,
): void {
  const { spf, dkim, dmarc } = auth.reported;
  const reporter = (id: string | null) =>
    id ? `reported by "${id}"` : 'reported (no server named)';

  if (auth.authenticationResults.length === 0 && auth.receivedSpf.length === 0) {
    findings.add('AUTH_RESULTS_ABSENT', 'No authentication results are recorded in the message.');
  }

  if (dmarc?.status === 'fail') {
    findings.add(
      'AUTH_REPORTED_DMARC_FAIL',
      `dmarc=${dmarc.result}, ${reporter(dmarc.authservId)}.`,
      [{ label: 'Detail', value: dmarc.detail ?? '—' }],
    );
  }
  const receivedSpf = auth.receivedSpf[0];
  const spfStatus = spf?.status ?? receivedSpf?.status;
  const spfResult = spf?.result ?? receivedSpf?.result ?? '';
  const spfSource = spf ? reporter(spf.authservId) : 'reported in Received-SPF';
  if (spfStatus === 'fail') {
    findings.add('AUTH_REPORTED_SPF_FAIL', `spf=${spfResult}, ${spfSource}.`, [
      { label: 'Detail', value: spf?.detail ?? '—' },
    ]);
  } else if (spfStatus === 'softfail') {
    findings.add('AUTH_REPORTED_SPF_SOFTFAIL', `spf=${spfResult}, ${spfSource}.`, [
      { label: 'Detail', value: spf?.detail ?? '—' },
    ]);
  }
  if (dkim?.status === 'fail') {
    findings.add('AUTH_REPORTED_DKIM_FAIL', `dkim=${dkim.result}, ${reporter(dkim.authservId)}.`, [
      { label: 'Detail', value: dkim.detail ?? '—' },
    ]);
  }
  for (const summary of [spf, dkim, dmarc]) {
    if (summary?.status === 'error') {
      findings.add(
        'AUTH_REPORTED_ERROR',
        `${summary.method}=${summary.result}, ${reporter(summary.authservId)}.`,
      );
    }
  }
  const compauth = auth.authenticationResults[0]?.results.find(
    (result) => result.method.toLowerCase() === 'compauth',
  );
  if (compauth?.status === 'fail') {
    findings.add(
      'AUTH_REPORTED_COMPAUTH_FAIL',
      `compauth=${compauth.result}${compauth.reason ? ` (reason ${compauth.reason})` : ''}, ${reporter(auth.authenticationResults[0]?.authservId ?? null)}.`,
    );
  }
  const passes = [spf, dkim, dmarc].filter((summary) => summary?.status === 'pass');
  if (passes.length > 0) {
    findings.add(
      'AUTH_REPORTED_PASS',
      `The message reports ${passes.map((summary) => `${summary?.method}=${summary?.result}`).join(', ')}. PhishLens did not verify this.`,
    );
  }

  if (auth.authservIds.length > 1) {
    findings.add(
      'AUTH_MULTIPLE_AUTHSERV',
      `Results claim to come from ${auth.authservIds.length} different servers.`,
      [{ label: 'Servers', value: auth.authservIds.join(', ') }],
    );
  }

  const fromOrgs = new Set(headers.from.map(orgOf).filter((org): org is string => Boolean(org)));
  const dmarcHeader = dmarc
    ? auth.authenticationResults.find((header) => header.headerIndex === dmarc.headerIndex)
    : undefined;
  const headerFrom = dmarcHeader?.results
    .find((result) => result.method === 'dmarc')
    ?.properties.find((property) => property.key === 'header.from')?.value;
  // Compare with the first mailbox: it is the one mail clients display.
  const displayedFrom = headers.from[0];
  const displayedOrg = displayedFrom ? orgOf(displayedFrom) : null;
  if (headerFrom && displayedOrg) {
    const reportedOrg =
      analyzeHost(headerFrom.toLowerCase()).registrableDomain ?? headerFrom.toLowerCase();
    if (reportedOrg !== displayedOrg) {
      findings.add(
        'AUTH_RESULTS_DOMAIN_MISMATCH',
        `The DMARC result is for header.from=${d(headerFrom)}, but the displayed From domain is ${d(displayedOrg)}.`,
      );
    }
  }

  const signatures = auth.dkimSignatures;
  if (
    signatures.length > 0 &&
    fromOrgs.size > 0 &&
    !signatures.some((signature) => signature.alignedWithFrom === true)
  ) {
    findings.add(
      'AUTH_DKIM_NOT_ALIGNED',
      `Signature domains: ${signatures.map((signature) => signature.domain ?? 'unknown').join(', ')}; From: ${[...fromOrgs].join(', ')}.`,
    );
  }
  for (const signature of signatures) {
    if (signature.bodyLengthLimit !== null) {
      findings.add(
        'AUTH_DKIM_BODY_LENGTH',
        `The signature for d=${signature.domain ?? 'unknown'} covers only the first ${signature.bodyLengthLimit} bytes of the body.`,
      );
    }
    if (signature.parseWarnings.length > 0) {
      findings.add(
        'AUTH_DKIM_MALFORMED',
        `Signature for d=${signature.domain ?? 'unknown'}: ${signature.parseWarnings.join(' ')}`,
      );
    }
  }
}

// ------------------------------------------------------------- content

const URGENCY_PATTERNS: readonly RegExp[] = [
  /\burgent(?:ly)?\b/iu,
  /\bwithin (?:24|48|72) hours\b/iu,
  /\baction required\b/iu,
  /\bfinal (?:notice|warning|reminder)\b/iu,
  /\b(?:account|mailbox|access)\b.{0,40}\b(?:suspended|locked|disabled|deactivated|terminated|restricted|closed|on hold)\b/iu,
  /\b(?:will be|has been)\s+(?:suspended|locked|disabled|deactivated|terminated|deleted)\b/iu,
  /\b(?:unusual|suspicious|unauthori[sz]ed)\s+(?:sign-?in|log-?in|activity|access|transaction)\b/iu,
  /\bpassword (?:expires|expired|expiring)\b/iu,
];

/**
 * Requests aimed at the reader. "Update your password" alone is left out:
 * password-reset mail you requested says exactly that.
 */
const CREDENTIAL_PATTERNS: readonly RegExp[] = [
  /\b(?:confirm|verify|validate|re-?enter|provide)\s+(?:your\s+)?(?:password|login|credentials|account (?:details|information)|billing (?:details|information)|payment (?:details|information|method)|card (?:details|number))\b/iu,
  /\bupdate\s+your\s+(?:billing (?:details|information)|payment (?:details|information)|card (?:details|number))\b/iu,
  /\benter your (?:password|pin|credentials)\b/iu,
  /\bsign[ -]?in to (?:verify|confirm|restore|unlock|reactivate)\b/iu,
  // Asking for a code, not warning against sharing it ("Do not share this code").
  /\b(?:reply|send|share|provide|forward)\s+(?:us\s+|me\s+)?(?:with\s+)?(?:the|your|this)\s+(?:verification|one-time|security|sign-in|login|6-digit)\s+(?:code|passcode|pin)\b/iu,
];

/**
 * Business email compromise: redirecting payments rather than stealing
 * logins. Phrases must come from the sender's side ("our bank details have
 * changed"), so routine invoices and account notifications do not match.
 */
const PAYMENT_PATTERNS: readonly RegExp[] = [
  /\b(?:our|my)\s+(?:new\s+)?(?:bank(?:ing)?|account|payment|remittance|wire)\s+(?:details|information|instructions)\s+(?:have|has)\s+(?:been\s+)?(?:changed|updated)\b/iu,
  /\b(?:new|updated|changed|different)\s+(?:bank(?:ing)?|remittance|wire)\s+(?:details|account|information|instructions)\b/iu,
  /\b(?:change|update)\s+(?:our|my)\s+(?:bank(?:ing)?|payment|remittance)\s+(?:details|information|instructions|account)\b/iu,
  /\b(?:make|send|process|arrange|initiate|complete)\s+(?:a|an|the)?\s*(?:urgent\s+|quick\s+)?(?:wire|bank|telegraphic)\s+transfer\b/iu,
  /\b(?:buy|purchase|get|pick up)\s+(?:me\s+|us\s+)?(?:some\s+|a\s+few\s+)?(?:\w+\s+)?gift\s?cards?\b/iu,
];

/** A QR code combined with sign-in or account wording: the typical "quishing" pretext. */
const QR_LURE =
  /\bQR[- ]?code\b[\s\S]{0,160}\b(?:authenticat\w*|MFA|2FA|two-factor|multi-factor|sign[ -]?in|log[ -]?in|password|account|re-?enrol\w*|re-?activat\w*|verify|security)\b|\b(?:authenticat\w*|MFA|2FA|two-factor|multi-factor|sign[ -]?in|log[ -]?in|password|account|re-?enrol\w*|re-?activat\w*|verify|security)\b[\s\S]{0,160}\bQR[- ]?code\b/iu;

/** Visible characters below which an image-bearing HTML body counts as image-only. */
const IMAGE_ONLY_TEXT_THRESHOLD = 120;

const MAX_CONTENT_SCAN = 200_000;

function matchedPhrases(patterns: readonly RegExp[], haystack: string): string[] {
  return patterns
    .map((pattern) => pattern.exec(haystack)?.[0])
    .filter((match): match is string => Boolean(match));
}

export function checkContent(
  subject: string | null,
  text: string,
  html: HtmlScan | null,
  findings: FindingCollector,
): void {
  const haystack = `${subject ?? ''}\n${text.slice(0, MAX_CONTENT_SCAN)}`.replace(/\s+/gu, ' ');
  const payment = matchedPhrases(PAYMENT_PATTERNS, haystack);
  if (payment.length > 0) {
    findings.add(
      'CONTENT_PAYMENT_DIVERSION',
      `Found ${payment.length} payment-related phrase${payment.length === 1 ? '' : 's'}.`,
      payment.slice(0, 5).map((phrase) => ({ label: 'Phrase', value: truncate(phrase, 120) })),
    );
  }
  const qr = QR_LURE.exec(haystack)?.[0];
  if (qr) {
    findings.add(
      'CONTENT_QR_CODE_LURE',
      'The message asks you to scan a QR code in connection with your account.',
      [{ label: 'Phrase', value: truncate(qr, 160) }],
    );
  }
  if (html && html.summary.images > 0) {
    const visible = html.visibleText.replace(/\s+/gu, '').length;
    if (visible < IMAGE_ONLY_TEXT_THRESHOLD) {
      findings.add(
        'CONTENT_IMAGE_ONLY',
        `The HTML body shows ${pluralize(html.summary.images, 'image')} and only ${pluralize(visible, 'visible character')}.`,
      );
    }
  }
  const urgency = URGENCY_PATTERNS.map((pattern) => pattern.exec(haystack)?.[0]).filter(
    (match): match is string => Boolean(match),
  );
  if (urgency.length > 0) {
    findings.add(
      'CONTENT_URGENCY_LANGUAGE',
      `Found ${urgency.length} pressure phrase${urgency.length === 1 ? '' : 's'}.`,
      urgency.slice(0, 5).map((phrase) => ({ label: 'Phrase', value: truncate(phrase, 120) })),
    );
  }
  const credential = CREDENTIAL_PATTERNS.map((pattern) => pattern.exec(haystack)?.[0]).filter(
    (match): match is string => Boolean(match),
  );
  if (credential.length > 0) {
    findings.add(
      'CONTENT_CREDENTIAL_REQUEST',
      `Found ${credential.length} request${credential.length === 1 ? '' : 's'} for sensitive information.`,
      credential.slice(0, 5).map((phrase) => ({ label: 'Phrase', value: truncate(phrase, 120) })),
    );
  }
}

// ---------------------------------------------------------------- URLs

export function checkUrls(records: UrlRecord[], findings: FindingCollector): void {
  for (const record of records) {
    const evidence: Evidence[] = [{ label: 'Link', value: record.defanged }];
    const textSource = record.sources.find((source) => source.text);
    if (textSource?.text) {
      evidence.push({
        label: 'Link text',
        value: truncate(revealHiddenCharacters(defangUrlsInText(textSource.text)), 200),
      });
    }
    const first = record.sources[0];
    if (first) evidence.push({ label: 'Found in', value: describeSource(first) });
    for (const urlFlag of record.flags) {
      findings.add(urlFlag.ruleId, urlFlag.label, evidence);
    }
  }
}

/** Newsletter preheaders hide a short preview line; only larger amounts are flagged. */
const HIDDEN_TEXT_THRESHOLD = 300;

export function checkHtml(summary: HtmlSummary, findings: FindingCollector): void {
  if (!summary.present) return;
  const formEvidence = (form: HtmlSummary['forms'][number]): Evidence[] => [
    {
      label: 'Submits to',
      value: form.action
        ? defangUrlsInText(form.action)
        : '(no action: submits to the current page)',
    },
    { label: 'Method', value: form.method.toUpperCase() },
    { label: 'Fields', value: String(form.inputCount) },
  ];
  for (const form of summary.forms) {
    findings.add(
      'HTML_FORM',
      `A form with ${form.inputCount} field${form.inputCount === 1 ? '' : 's'}.`,
      formEvidence(form),
    );
  }
  if (summary.passwordInputs > 0) {
    const passwordForm = summary.forms.find((form) => form.hasPassword);
    findings.add(
      'HTML_PASSWORD_FIELD',
      `The message body contains ${pluralize(summary.passwordInputs, 'password field')}.`,
      passwordForm ? formEvidence(passwordForm) : [],
    );
  }
  if (summary.hiddenTextChars > HIDDEN_TEXT_THRESHOLD) {
    findings.add(
      'HTML_HIDDEN_TEXT',
      `${summary.hiddenTextChars.toLocaleString('en-US')} characters of text are hidden from the reader with CSS.`,
    );
  }
  const active: Evidence[] = [
    { label: 'Scripts', value: String(summary.scripts) },
    { label: 'Frames', value: String(summary.frames) },
    { label: 'Embedded objects', value: String(summary.embeddedObjects) },
    { label: 'Event-handler attributes', value: String(summary.eventHandlerAttributes) },
    { label: 'Automatic redirects', value: String(summary.metaRefresh) },
  ].filter((entry) => entry.value !== '0');
  if (active.length > 0) {
    findings.add(
      'HTML_ACTIVE_CONTENT',
      'The HTML body contains elements that mail clients normally block.',
      active,
    );
  }
  if (summary.remoteImages + summary.remoteResources > 0) {
    findings.add(
      'HTML_REMOTE_CONTENT',
      `${summary.remoteImages} remote image${summary.remoteImages === 1 ? '' : 's'} and ${summary.remoteResources} other remote resource${summary.remoteResources === 1 ? '' : 's'}.`,
      summary.remoteHosts
        .slice(0, 10)
        .map((host) => ({ label: 'Host', value: host.replace(/\./gu, '[.]') })),
    );
  }
  if (summary.baseHref) {
    findings.add('HTML_BASE_TAG', 'The HTML sets a base URL for relative links.', [
      { label: 'Base', value: defangUrl(summary.baseHref) },
    ]);
  }
}

export function checkAttachments(records: AttachmentRecord[], findings: FindingCollector): void {
  for (const record of records) {
    const evidence: Evidence[] = [
      {
        label: 'Name',
        value: record.filename ? revealHiddenCharacters(record.filename) : '(none)',
      },
      { label: 'Declared type', value: record.declaredType || '(none)' },
    ];
    if (record.signature)
      evidence.push({ label: 'Detected format', value: record.signature.label });
    if (record.sha256) evidence.push({ label: 'SHA-256', value: record.sha256 });
    for (const attachmentFlag of record.flags) {
      findings.add(attachmentFlag.ruleId, attachmentFlag.label, evidence);
    }
  }
}
