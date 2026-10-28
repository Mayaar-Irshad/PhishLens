import { ASSESSMENT_THRESHOLDS } from './assessment';
import { defangEmail, defangHost, defangUrlsInText } from './defang';
import { collectIndicators, indicatorsAsText, type Indicators } from './indicators';
import { describeSource } from './labels';
import { analystSteps, recommendedSteps } from './recommendations';
import { revealHiddenCharacters } from './text';
import type { AddressInfo, AnalysisResult, Assessment, Severity } from './types';
import { REPORT_SCHEMA, TOOL_NAME, TOOL_VERSION } from './version';

/**
 * Builds the exportable JSON report. The report is designed to be shared with
 * a security team, so it contains indicators and findings but never message
 * bodies, raw headers or attachment contents. Recipient addresses are
 * redacted by default, including where they appear inside URLs, because
 * phishing links frequently embed the victim's address.
 */

export interface ReportOptions {
  /** Include To/Cc addresses. When false they are replaced by "[recipient]". */
  includeRecipients: boolean;
  /** Replace every email address found inside URLs with "[email]". */
  redactEmailsInUrls: boolean;
  /** Generation time; injectable for deterministic tests. */
  generatedAt?: Date;
}

export const DEFAULT_REPORT_OPTIONS: ReportOptions = {
  includeRecipients: false,
  redactEmailsInUrls: true,
};

const RECIPIENT_PLACEHOLDER = '[recipient]';
const EMAIL_PLACEHOLDER = '[email]';
const EMAIL_PATTERN = /[a-z0-9._%+-]{1,64}(?:@|%40)[a-z0-9.-]{1,253}\.[a-z]{2,24}/giu;

/** Runs the email pattern only on strings that can contain an address. */
function redactEmails(value: string): string {
  if (!value.includes('@') && !/%40/iu.test(value)) return value;
  return value.replace(EMAIL_PATTERN, EMAIL_PLACEHOLDER);
}
const LIMITATIONS = [
  'Heuristic analysis only: findings indicate characteristics worth investigating, not proof of phishing or of safety.',
  'Authentication results are reported values copied from the message headers. PhishLens did not verify SPF, DKIM or DMARC.',
  'No links were opened, no DNS lookups were made and no reputation services were contacted.',
  'Attachments were not opened or executed. Only their leading bytes were read for format detection, and they were hashed.',
];

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

/** Deep-maps every string in a JSON-compatible value. */
function mapStrings<T>(value: T, transform: (input: string) => string): T {
  if (typeof value === 'string') return transform(value) as T;
  if (Array.isArray(value)) return value.map((item: unknown) => mapStrings(item, transform)) as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>))
      out[key] = mapStrings(item, transform);
    return out as T;
  }
  return value;
}

function recipientAddresses(result: AnalysisResult): string[] {
  const deliveredTo = result.headers.all
    .filter((entry) => ['delivered-to', 'x-original-to', 'envelope-to'].includes(entry.key))
    .map((entry) => entry.value.trim().replace(/^<|>$/gu, ''));
  return [...result.headers.to, ...result.headers.cc]
    .map((address) => address.address)
    .concat(deliveredTo)
    .filter((address) => address.includes('@'));
}

/** Defangs a host, address or "key=value" detail so chat and ticket tools cannot link it. */
function inert(value: string | null): string | null {
  if (value === null) return null;
  return value.replace(/[^\s=,;]+/gu, (token: string, offset: number, whole: string) => {
    if (whole[offset + token.length] === '=') return token; // a key such as "smtp.mailfrom"
    if (token.includes('@')) return defangEmail(token);
    return /\.[a-z0-9]/iu.test(token) ? defangHost(token) : token;
  });
}

function address(info: AddressInfo) {
  return {
    name: revealHiddenCharacters(info.name),
    address: defangEmail(info.address),
    domain: inert(info.domain),
    registrableDomain: inert(info.registrableDomain),
  };
}

/** Binary-safe base64 of a string's UTF-8 bytes. */
function base64(value: string): string {
  let binary = '';
  for (const byte of new TextEncoder().encode(value)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/**
 * Base64 and base64url fragments that appear wherever `value` is encoded
 * inside a longer base64 string, at each of the three byte alignments.
 * Phishing kits commonly pass the victim's address this way.
 */
function base64Forms(value: string): string[] {
  const forms = new Set<string>();
  for (const offset of [0, 1, 2]) {
    const full = base64('\u0000'.repeat(offset) + value);
    const start = offset === 0 ? 0 : offset + 1;
    const end = (offset + value.length) % 3 === 0 ? full.length : full.length - 4;
    const core = full.slice(start, end);
    if (core.length >= 8) {
      forms.add(core);
      forms.add(core.replace(/\+/gu, '-').replace(/\//gu, '_'));
    }
  }
  return [...forms];
}

/** Matches an address written plainly, percent-encoded or defanged ("[@]", "[.]"). */
function flexibleAddressPattern(value: string): string {
  return escapeRegExp(value)
    .replace(/@/gu, '(?:@|%40|\\[@\\])')
    .replace(/\\\./gu, '(?:\\.|\\[\\.\\])');
}

export interface PhishLensReport {
  schema: string;
  tool: { name: string; version: string };
  generatedAt: string;
  privacy: {
    recipientsIncluded: boolean;
    emailsInUrlsRedacted: boolean;
    bodyIncluded: false;
    rawHeadersIncluded: false;
  };
  input: {
    source: string;
    sizeBytes: number;
    sha256: string | null;
    headersOnly: boolean;
    analyzedAt: string;
  };
  assessment: Assessment & { method: string };
  findingCounts: Record<Severity, number>;
  message: Record<string, unknown>;
  authentication: Record<string, unknown>;
  transit: {
    originIp: { ip: string; source: string; note: string } | null;
    hops: Record<string, unknown>[];
  };
  indicators: Indicators;
  urls: Record<string, unknown>[];
  attachments: Record<string, unknown>[];
  findings: Record<string, unknown>[];
  recommendedSteps: string[];
  analystSteps: string[];
  warnings: string[];
  limitations: string[];
}

export function buildReport(
  result: AnalysisResult,
  options: ReportOptions = DEFAULT_REPORT_OPTIONS,
): PhishLensReport {
  const { headers, authentication } = result;
  const recipientCount = headers.to.length + headers.cc.length;

  const report: PhishLensReport = {
    schema: REPORT_SCHEMA,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    generatedAt: (options.generatedAt ?? new Date()).toISOString(),
    privacy: {
      recipientsIncluded: options.includeRecipients,
      emailsInUrlsRedacted: options.redactEmailsInUrls,
      bodyIncluded: false,
      rawHeadersIncluded: false,
    },
    input: {
      source: result.meta.source.kind,
      sizeBytes: result.meta.sizeBytes,
      sha256: result.meta.sha256,
      headersOnly: result.meta.headersOnly,
      analyzedAt: result.meta.analyzedAt,
    },
    assessment: {
      ...result.assessment,
      method: ASSESSMENT_THRESHOLDS.map(
        (threshold) => `${threshold.label}: ${threshold.rule}`,
      ).join(' '),
    },
    findingCounts: result.assessment.counts,
    message: {
      subject: headers.subject === null ? null : revealHiddenCharacters(headers.subject),
      date: headers.date.raw,
      dateIso: headers.date.iso,
      messageId: headers.messageId,
      from: headers.from.map(address),
      replyTo: headers.replyTo.map(address),
      returnPath: headers.returnPath.map((info) => defangEmail(info.address)),
      sender: headers.sender.map(address),
      recipients: options.includeRecipients
        ? { to: headers.to.map(address), cc: headers.cc.map(address) }
        : { count: recipientCount, redacted: true },
    },
    authentication: {
      independentlyVerified: false,
      note: 'Values reported inside the message. Not verified by PhishLens; headers can be forged.',
      reported: Object.fromEntries(
        Object.entries(authentication.reported).map(([method, summary]) => [
          method,
          summary && {
            ...summary,
            detail: inert(summary.detail),
            authservId: inert(summary.authservId),
          },
        ]),
      ),
      reportingServers: authentication.authservIds.map((id) => inert(id)),
      authenticationResults: authentication.authenticationResults.map((header) => ({
        authservId: inert(header.authservId),
        results: header.results.map((result) => ({
          method: result.method,
          result: result.result,
          reason: result.reason,
          properties: Object.fromEntries(
            result.properties.map((property) => [property.key, inert(property.value)]),
          ),
        })),
      })),
      receivedSpf: authentication.receivedSpf.map((spf) => ({
        result: spf.result,
        properties: Object.fromEntries(
          spf.properties.map((property) => [property.key, inert(property.value)]),
        ),
      })),
      dkimSignatures: authentication.dkimSignatures.map((signature) => ({
        domain: inert(signature.domain),
        selector: signature.selector,
        algorithm: signature.algorithm,
        bodyLengthLimit: signature.bodyLengthLimit,
        signedHeaders: signature.signedHeaders,
        alignedWithFrom: signature.alignedWithFrom,
      })),
    },
    transit: {
      originIp: headers.originIp
        ? {
            ip: defangHost(headers.originIp.ip),
            source:
              headers.originIp.source === 'received'
                ? 'earliest Received header'
                : 'X-Originating-IP header',
            note: 'Claimed by the message headers; the sender can forge it.',
          }
        : null,
      hops: [...headers.received].reverse().map((hop, i) => ({
        hop: i + 1,
        from: inert(hop.from),
        by: inert(hop.by),
        with: hop.with,
        ips: hop.ips.map(defangHost),
        date: hop.dateIso ?? hop.dateRaw,
      })),
    },
    indicators: collectIndicators(result),
    urls: result.urls.map((url) => ({
      defanged: url.defanged,
      scheme: url.scheme,
      host: url.host === null ? null : url.host.replace(/\./gu, '[.]'),
      hostUnicode: url.hostUnicode,
      registrableDomain:
        url.registrableDomain === null ? null : url.registrableDomain.replace(/\./gu, '[.]'),
      sources: url.sources.map(describeSource),
      embedded: url.embedded.map((entry) => ({
        kind: entry.kind,
        parameter: entry.parameter,
        defanged: entry.defanged,
      })),
      flags: url.flags.map((flag) => ({
        ruleId: flag.ruleId,
        severity: flag.severity,
        detail: flag.label,
      })),
    })),
    attachments: result.attachments.map((attachment) => ({
      filename: attachment.filename === null ? null : revealHiddenCharacters(attachment.filename),
      declaredType: attachment.declaredType,
      sizeBytes: attachment.sizeBytes,
      sha256: attachment.sha256,
      detectedFormat: attachment.signature?.label ?? null,
      encryptedArchive: attachment.encryptedArchive,
      flags: attachment.flags.map((flag) => ({
        ruleId: flag.ruleId,
        severity: flag.severity,
        detail: flag.label,
      })),
    })),
    findings: result.findings.map((finding) => ({
      ruleId: finding.ruleId,
      severity: finding.severity,
      category: finding.category,
      title: finding.title,
      occurrences: finding.occurrences,
      details: finding.instances.map((instance) => ({
        message: instance.message,
        evidence: instance.evidence,
      })),
      rationale: finding.rationale,
      recommendation: finding.recommendation,
    })),
    recommendedSteps: recommendedSteps(result),
    analystSteps: analystSteps(result),
    warnings: result.meta.warnings,
    limitations: LIMITATIONS,
  };

  let redacted = report;
  if (!options.includeRecipients) {
    const recipients = [...new Set(recipientAddresses(result).map((value) => value.toLowerCase()))];
    if (recipients.length > 0) {
      // Plain, percent-encoded and defanged forms (attackers often spoof the recipient as sender).
      const plain = new RegExp(recipients.map(flexibleAddressPattern).join('|'), 'giu');
      // Base64 is case-sensitive, so it gets its own pattern.
      const encoded = new RegExp(
        recipients
          .flatMap(base64Forms)
          .map(escapeRegExp)
          .sort((a, b) => b.length - a.length)
          .join('|'),
        'gu',
      );
      redacted = mapStrings(redacted, (value) =>
        value.replace(plain, RECIPIENT_PLACEHOLDER).replace(encoded, RECIPIENT_PLACEHOLDER),
      );
    }
  }
  if (options.redactEmailsInUrls) {
    redacted = {
      ...redacted,
      urls: redacted.urls.map((url) => mapStrings(url, redactEmails)),
      indicators: {
        ...redacted.indicators,
        urls: redacted.indicators.urls.map((value) => redactEmails(value)),
      },
      findings: redacted.findings.map((finding) => ({
        ...finding,
        details: mapStrings(finding['details'], (value) =>
          /\[:\/\/\]|\[:\]/u.test(value) ? redactEmails(value) : value,
        ),
      })),
    };
  }
  // Final safety net: no clickable URL may appear anywhere in a shared report.
  return mapStrings(redacted, (value) =>
    value.includes('://') || /\bwww\./iu.test(value) ? defangUrlsInText(value) : value,
  );
}

export function serializeReport(report: PhishLensReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function reportFileName(result: AnalysisResult): string {
  const hash = result.meta.sha256?.slice(0, 12) ?? 'unhashed';
  const date = result.meta.analyzedAt.slice(0, 10);
  return `phishlens-report-${date}-${hash}.json`;
}

/**
 * Plain-text version of a report for pasting into a ticket or chat. Built from
 * the report object, so it carries the same redaction and defanging.
 */
export function reportAsText(report: PhishLensReport): string {
  const message = report.message as {
    subject: string | null;
    date: string | null;
    from: { name: string; address: string }[];
    replyTo: { name: string; address: string }[];
    returnPath: string[];
  };
  const reported = (report.authentication['reported'] ?? {}) as Record<
    string,
    { result: string } | null
  >;
  const auth = ['spf', 'dkim', 'dmarc']
    .map((method) => `${method.toUpperCase()} ${reported[method]?.result ?? 'not reported'}`)
    .join(', ');
  const address = (entry: { name: string; address: string }) =>
    `${entry.name ? `"${entry.name}" ` : ''}<${entry.address}>`;
  const counts = report.findingCounts;
  const lines = [
    `PhishLens ${report.tool.version} analysis, ${report.input.analyzedAt}`,
    `Assessment: ${report.assessment.label} (${counts.high} high, ${counts.medium} medium, ${counts.low} low). Heuristic, not a verdict.`,
    '',
    `Subject: ${message.subject ?? '(none)'}`,
    `From: ${message.from.map(address).join(', ') || '(none)'}`,
    ...(message.replyTo.length > 0 ? [`Reply-To: ${message.replyTo.map(address).join(', ')}`] : []),
    ...(message.returnPath.length > 0 ? [`Return-Path: ${message.returnPath.join(', ')}`] : []),
    `Date: ${message.date ?? '(none)'}`,
    `Reported authentication (not verified): ${auth}`,
    ...(report.transit.originIp ? [`Claimed origin IP: ${report.transit.originIp.ip}`] : []),
    '',
    'Findings:',
    ...report.findings
      .filter((finding) => finding['severity'] !== 'info')
      .map((finding) => {
        const details = finding['details'] as { message: string }[];
        return `- [${String(finding['severity'])}] ${String(finding['title'])}: ${details[0]?.message ?? ''}`;
      }),
    '',
    'Indicators (defanged):',
    indicatorsAsText(report.indicators),
  ];
  return `${lines.join('\n')}\n`;
}
