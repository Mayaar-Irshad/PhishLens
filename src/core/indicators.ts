import { defangEmail, defangHost } from './defang';
import type { AnalysisResult } from './types';

/**
 * Indicators of compromise (IOCs) gathered from an analysis, defanged so they
 * can be pasted into tickets and chat tools without becoming clickable.
 * Recipient addresses are never included.
 */
export interface Indicators {
  senderAddresses: string[];
  /** Sender domains and domains of links that matched a rule. */
  domains: string[];
  /** Other domains linked from the message, listed for completeness; many are legitimate. */
  otherDomains: string[];
  /** The claimed origin IP and IP addresses used directly as link hosts. */
  ips: string[];
  urls: string[];
  attachmentHashes: { name: string; sha256: string }[];
  messageSha256: string | null;
}

function unique(values: Iterable<string>): string[] {
  return [...new Set([...values].filter(Boolean))];
}

export function collectIndicators(result: AnalysisResult): Indicators {
  const { headers } = result;
  const senders = [...headers.from, ...headers.replyTo, ...headers.returnPath, ...headers.sender];
  const senderAddresses = unique(senders.map((address) => address.address.toLowerCase()));
  // Security-gateway wrappers (Safe Links...) are infrastructure; their unwrapped destinations are kept.
  const links = result.urls.filter(
    (url) =>
      url.schemeClass !== 'contact' &&
      !url.embedded.some((entry) => entry.kind === 'security-wrapper'),
  );
  const flagged = (url: (typeof links)[number]) =>
    url.flags.some((entry) => entry.severity !== 'info');
  const domainOf = (url: (typeof links)[number]) => url.registrableDomain ?? url.host ?? '';

  const domains = unique([
    ...senders
      .map((address) => address.registrableDomain ?? '')
      .filter((domain) => !domain.startsWith('[')),
    ...links.filter((url) => !url.isIpHost && flagged(url)).map(domainOf),
  ]);
  const otherDomains = unique(
    links.filter((url) => !url.isIpHost && !flagged(url)).map(domainOf),
  ).filter((domain) => !domains.includes(domain));

  // Relay IPs are mostly provider infrastructure, so only the claimed origin is listed.
  const ips = unique([
    ...(headers.originIp ? [headers.originIp.ip] : []),
    ...links.filter((url) => url.isIpHost && url.host).map((url) => url.host ?? ''),
  ]);

  return {
    senderAddresses: senderAddresses.map(defangEmail),
    domains: domains.map(defangHost),
    otherDomains: otherDomains.map(defangHost),
    ips: ips.map(defangHost),
    urls: unique(links.map((url) => url.defanged)),
    attachmentHashes: result.attachments
      .filter((attachment) => attachment.sha256)
      .map((attachment) => ({
        name: attachment.filename ?? `attachment ${attachment.index + 1}`,
        sha256: attachment.sha256 ?? '',
      })),
    messageSha256: result.meta.sha256,
  };
}

export function indicatorCount(indicators: Indicators): number {
  return (
    indicators.senderAddresses.length +
    indicators.domains.length +
    indicators.otherDomains.length +
    indicators.ips.length +
    indicators.urls.length +
    indicators.attachmentHashes.length
  );
}

/** Plain-text block of defanged indicators, one per line, grouped by type. */
export function indicatorsAsText(indicators: Indicators): string {
  const section = (title: string, values: string[]) =>
    values.length > 0 ? `${title}\n${values.map((value) => `  ${value}`).join('\n')}` : '';
  return [
    section('Sender addresses', indicators.senderAddresses),
    section('Domains', indicators.domains),
    section('Other linked domains', indicators.otherDomains),
    section('IP addresses', indicators.ips),
    section('URLs', indicators.urls),
    section(
      'Attachment SHA-256',
      indicators.attachmentHashes.map((entry) => `${entry.sha256}  ${entry.name}`),
    ),
    indicators.messageSha256 ? `Message SHA-256\n  ${indicators.messageSha256}` : '',
  ]
    .filter(Boolean)
    .join('\n\n');
}
