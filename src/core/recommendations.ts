import { defangEmail } from './defang';
import type { AnalysisResult } from './types';

/** Next steps for the person who received the message. Shown in the dashboard and the report. */
export function recommendedSteps(result: AnalysisResult): string[] {
  const { level } = result.assessment;
  const categories = new Set(
    result.findings
      .filter((finding) => finding.severity !== 'info')
      .map((finding) => finding.category),
  );
  const steps: string[] = [];

  if (level === 'high' || level === 'elevated') {
    steps.push(
      'Do not click links, open attachments, reply, or call numbers from this message until it has been verified.',
    );
    steps.push(
      "Verify the request through a channel you already trust: type the organisation's address into your browser yourself, or use a phone number from a previous statement or their official site.",
    );
    steps.push(
      "Report the message through your organisation's phishing-report button or process, and attach the exported PhishLens report if it helps.",
    );
  } else {
    steps.push(
      'Absence of indicators is not proof of safety. Still be cautious with unexpected requests for money, credentials, gift cards or urgent action.',
    );
  }
  if (categories.has('url') || categories.has('html')) {
    steps.push(
      'If you already opened a link and entered a password, change that password from the official website and turn on multi-factor authentication.',
    );
  }
  if (categories.has('attachment')) {
    steps.push(
      'If an attachment was opened, disconnect the device from the network and contact your IT or security team. Share the SHA-256 hashes shown, not the file.',
    );
  }
  if (categories.has('authentication') || categories.has('sender')) {
    steps.push(
      'Ask your mail administrator to review the message in your mail system, where authentication results can be checked against a trusted source.',
    );
  }
  if (result.meta.headersOnly) {
    steps.push('Analyse the complete .eml file to include links and attachments.');
  }
  return steps;
}

/** Next steps for an analyst investigating the message. */
export function analystSteps(result: AnalysisResult): string[] {
  const { headers } = result;
  const categories = new Set(
    result.findings
      .filter((finding) => finding.severity !== 'info')
      .map((finding) => finding.category),
  );
  const sender = headers.from[0]?.address;
  const steps: string[] = [];
  const lookup = [
    headers.messageId ? `Message-ID ${headers.messageId}` : null,
    sender ? `sender ${defangEmail(sender)}` : null,
  ].filter(Boolean);
  steps.push(
    `Search mail logs for other recipients of this message${lookup.length > 0 ? ` (by ${lookup.join(' or ')})` : ''} and quarantine any copies if it is confirmed malicious.`,
  );
  if (categories.has('url') || categories.has('html')) {
    steps.push(
      'Check proxy, DNS and endpoint logs for visits to the domains listed under Indicators, then block them if confirmed malicious.',
    );
  }
  if (result.attachments.some((attachment) => attachment.sha256)) {
    steps.push('Look up the attachment SHA-256 hashes in your threat-intelligence or EDR tools.');
  }
  if (categories.has('authentication') || categories.has('sender')) {
    steps.push(
      'Compare with the authentication results your own mail gateway logged for this message; the headers shown here are unverified.',
    );
  }
  if (result.assessment.level === 'none' || result.assessment.level === 'low') {
    steps.push(
      'Few or no technical indicators matched. Business email compromise and well-crafted lures often look like this, so judge the request itself.',
    );
  }
  steps.push('Attach the exported JSON report or the copied summary to the case.');
  return steps;
}
