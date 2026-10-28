import { assess } from './assessment';
import { analyzeAttachment, sha256Hex } from './attachments';
import { analyzeAuthentication } from './auth';
import {
  checkAttachments,
  checkAuthentication,
  checkContent,
  checkHeaders,
  checkHtml,
  checkSender,
  checkUrls,
} from './checks';
import { AnalysisError } from './errors';
import { FindingCollector } from './findings';
import { analyzeHeaders } from './headers';
import { MAX_HTML_DEPTH, scanHtml, type HtmlScan } from './html';
import { prepareInput } from './input';
import { DEFAULT_LIMITS, type AnalysisLimits } from './limits';
import { parseMime } from './parse';
import type {
  AnalysisOutput,
  AnalysisStage,
  AttachmentRecord,
  EmbeddedMessage,
  HtmlSummary,
  InputSource,
} from './types';
import { analyzeOccurrences, extractTextUrls, type UrlOccurrence } from './urls';
import { TOOL_VERSION } from './version';

export interface AnalyzeOptions {
  source: InputSource;
  limits?: AnalysisLimits;
  /** Reference time for date checks; injectable for deterministic tests. */
  now?: Date;
  onProgress?: (stage: AnalysisStage) => void;
}

function emptyHtmlSummary(): HtmlSummary {
  return {
    present: false,
    truncated: false,
    flattenedTags: 0,
    links: 0,
    forms: [],
    scripts: 0,
    frames: 0,
    embeddedObjects: 0,
    eventHandlerAttributes: 0,
    metaRefresh: 0,
    remoteImages: 0,
    remoteResources: 0,
    remoteHosts: [],
    baseHref: null,
    hiddenTextChars: 0,
    passwordInputs: 0,
    images: 0,
  };
}

/** Characters of each body kept for the in-app content preview (never exported). */
const PREVIEW_CHARS = 100_000;

/**
 * Runs the full analysis pipeline on raw message bytes. Pure apart from
 * hashing: no network, no storage, no DOM. Safe to run in a Web Worker.
 */
export async function analyzeEmail(
  input: Uint8Array,
  options: AnalyzeOptions,
): Promise<AnalysisOutput> {
  const limits = options.limits ?? DEFAULT_LIMITS;
  const now = options.now ?? new Date();
  const progress = options.onProgress ?? (() => undefined);
  const warnings: string[] = [];

  progress('validating');
  const prepared = prepareInput(input, limits.maxInputBytes);
  const inputHash = await sha256Hex(input);

  progress('parsing');
  const email = await parseMime(prepared.bytes);
  if (email.headers.length === 0) {
    throw new AnalysisError('NO_HEADERS', 'No email headers could be parsed from the input.');
  }

  progress('headers');
  const headers = analyzeHeaders(email.headers);

  progress('authentication');
  const authentication = analyzeAuthentication(headers.all, headers.from);

  // Attachments first: links found inside them join the message's links below.
  progress('attachments');
  const attachments: AttachmentRecord[] = [];
  const attachmentLinks: UrlOccurrence[] = [];
  const embeddedMessages: EmbeddedMessage[] = [];
  for (const [index, attachment] of email.attachments.slice(0, limits.maxAttachments).entries()) {
    const analyzed = await analyzeAttachment(attachment, index);
    attachments.push(analyzed.record);
    attachmentLinks.push(...analyzed.links);
    if (analyzed.embeddedMessage)
      embeddedMessages.push({ attachmentIndex: index, bytes: analyzed.embeddedMessage });
  }
  const attachmentsTruncated = email.attachments.length > limits.maxAttachments;
  if (attachmentsTruncated)
    warnings.push(`Only the first ${limits.maxAttachments} attachments were analysed.`);

  progress('links');
  const htmlBody = email.html ?? '';
  const textBody = (email.text ?? '').slice(0, limits.maxTextChars);
  if ((email.text?.length ?? 0) > limits.maxTextChars) {
    warnings.push(
      `The plain-text body was truncated to ${limits.maxTextChars.toLocaleString('en-US')} characters for analysis.`,
    );
  }
  let html: HtmlScan | null = null;
  if (htmlBody) {
    html = scanHtml(htmlBody, limits.maxHtmlChars, limits.maxUrls * 4);
    if (html.summary.flattenedTags > 0) {
      warnings.push(
        `The HTML body was nested more than ${MAX_HTML_DEPTH} levels deep; ${html.summary.flattenedTags.toLocaleString('en-US')} structural tags were flattened before analysis. Text and links were kept.`,
      );
    }
    if (html.summary.truncated) {
      warnings.push(
        `The HTML body was truncated to ${limits.maxHtmlChars.toLocaleString('en-US')} characters for analysis.`,
      );
    }
  }
  const occurrences: UrlOccurrence[] = [
    ...(html?.occurrences ?? []),
    ...extractTextUrls(html?.unlinkedText ?? '', limits.maxUrls).map((url): UrlOccurrence => ({
      kind: 'html-text',
      url,
    })),
    ...extractTextUrls(textBody, limits.maxUrls).map((url): UrlOccurrence => ({
      kind: 'plain-text',
      url,
    })),
    ...attachmentLinks,
  ];
  const urls = analyzeOccurrences(occurrences, limits.maxUrls, html?.summary.baseHref ?? null);
  if (urls.truncated)
    warnings.push(`Only the first ${limits.maxUrls} distinct links were analysed.`);

  progress('assessing');
  const findings = new FindingCollector(limits.maxInstancesPerFinding);
  if (prepared.headersOnly) findings.add('INPUT_HEADERS_ONLY', 'Only a header block was supplied.');
  if (prepared.skippedLines > 0) {
    warnings.push(
      `Ignored ${prepared.skippedLines} line${prepared.skippedLines === 1 ? '' : 's'} of text before the first email header (for example a mail client's summary).`,
    );
  }
  if (prepared.malformedHeaderLines > 0) {
    findings.add(
      'INPUT_MALFORMED_HEADER_LINES',
      `${prepared.malformedHeaderLines} line${prepared.malformedHeaderLines === 1 ? '' : 's'} in the header block ${prepared.malformedHeaderLines === 1 ? 'is' : 'are'} not valid header fields.`,
    );
  }
  checkSender(headers, findings);
  checkHeaders(headers, now, findings);
  checkAuthentication(authentication, headers, findings);
  checkUrls(urls.records, findings);
  const htmlSummary = html?.summary ?? emptyHtmlSummary();
  checkHtml(htmlSummary, findings);
  checkAttachments(attachments, findings);
  checkContent(
    headers.subject,
    html ? `${textBody}\n${html.visibleText}` : textBody,
    html,
    findings,
  );
  const findingList = findings.list();

  return {
    result: {
      meta: {
        toolVersion: TOOL_VERSION,
        analyzedAt: now.toISOString(),
        source: options.source,
        sizeBytes: input.byteLength,
        sha256: inputHash,
        headersOnly: prepared.headersOnly,
        warnings,
      },
      headers,
      authentication,
      body: {
        hasText: Boolean(email.text?.trim()),
        hasHtml: Boolean(htmlBody.trim()),
        textLength: email.text?.length ?? 0,
        htmlLength: htmlBody.length,
        html: htmlSummary,
        preview: {
          plainText: (email.text ?? '').slice(0, PREVIEW_CHARS),
          visibleText: (html?.visibleText ?? '')
            .replace(/[ \t]*\n[\s]*/gu, '\n')
            .slice(0, PREVIEW_CHARS),
          htmlSource: htmlBody.slice(0, PREVIEW_CHARS * 2),
          truncated:
            (email.text?.length ?? 0) > PREVIEW_CHARS ||
            (html?.visibleText.length ?? 0) > PREVIEW_CHARS ||
            htmlBody.length > PREVIEW_CHARS * 2,
        },
      },
      urls: urls.records,
      urlsTruncated: urls.truncated,
      attachments,
      attachmentsTruncated,
      findings: findingList,
      assessment: assess(findingList),
    },
    embeddedMessages,
  };
}
