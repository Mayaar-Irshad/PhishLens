import PostalMime, { type Email } from 'postal-mime';
import { AnalysisError } from './errors';

/**
 * Parser limits, tighter than PostalMime's defaults because PhishLens only
 * needs the structure of one message, never deeply nested archives of mail.
 * Forwarded messages are kept as attachments (not parsed inline) so their
 * headers and links are never mixed into the outer message's analysis.
 */
export const PARSER_OPTIONS = Object.freeze({
  attachmentEncoding: 'arraybuffer',
  forceRfc822Attachments: true,
  maxRfc822NestingDepth: 0,
  maxNestingDepth: 64,
  maxHeadersSize: 1024 * 1024,
  maxPartCount: 2000,
  maxForwardedAddresses: 1000,
} as const);

const LIMIT_CODES = new Set([
  'EMAXNESTINGDEPTH',
  'EMAXHEADERSIZE',
  'EMAXPARTCOUNT',
  'EMAXFORWARDEDADDRESSES',
]);

function errorCode(error: unknown): string | null {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    return typeof error.code === 'string' ? error.code : null;
  }
  return null;
}

export async function parseMime(bytes: Uint8Array): Promise<Email> {
  try {
    return await PostalMime.parse(bytes, PARSER_OPTIONS);
  } catch (error) {
    const code = errorCode(error);
    if (code && LIMIT_CODES.has(code)) {
      throw new AnalysisError(
        'RESOURCE_LIMIT',
        'The message structure exceeds a safety limit (too deeply nested, too many parts, or oversized headers). Messages like this are usually malformed or deliberately crafted to overload parsers.',
        code,
      );
    }
    throw new AnalysisError(
      'PARSE_FAILED',
      'The MIME structure of this message could not be parsed. It may be corrupted or truncated.',
      code ?? (error instanceof Error ? error.name : undefined),
    );
  }
}
