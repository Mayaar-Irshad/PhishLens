export type AnalysisErrorCode =
  | 'EMPTY_INPUT'
  | 'FILE_TOO_LARGE'
  | 'UNSUPPORTED_FILE_TYPE'
  | 'OUTLOOK_MSG'
  | 'BINARY_CONTENT'
  | 'NO_HEADERS'
  | 'PARSE_FAILED'
  | 'RESOURCE_LIMIT'
  | 'TIMEOUT'
  | 'CANCELLED'
  | 'WORKER_FAILED'
  | 'READ_FAILED'
  | 'INVALID_REQUEST';

export interface SerializedAnalysisError {
  code: AnalysisErrorCode;
  title: string;
  message: string;
  /** Optional technical detail. Never contains message content. */
  detail?: string;
}

const TITLES: Record<AnalysisErrorCode, string> = {
  EMPTY_INPUT: 'Nothing to analyze',
  FILE_TOO_LARGE: 'Message is too large',
  UNSUPPORTED_FILE_TYPE: 'Unsupported file type',
  OUTLOOK_MSG: 'Outlook .msg files are not supported',
  BINARY_CONTENT: 'This is not a raw email message',
  NO_HEADERS: 'No email headers found',
  PARSE_FAILED: 'The message could not be parsed',
  RESOURCE_LIMIT: 'The message exceeds a safety limit',
  TIMEOUT: 'Analysis took too long',
  CANCELLED: 'Analysis cancelled',
  WORKER_FAILED: 'The analysis engine stopped unexpectedly',
  READ_FAILED: 'The file could not be read',
  INVALID_REQUEST: 'Invalid analysis request',
};

/** An expected, user-facing failure. Messages must not echo untrusted input. */
export class AnalysisError extends Error {
  readonly code: AnalysisErrorCode;
  readonly title: string;
  readonly detail: string | undefined;

  constructor(code: AnalysisErrorCode, message: string, detail?: string) {
    super(message);
    this.name = 'AnalysisError';
    this.code = code;
    this.title = TITLES[code];
    this.detail = detail;
  }

  toJSON(): SerializedAnalysisError {
    return {
      code: this.code,
      title: this.title,
      message: this.message,
      ...(this.detail === undefined ? {} : { detail: this.detail }),
    };
  }
}

export function serializeError(error: unknown): SerializedAnalysisError {
  if (error instanceof AnalysisError) return error.toJSON();
  return {
    code: 'PARSE_FAILED',
    title: TITLES.PARSE_FAILED,
    message:
      'An unexpected error occurred while analyzing the message. It may be malformed or use an unusual structure.',
    detail: error instanceof Error ? error.name : 'Unknown error',
  };
}

export function errorTitle(code: AnalysisErrorCode): string {
  return TITLES[code];
}
