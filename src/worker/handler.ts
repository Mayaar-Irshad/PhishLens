import { analyzeEmail } from '../core/analyze';
import { AnalysisError, serializeError } from '../core/errors';
import { ABSOLUTE_MAX_INPUT_BYTES, DEFAULT_LIMITS, type AnalysisLimits } from '../core/limits';
import { isAnalyzeRequest, type TransferredMessage, type WorkerResponse } from './protocol';

export type Post = (message: WorkerResponse, transfer?: Transferable[]) => void;

function clamp(value: unknown, fallback: number, max: number): number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0
    ? Math.min(value, max)
    : fallback;
}

/** Never trusts limits from the message: each is validated and capped. */
export function sanitizeLimits(
  limits: Partial<Record<keyof AnalysisLimits, unknown>>,
): AnalysisLimits {
  return {
    maxInputBytes: clamp(
      limits.maxInputBytes,
      DEFAULT_LIMITS.maxInputBytes,
      ABSOLUTE_MAX_INPUT_BYTES,
    ),
    maxUrls: clamp(limits.maxUrls, DEFAULT_LIMITS.maxUrls, 5000),
    maxAttachments: clamp(limits.maxAttachments, DEFAULT_LIMITS.maxAttachments, 1000),
    maxHtmlChars: clamp(limits.maxHtmlChars, DEFAULT_LIMITS.maxHtmlChars, 20_000_000),
    maxTextChars: clamp(limits.maxTextChars, DEFAULT_LIMITS.maxTextChars, 20_000_000),
    maxInstancesPerFinding: clamp(
      limits.maxInstancesPerFinding,
      DEFAULT_LIMITS.maxInstancesPerFinding,
      200,
    ),
  };
}

/** Handles one analysis request. Separated from the worker entry point so it can be unit tested. */
export async function handleRequest(data: unknown, post: Post): Promise<void> {
  if (!isAnalyzeRequest(data)) {
    const id =
      typeof data === 'object' && data !== null && 'id' in data && typeof data.id === 'string'
        ? data.id
        : 'unknown';
    post({
      type: 'error',
      id,
      error: new AnalysisError(
        'INVALID_REQUEST',
        'The analysis engine received a malformed request.',
      ).toJSON(),
    });
    return;
  }
  const { id, bytes, source, limits } = data;
  try {
    const output = await analyzeEmail(new Uint8Array(bytes), {
      source:
        source.name === undefined
          ? { kind: source.kind }
          : { kind: source.kind, name: source.name },
      limits: sanitizeLimits(limits),
      onProgress: (stage) => post({ type: 'progress', id, stage }),
    });
    // Copy each attached message into its own buffer so it can be transferred
    // without dragging the whole parser buffer along.
    const embeddedMessages: TransferredMessage[] = output.embeddedMessages.map((message) => ({
      attachmentIndex: message.attachmentIndex,
      bytes: message.bytes.slice().buffer,
    }));
    post(
      { type: 'result', id, result: output.result, embeddedMessages },
      embeddedMessages.map((message) => message.bytes),
    );
  } catch (error) {
    post({ type: 'error', id, error: serializeError(error) });
  }
}
