import type { SerializedAnalysisError } from '../core/errors';
import type { AnalysisLimits } from '../core/limits';
import type { AnalysisResult, AnalysisStage, InputSource } from '../core/types';

export interface AnalyzeRequest {
  type: 'analyze';
  id: string;
  bytes: ArrayBuffer;
  source: InputSource;
  limits: AnalysisLimits;
}

export interface TransferredMessage {
  attachmentIndex: number;
  bytes: ArrayBuffer;
}

export type WorkerResponse =
  | { type: 'progress'; id: string; stage: AnalysisStage }
  | { type: 'result'; id: string; result: AnalysisResult; embeddedMessages: TransferredMessage[] }
  | { type: 'error'; id: string; error: SerializedAnalysisError };

const SOURCE_KINDS: ReadonlySet<string> = new Set(['file', 'paste', 'sample', 'attachment']);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

export function isAnalyzeRequest(value: unknown): value is AnalyzeRequest {
  if (!isRecord(value)) return false;
  const { type, id, bytes, source, limits } = value;
  return (
    type === 'analyze' &&
    typeof id === 'string' &&
    bytes instanceof ArrayBuffer &&
    isRecord(source) &&
    typeof source['kind'] === 'string' &&
    SOURCE_KINDS.has(source['kind']) &&
    (source['name'] === undefined || typeof source['name'] === 'string') &&
    isRecord(limits)
  );
}
