import { AnalysisError } from '../core/errors';
import type { AnalysisLimits } from '../core/limits';
import type { AnalysisResult, AnalysisStage, InputSource } from '../core/types';
import type { AnalyzeRequest, WorkerResponse } from './protocol';

export interface AnalysisOutcome {
  result: AnalysisResult;
  /** Attached email messages by attachment index, held in memory only. */
  embeddedMessages: Map<number, Uint8Array>;
}

export interface AnalysisJob {
  promise: Promise<AnalysisOutcome>;
  cancel: () => void;
}

export type Analyzer = (
  bytes: Uint8Array,
  source: InputSource,
  onProgress: (stage: AnalysisStage) => void,
) => AnalysisJob;

function requestId(): string {
  return typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random()}`;
}

/**
 * Runs each analysis in a fresh Web Worker. The worker is terminated when the
 * analysis finishes, fails, times out or is cancelled, which releases every
 * byte of the message held by the parser.
 */
export function createWorkerAnalyzer(limits: AnalysisLimits, timeoutMs: number): Analyzer {
  return (bytes, source, onProgress) => {
    const id = requestId();
    let cancel: () => void = () => undefined;

    const promise = new Promise<AnalysisOutcome>((resolve, reject) => {
      let settled = false;
      const worker = new Worker(new URL('./analysis.worker.ts', import.meta.url), {
        type: 'module',
        name: 'phishlens-analysis',
      });
      const finish = (outcome: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        worker.terminate();
        outcome();
      };
      const timer = setTimeout(() => {
        finish(() =>
          reject(
            new AnalysisError(
              'TIMEOUT',
              `Analysis was stopped after ${Math.round(timeoutMs / 1000)} seconds. The message may be unusually large or crafted to slow parsers down.`,
            ),
          ),
        );
      }, timeoutMs);

      cancel = () =>
        finish(() => reject(new AnalysisError('CANCELLED', 'The analysis was cancelled.')));

      worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
        const message = event.data;
        if (message.id !== id) return;
        switch (message.type) {
          case 'progress':
            if (!settled) onProgress(message.stage);
            break;
          case 'result':
            finish(() =>
              resolve({
                result: message.result,
                embeddedMessages: new Map(
                  message.embeddedMessages.map((entry) => [
                    entry.attachmentIndex,
                    new Uint8Array(entry.bytes),
                  ]),
                ),
              }),
            );
            break;
          case 'error':
            finish(() =>
              reject(
                new AnalysisError(message.error.code, message.error.message, message.error.detail),
              ),
            );
            break;
        }
      };
      worker.onerror = (event) => {
        event.preventDefault();
        finish(() =>
          reject(
            new AnalysisError(
              'WORKER_FAILED',
              'The analysis engine stopped unexpectedly, possibly because the browser ran out of memory. Try a smaller message.',
            ),
          ),
        );
      };
      worker.onmessageerror = () => {
        finish(() =>
          reject(
            new AnalysisError('WORKER_FAILED', 'The analysis result could not be transferred.'),
          ),
        );
      };

      // Transfer a private copy so the caller's buffer is never detached.
      const copy = bytes.slice();
      const request: AnalyzeRequest = { type: 'analyze', id, bytes: copy.buffer, source, limits };
      worker.postMessage(request, [copy.buffer]);
    });

    return { promise, cancel: () => cancel() };
  };
}
