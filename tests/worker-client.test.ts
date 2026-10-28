import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AnalysisError } from '../src/core/errors';
import { DEFAULT_LIMITS } from '../src/core/limits';
import type { AnalysisResult } from '../src/core/types';
import { createWorkerAnalyzer } from '../src/worker/client';
import type { AnalyzeRequest, WorkerResponse } from '../src/worker/protocol';
import { encode } from './helpers';

/** Minimal stand-in for the browser Worker, driven by the test. */
class FakeWorker {
  static instances: FakeWorker[] = [];
  onmessage: ((event: { data: WorkerResponse }) => void) | null = null;
  onerror: ((event: { preventDefault: () => void }) => void) | null = null;
  onmessageerror: (() => void) | null = null;
  request: AnalyzeRequest | null = null;
  transfer: Transferable[] = [];
  terminated = false;

  constructor(
    readonly url: URL,
    readonly options: WorkerOptions,
  ) {
    FakeWorker.instances.push(this);
  }

  postMessage(request: AnalyzeRequest, transfer: Transferable[]) {
    this.request = request;
    this.transfer = transfer;
  }

  terminate() {
    this.terminated = true;
  }

  reply(message: Partial<WorkerResponse> & { type: WorkerResponse['type'] }) {
    this.onmessage?.({ data: { id: this.request?.id ?? '', ...message } as WorkerResponse });
  }
}

const latest = () => {
  const worker = FakeWorker.instances.at(-1);
  if (!worker) throw new Error('no worker created');
  return worker;
};

async function rejection(promise: Promise<unknown>): Promise<AnalysisError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof AnalysisError) return error;
    throw error;
  }
  throw new Error('expected a rejection');
}

beforeEach(() => {
  FakeWorker.instances = [];
  vi.stubGlobal('Worker', FakeWorker);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('worker client', () => {
  const analyzer = createWorkerAnalyzer(DEFAULT_LIMITS, 30_000);

  it('starts a module worker, transfers a private copy of the bytes and forwards progress', async () => {
    const input = encode('From: a@b.example\r\n\r\nbody');
    const progress = vi.fn();
    const job = analyzer(input, { kind: 'paste' }, progress);
    const worker = latest();

    expect(worker.options).toMatchObject({ type: 'module' });
    expect(worker.request).toMatchObject({
      type: 'analyze',
      source: { kind: 'paste' },
      limits: DEFAULT_LIMITS,
    });
    expect(worker.transfer).toEqual([worker.request?.bytes]);
    expect(worker.request?.bytes).not.toBe(input.buffer);
    expect(input.byteLength).toBeGreaterThan(0);

    worker.reply({ type: 'progress', stage: 'parsing' });
    worker.reply({
      type: 'result',
      result: { meta: {} } as AnalysisResult,
      embeddedMessages: [{ attachmentIndex: 2, bytes: new Uint8Array([0x78]).buffer }],
    });
    const outcome = await job.promise;
    expect(progress).toHaveBeenCalledWith('parsing');
    expect(outcome.embeddedMessages.get(2)).toBeInstanceOf(Uint8Array);
    expect(worker.terminated).toBe(true);
  });

  it('ignores messages for other requests', async () => {
    const job = analyzer(encode('x'), { kind: 'paste' }, vi.fn());
    const worker = latest();
    worker.onmessage?.({
      data: {
        type: 'error',
        id: 'someone-else',
        error: { code: 'PARSE_FAILED', title: 't', message: 'm' },
      },
    });
    expect(worker.terminated).toBe(false);
    worker.reply({
      type: 'error',
      error: { code: 'NO_HEADERS', title: 'No email headers found', message: 'msg' },
    });
    expect((await rejection(job.promise)).code).toBe('NO_HEADERS');
    expect(worker.terminated).toBe(true);
  });

  it('times out and terminates a stuck worker', async () => {
    vi.useFakeTimers();
    const job = analyzer(encode('x'), { kind: 'paste' }, vi.fn());
    const pending = rejection(job.promise);
    vi.advanceTimersByTime(30_001);
    expect((await pending).code).toBe('TIMEOUT');
    expect(latest().terminated).toBe(true);
  });

  it('cancels on request', async () => {
    const job = analyzer(encode('x'), { kind: 'paste' }, vi.fn());
    job.cancel();
    expect((await rejection(job.promise)).code).toBe('CANCELLED');
    expect(latest().terminated).toBe(true);
  });

  it('reports a crashed worker', async () => {
    const job = analyzer(encode('x'), { kind: 'paste' }, vi.fn());
    const preventDefault = vi.fn();
    latest().onerror?.({ preventDefault });
    expect((await rejection(job.promise)).code).toBe('WORKER_FAILED');
    expect(preventDefault).toHaveBeenCalled();
  });

  it('ignores late messages after settling', async () => {
    const progress = vi.fn();
    const job = analyzer(encode('x'), { kind: 'paste' }, progress);
    job.cancel();
    latest().reply({ type: 'progress', stage: 'links' });
    latest().reply({
      type: 'result',
      result: { meta: {} } as AnalysisResult,
      embeddedMessages: [],
    });
    expect(progress).not.toHaveBeenCalled();
    expect((await rejection(job.promise)).code).toBe('CANCELLED');
  });
});
