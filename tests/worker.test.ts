import { describe, expect, it } from 'vitest';
import { ABSOLUTE_MAX_INPUT_BYTES, DEFAULT_LIMITS } from '../src/core/limits';
import { handleRequest, sanitizeLimits } from '../src/worker/handler';
import { isAnalyzeRequest, type WorkerResponse } from '../src/worker/protocol';
import { buildEmail, encode, readSample } from './helpers';

async function run(data: unknown) {
  const messages: { message: WorkerResponse; transfer: Transferable[] }[] = [];
  await handleRequest(data, (message, transfer = []) => messages.push({ message, transfer }));
  return messages;
}

const request = (bytes: Uint8Array, limits: object = DEFAULT_LIMITS) => ({
  type: 'analyze',
  id: 'job-1',
  bytes: bytes.slice().buffer,
  source: { kind: 'file', name: 'message.eml' },
  limits,
});

describe('worker request handling', () => {
  it('rejects malformed requests', async () => {
    for (const bad of [
      null,
      'analyze',
      { type: 'analyze' },
      { ...request(encode('x')), bytes: 'not a buffer' },
      { ...request(encode('x')), source: { kind: 'remote-url' } },
    ]) {
      const [first] = await run(bad);
      expect(first?.message).toMatchObject({ type: 'error', error: { code: 'INVALID_REQUEST' } });
    }
    expect(isAnalyzeRequest(request(encode('x')))).toBe(true);
  });

  it('streams progress and returns the result', async () => {
    const messages = await run(request(encode(buildEmail())));
    const stages = messages
      .filter((entry) => entry.message.type === 'progress')
      .map((entry) => (entry.message as { stage: string }).stage);
    expect(stages).toEqual([
      'validating',
      'parsing',
      'headers',
      'authentication',
      'attachments',
      'links',
      'assessing',
    ]);
    const last = messages.at(-1)?.message;
    expect(last?.type).toBe('result');
    if (last?.type === 'result') {
      expect(last.id).toBe('job-1');
      expect(last.result.meta.source).toEqual({ kind: 'file', name: 'message.eml' });
    }
  });

  it('transfers attached messages as standalone buffers', async () => {
    const inner = 'From: inner@inner.example\r\nSubject: Inner\r\n\r\nInner body\r\n';
    const raw = buildEmail({
      headers: ['Content-Type: multipart/mixed; boundary="w"'],
      body: `--w\r\nContent-Type: text/plain\r\n\r\nSee attached\r\n--w\r\nContent-Type: message/rfc822\r\n\r\n${inner}--w--\r\n`,
    });
    const messages = await run(request(encode(raw)));
    const last = messages.at(-1);
    expect(last?.message.type).toBe('result');
    if (last?.message.type === 'result') {
      const embedded = last.message.embeddedMessages[0];
      expect(embedded?.bytes).toBeInstanceOf(ArrayBuffer);
      expect(last.transfer).toEqual([embedded?.bytes]);
      expect(new TextDecoder().decode(embedded?.bytes)).toContain('inner@inner.example');
    }
  });

  it('turns analysis failures into serialized errors', async () => {
    const [first] = await run(request(encode('just text, no headers')));
    expect(first?.message.type).toBe('progress');
    const last = (await run(request(encode('just text, no headers')))).at(-1)?.message;
    expect(last).toMatchObject({ type: 'error', id: 'job-1', error: { code: 'NO_HEADERS' } });
  });

  it('enforces the size limit it is given', async () => {
    const last = (
      await run(request(readSample('newsletter'), { ...DEFAULT_LIMITS, maxInputBytes: 100 }))
    ).at(-1)?.message;
    expect(last).toMatchObject({ type: 'error', error: { code: 'FILE_TOO_LARGE' } });
  });

  it('never trusts limits from the request', () => {
    expect(
      sanitizeLimits({
        maxInputBytes: 10 ** 12,
        maxUrls: -1,
        maxAttachments: '9',
        maxHtmlChars: Number.NaN,
      }),
    ).toEqual({
      ...DEFAULT_LIMITS,
      maxInputBytes: ABSOLUTE_MAX_INPUT_BYTES,
    });
  });
});
