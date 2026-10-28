import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from '../../src/App';
import { analyzeEmail } from '../../src/core/analyze';
import { AnalysisError } from '../../src/core/errors';
import { DEFAULT_LIMITS, type AnalysisLimits } from '../../src/core/limits';
import type { Analyzer } from '../../src/worker/client';
import { NOW } from '../helpers';

/** Runs the real analysis in-process; the production app uses a Web Worker. */
export function inlineAnalyzer(limits: AnalysisLimits = DEFAULT_LIMITS): Analyzer {
  return (bytes, source, onProgress) => {
    let rejectJob: (error: unknown) => void = () => undefined;
    let settled = false;
    const promise = new Promise<Awaited<ReturnType<Analyzer>['promise']>>((resolve, reject) => {
      rejectJob = reject;
      analyzeEmail(bytes, { source, limits, now: NOW, onProgress }).then(
        (output) => {
          if (settled) return;
          settled = true;
          resolve({
            result: output.result,
            embeddedMessages: new Map(
              output.embeddedMessages.map((message) => [message.attachmentIndex, message.bytes]),
            ),
          });
        },
        (error: unknown) => {
          settled = true;
          reject(error instanceof Error ? error : new Error(String(error)));
        },
      );
    });
    return {
      promise,
      cancel: () => {
        if (settled) return;
        settled = true;
        rejectJob(new AnalysisError('CANCELLED', 'The analysis was cancelled.'));
      },
    };
  };
}

export function renderApp(
  limits: AnalysisLimits = DEFAULT_LIMITS,
  analyzer: Analyzer = inlineAnalyzer(limits),
) {
  const user = userEvent.setup();
  const view = render(<App analyzer={analyzer} limits={limits} />);
  return { user, ...view };
}

export async function pasteAndAnalyze(user: ReturnType<typeof userEvent.setup>, raw: string) {
  await user.click(screen.getByRole('tab', { name: 'Paste source' }));
  const textarea = screen.getByLabelText('Raw message or headers');
  fireEvent.change(textarea, { target: { value: raw } });
  await user.click(screen.getByRole('button', { name: 'Analyze message' }));
}

export function chooseFile(container: HTMLElement, file: File) {
  const input = container.querySelector<HTMLInputElement>('input[type=file]');
  if (!input) throw new Error('file input missing');
  fireEvent.change(input, { target: { files: [file] } });
}
