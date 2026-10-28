import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ANALYSIS_TIMEOUT_MS, APP_LIMITS } from './config';
import { AnalysisError, serializeError, type SerializedAnalysisError } from './core/errors';
import { checkFileMetadata, checkSize } from './core/input';
import type { AnalysisLimits } from './core/limits';
import type { AnalysisStage, InputSource } from './core/types';
import type { Sample } from './samples';
import { InputView } from './ui/components/InputView';
import { ResultsView, type ResultsTab } from './ui/components/ResultsView';
import { SiteFooter } from './ui/components/SiteFooter';
import { SiteHeader } from './ui/components/SiteHeader';
import { ErrorView, ScanningView } from './ui/components/StatusViews';
import { usePageDrop } from './ui/hooks/usePageDrop';
import {
  createWorkerAnalyzer,
  type AnalysisJob,
  type AnalysisOutcome,
  type Analyzer,
} from './worker/client';

interface ResultEntry {
  id: number;
  outcome: AnalysisOutcome;
  label: string;
  /** Selected tab, remembered while an attached message is being inspected. */
  tab: ResultsTab;
}

const BASE_TITLE = 'PhishLens \u2013 Phishing Email Analyzer';

type View =
  | { kind: 'input' }
  | { kind: 'scanning'; stage: AnalysisStage; label: string }
  | { kind: 'error'; error: SerializedAnalysisError; returnTo: 'input' | 'results' }
  | { kind: 'results' };

interface AppProps {
  /** Injectable for tests; defaults to a Web Worker per analysis. */
  analyzer?: Analyzer;
  limits?: AnalysisLimits;
}

const encoder = new TextEncoder();

export function App({ analyzer, limits = APP_LIMITS }: AppProps) {
  const analyze = useMemo(
    () => analyzer ?? createWorkerAnalyzer(limits, ANALYSIS_TIMEOUT_MS),
    [analyzer, limits],
  );
  const [view, setView] = useState<View>({ kind: 'input' });
  // Results stay in memory only. The stack holds the parent message while an attached message is inspected.
  const [stack, setStack] = useState<ResultEntry[]>([]);
  const [pasteText, setPasteText] = useState('');
  const [announcement, setAnnouncement] = useState('');
  // Focus the input heading when returning to it (not on first load).
  const [focusInput, setFocusInput] = useState(false);
  const job = useRef<AnalysisJob | null>(null);
  const nextId = useRef(1);

  useEffect(() => () => job.current?.cancel(), []);

  const backToInput = useCallback(() => {
    job.current?.cancel();
    job.current = null;
    setStack([]);
    setFocusInput(true);
    setView({ kind: 'input' });
  }, []);

  // The browser's Back button returns from results to the input screen. No
  // message data is ever placed in the URL or history state.
  useEffect(() => {
    const onPopState = () => backToInput();
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, [backToInput]);

  const fail = useCallback((error: unknown, returnTo: 'input' | 'results') => {
    const serialized = serializeError(error);
    setView({ kind: 'error', error: serialized, returnTo });
    setAnnouncement(`${serialized.title}.`);
  }, []);

  const run = useCallback(
    (bytes: Uint8Array, source: InputSource, label: string, mode: 'replace' | 'push') => {
      job.current?.cancel();
      setView({ kind: 'scanning', stage: 'validating', label });
      setAnnouncement(`Analysing ${label}.`);
      const current = analyze(bytes, source, (stage) => {
        setView((previous) => (previous.kind === 'scanning' ? { ...previous, stage } : previous));
      });
      job.current = current;
      current.promise.then(
        (outcome) => {
          if (job.current !== current) return;
          job.current = null;
          const entry: ResultEntry = { id: nextId.current++, outcome, label, tab: 'overview' };
          setStack((previous) => (mode === 'push' ? [...previous, entry] : [entry]));
          setView({ kind: 'results' });
          if ((window.history.state as { phishlens?: string } | null)?.phishlens !== 'results') {
            window.history.pushState({ phishlens: 'results' }, '');
          }
          setAnnouncement(`Analysis complete: ${outcome.result.assessment.label}.`);
        },
        (error: unknown) => {
          if (job.current !== current) return;
          job.current = null;
          if (error instanceof AnalysisError && error.code === 'CANCELLED') {
            if (mode === 'replace') setFocusInput(true);
            setView(mode === 'push' ? { kind: 'results' } : { kind: 'input' });
            setAnnouncement('Analysis cancelled.');
            return;
          }
          fail(error, mode === 'push' ? 'results' : 'input');
        },
      );
    },
    [analyze, fail],
  );

  const onFile = useCallback(
    (file: File) => {
      try {
        checkFileMetadata(file.name, file.size, limits.maxInputBytes);
      } catch (error) {
        fail(error, 'input');
        return;
      }
      file.arrayBuffer().then(
        (buffer) =>
          run(new Uint8Array(buffer), { kind: 'file', name: file.name }, file.name, 'replace'),
        () =>
          fail(
            new AnalysisError('READ_FAILED', 'The browser could not read the selected file.'),
            'input',
          ),
      );
    },
    [fail, limits.maxInputBytes, run],
  );

  const onPaste = useCallback(
    (text: string) => {
      try {
        if (!text.trim())
          throw new AnalysisError(
            'EMPTY_INPUT',
            'Paste the raw message source or its headers first.',
          );
        const bytes = encoder.encode(text);
        checkSize(bytes.byteLength, limits.maxInputBytes);
        run(bytes, { kind: 'paste' }, 'pasted message', 'replace');
      } catch (error) {
        fail(error, 'input');
      }
    },
    [fail, limits.maxInputBytes, run],
  );

  const onSample = useCallback(
    (sample: Sample) =>
      run(
        encoder.encode(sample.raw),
        { kind: 'sample', name: sample.fileName },
        `sample "${sample.title}"`,
        'replace',
      ),
    [run],
  );

  const top = stack.at(-1);

  const onAnalyzeEmbedded = useCallback(
    (index: number) => {
      const bytes = top?.outcome.embeddedMessages.get(index);
      if (!top || !bytes) return;
      const attachment = top.outcome.result.attachments.find((entry) => entry.index === index);
      const label = attachment?.filename ?? `attached message ${index + 1}`;
      run(bytes, { kind: 'attachment', name: label }, label, 'push');
    },
    [run, top],
  );

  // A file dropped anywhere starts a new analysis, except while one is running.
  const dragging = usePageDrop(onFile, view.kind !== 'scanning');

  const reset = () => {
    // Undo the history entry pushed for the results; popstate then resets the view.
    if ((window.history.state as { phishlens?: string } | null)?.phishlens === 'results') {
      window.history.back();
    } else {
      backToInput();
    }
  };

  useEffect(() => {
    if (view.kind === 'results' && top) {
      document.title = `${top.outcome.result.assessment.label} \u2013 Analysis \u2013 PhishLens`;
    } else if (view.kind === 'scanning') {
      document.title = 'Analysing\u2026 \u2013 PhishLens';
    } else if (view.kind === 'error') {
      document.title = `${view.error.title} \u2013 PhishLens`;
    } else {
      document.title = BASE_TITLE;
    }
  }, [view, top]);

  let content;
  switch (view.kind) {
    case 'input':
      content = (
        <InputView
          dragging={dragging}
          focusOnMount={focusInput}
          maxBytes={limits.maxInputBytes}
          pasteText={pasteText}
          onPasteTextChange={setPasteText}
          onFile={onFile}
          onPaste={onPaste}
          onSample={onSample}
        />
      );
      break;
    case 'scanning':
      content = (
        <ScanningView
          stage={view.stage}
          sourceLabel={view.label}
          onCancel={() => job.current?.cancel()}
        />
      );
      break;
    case 'error':
      content = (
        <ErrorView
          error={view.error}
          onRetry={() => {
            if (view.returnTo === 'results' && stack.length > 0) {
              setView({ kind: 'results' });
            } else {
              setFocusInput(true);
              setView({ kind: 'input' });
            }
          }}
        />
      );
      break;
    case 'results':
      content = top ? (
        <ResultsView
          key={top.id}
          result={top.outcome.result}
          tab={top.tab}
          onTabChange={(tab) =>
            setStack((previous) =>
              previous.map((entry) => (entry.id === top.id ? { ...entry, tab } : entry)),
            )
          }
          sourceLabel={top.label}
          trail={stack.slice(0, -1).map((entry) => entry.label)}
          canAnalyzeEmbedded={(index) => top.outcome.embeddedMessages.has(index)}
          onAnalyzeEmbedded={onAnalyzeEmbedded}
          onBack={stack.length > 1 ? () => setStack((previous) => previous.slice(0, -1)) : null}
          onNew={reset}
        />
      ) : null;
      break;
  }

  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <SiteHeader />
      <main id="main">{content}</main>
      {dragging && view.kind !== 'input' && (
        <div className="drop-overlay" aria-hidden="true">
          <p>Drop the .eml file to analyse it</p>
        </div>
      )}
      <SiteFooter />
      <p className="visually-hidden" role="status" aria-live="polite">
        {announcement}
      </p>
    </div>
  );
}
