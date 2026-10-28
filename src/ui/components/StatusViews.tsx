import { useEffect, useRef, useState } from 'react';
import type { SerializedAnalysisError } from '../../core/errors';
import type { AnalysisStage } from '../../core/types';

const STAGES: readonly { id: AnalysisStage; label: string }[] = [
  { id: 'validating', label: 'Checking the input' },
  { id: 'parsing', label: 'Parsing the MIME structure' },
  { id: 'headers', label: 'Reading headers and sender' },
  { id: 'authentication', label: 'Reading reported authentication' },
  { id: 'attachments', label: 'Inspecting attachments' },
  { id: 'links', label: 'Extracting and checking links' },
  { id: 'assessing', label: 'Applying the rules' },
];

function useFocusOnMount<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  useEffect(() => {
    ref.current?.focus();
  }, []);
  return ref;
}

interface ScanningViewProps {
  stage: AnalysisStage;
  sourceLabel: string;
  onCancel: () => void;
}

/** Most analyses finish in well under this, so the progress screen would only flash. */
const SHOW_PROGRESS_AFTER_MS = 300;

export function ScanningView(props: ScanningViewProps) {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const timer = setTimeout(() => setVisible(true), SHOW_PROGRESS_AFTER_MS);
    return () => clearTimeout(timer);
  }, []);
  return visible ? <ScanningProgress {...props} /> : <div className="container" aria-busy="true" />;
}

function ScanningProgress({ stage, sourceLabel, onCancel }: ScanningViewProps) {
  const heading = useFocusOnMount<HTMLHeadingElement>();
  const current = STAGES.findIndex((entry) => entry.id === stage);
  return (
    <div className="container">
      <section className="status-view" aria-labelledby="scanning-title" aria-busy="true">
        <h1 id="scanning-title" ref={heading} tabIndex={-1}>
          Analysing {sourceLabel}
        </h1>
        <p>
          Everything happens in a background worker in this tab. Links and attachments are never
          opened.
        </p>
        <ol className="stage-list" aria-label="Progress">
          {STAGES.map((entry, index) => {
            const state = index < current ? 'done' : index === current ? 'current' : 'pending';
            return (
              <li
                key={entry.id}
                data-state={state}
                aria-current={state === 'current' ? 'step' : undefined}
              >
                {entry.label}
                {state === 'done' && <span className="visually-hidden"> (done)</span>}
              </li>
            );
          })}
        </ol>
        <button type="button" className="button button--secondary" onClick={onCancel}>
          Cancel analysis
        </button>
      </section>
    </div>
  );
}

interface ErrorViewProps {
  error: SerializedAnalysisError;
  onRetry: () => void;
}

export function ErrorView({ error, onRetry }: ErrorViewProps) {
  const heading = useFocusOnMount<HTMLHeadingElement>();
  return (
    <div className="container">
      <section className="status-view" aria-labelledby="error-title">
        <h1 id="error-title" ref={heading} tabIndex={-1}>
          {error.title}
        </h1>
        <div className="error-panel">
          <p>{error.message}</p>
          {error.detail && <p className="error-panel__detail">Technical detail: {error.detail}</p>}
        </div>
        <div className="status-view__actions">
          <button type="button" className="button button--primary" onClick={onRetry}>
            {error.code === 'CANCELLED' ? 'Back to input' : 'Try another message'}
          </button>
        </div>
      </section>
    </div>
  );
}
