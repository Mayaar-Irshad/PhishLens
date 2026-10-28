import { useState } from 'react';
import { defangUrlsInText } from '../../core/defang';
import type { BodySummary } from '../../core/types';
import { UntrustedText } from './UntrustedText';

type View = 'visible' | 'plain' | 'source';

const VIEWS: readonly { id: View; label: string; hint: string }[] = [
  {
    id: 'visible',
    label: 'Visible text',
    hint: 'Text a reader would see in the HTML version, extracted without rendering. Hidden text is excluded.',
  },
  {
    id: 'plain',
    label: 'Plain-text part',
    hint: 'The text/plain version of the message, if it has one.',
  },
  {
    id: 'source',
    label: 'HTML source',
    hint: 'The raw HTML markup, shown as inert text. Nothing is rendered, run or loaded.',
  },
];

export function ContentTab({ body, headersOnly }: { body: BodySummary; headersOnly: boolean }) {
  const available = VIEWS.filter((view) =>
    view.id === 'visible'
      ? body.preview.visibleText.trim()
      : view.id === 'plain'
        ? body.preview.plainText.trim()
        : body.preview.htmlSource.trim(),
  );
  const [selected, setSelected] = useState<View>(available[0]?.id ?? 'visible');
  const current = available.find((view) => view.id === selected) ?? available[0];
  const text = !current
    ? ''
    : current.id === 'visible'
      ? body.preview.visibleText
      : current.id === 'plain'
        ? body.preview.plainText
        : body.preview.htmlSource;

  return (
    <section aria-labelledby="content-title">
      <h2 id="content-title" className="section-title">
        Message content
      </h2>
      <p className="panel-intro">
        Read what the message says without opening it. Everything is shown as plain text with links
        defanged and hidden characters revealed. This content stays on your device and is never
        included in exported reports.
      </p>
      {available.length === 0 || !current ? (
        <p className="empty">
          {headersOnly
            ? 'Only headers were provided, so there is no body to show.'
            : 'The message has no text or HTML body.'}
        </p>
      ) : (
        <>
          <div className="filter-bar" role="group" aria-label="Content view">
            {available.map((view) => (
              <button
                key={view.id}
                type="button"
                className="chip"
                aria-pressed={view.id === current.id}
                onClick={() => setSelected(view.id)}
              >
                {view.label}
              </button>
            ))}
          </div>
          <p className="muted content-hint">{current.hint}</p>
          <pre className="raw content-view" tabIndex={0} aria-label={current.label}>
            <UntrustedText value={defangUrlsInText(text.replace(/^\s*\n/u, '').trimEnd())} />
          </pre>
          {body.preview.truncated && (
            <p className="notice">
              Long bodies are shortened in this preview; the analysis used the full text.
            </p>
          )}
        </>
      )}
    </section>
  );
}
