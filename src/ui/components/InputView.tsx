import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react';
import { ACCEPT_ATTRIBUTE } from '../../core/input';
import { formatBytes } from '../../core/text';
import { SAMPLES, type Sample } from '../../samples';
import { HeaderIcon, KeyIcon, LinkIcon, PaperclipIcon, UploadIcon } from './Icons';

type Mode = 'upload' | 'paste';

interface InputViewProps {
  maxBytes: number;
  pasteText: string;
  /** True while a file is being dragged anywhere over the page. */
  dragging: boolean;
  /** Move focus to the heading on mount (after "New analysis", cancel or an error). */
  focusOnMount: boolean;
  onPasteTextChange: (value: string) => void;
  onFile: (file: File) => void;
  onPaste: (text: string) => void;
  onSample: (sample: Sample) => void;
}

const encoder = new TextEncoder();

function prefersTouch(): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia('(pointer: coarse)').matches;
}

/** Text that plausibly contains email headers ("Name: value" lines). */
function looksLikeHeaders(text: string): boolean {
  return /^[\x21-\x39\x3B-\x7E]+[ \t]*:/mu.test(text);
}

export function InputView({
  maxBytes,
  pasteText,
  dragging,
  focusOnMount,
  onPasteTextChange,
  onFile,
  onPaste,
  onSample,
}: InputViewProps) {
  const [mode, setMode] = useState<Mode>(pasteText ? 'paste' : 'upload');
  const fileInput = useRef<HTMLInputElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const textarea = useRef<HTMLTextAreaElement>(null);
  const textareaId = useId();
  const hintId = useId();
  const [touch] = useState(prefersTouch);
  const pasteBytes = pasteText ? encoder.encode(pasteText).byteLength : 0;
  const nearLimit = pasteBytes > maxBytes * 0.9;

  useEffect(() => {
    if (focusOnMount) heading.current?.focus();
  }, [focusOnMount]);

  // Pasting anywhere on this screen (outside a text field) fills the paste box.
  useEffect(() => {
    const onPasteEvent = (event: ClipboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (target?.closest('textarea, input, [contenteditable="true"]')) return;
      const text = event.clipboardData?.getData('text/plain') ?? '';
      if (!text.trim() || !looksLikeHeaders(text)) return;
      event.preventDefault();
      setMode('paste');
      onPasteTextChange(text);
      requestAnimationFrame(() => textarea.current?.focus());
    };
    document.addEventListener('paste', onPasteEvent);
    return () => document.removeEventListener('paste', onPasteEvent);
  }, [onPasteTextChange]);

  const modeKeys = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
      event.preventDefault();
      const next: Mode = mode === 'upload' ? 'paste' : 'upload';
      setMode(next);
      document.getElementById(`mode-${next}`)?.focus();
    }
  };

  return (
    <div className="container intake">
      <section className="intake__lede" aria-labelledby="intake-title">
        <h1 id="intake-title" ref={heading} tabIndex={-1}>
          Inspect a suspicious email without opening it
        </h1>
        <p>
          Give PhishLens the raw message. It explains what looks wrong and why, in this browser,
          without following a single link.
        </p>
      </section>

      <ul className="checks-list" aria-label="What PhishLens checks">
        <li>
          <HeaderIcon />
          <span>
            <strong>Sender and headers.</strong> Look-alike domains, mismatched reply addresses and
            the route the message claims to have taken.
          </span>
        </li>
        <li>
          <KeyIcon />
          <span>
            <strong>Reported authentication.</strong> SPF, DKIM and DMARC results as the headers
            state them, clearly marked as unverified.
          </span>
        </li>
        <li>
          <LinkIcon />
          <span>
            <strong>Links.</strong> Text that disguises its destination, raw IP addresses, punycode
            and other tricks, shown defanged so nothing is clickable.
          </span>
        </li>
        <li>
          <PaperclipIcon />
          <span>
            <strong>Attachments.</strong> Risky types and disguised names, plus what archives, PDFs
            and HTML files contain, read as data and never opened.
          </span>
        </li>
      </ul>

      <section className="intake__input" aria-label="Provide a message">
        <div className="mode-switch" role="tablist" aria-label="How to provide the message">
          <button
            id="mode-upload"
            type="button"
            role="tab"
            aria-selected={mode === 'upload'}
            aria-controls="mode-panel"
            tabIndex={mode === 'upload' ? 0 : -1}
            onClick={() => setMode('upload')}
            onKeyDown={modeKeys}
          >
            Upload .eml file
          </button>
          <button
            id="mode-paste"
            type="button"
            role="tab"
            aria-selected={mode === 'paste'}
            aria-controls="mode-panel"
            tabIndex={mode === 'paste' ? 0 : -1}
            onClick={() => setMode('paste')}
            onKeyDown={modeKeys}
          >
            Paste source
          </button>
        </div>

        <div id="mode-panel" role="tabpanel" aria-labelledby={`mode-${mode}`}>
          {mode === 'upload' ? (
            <div className={`envelope${dragging ? ' envelope--active' : ''}`}>
              <div className="envelope__label">
                <h2>
                  {dragging
                    ? 'Drop to inspect'
                    : touch
                      ? 'Choose an .eml file'
                      : 'Drop an .eml file here'}
                </h2>
                <p>
                  Saved messages from Gmail, Outlook, Apple Mail or Thunderbird, up to{' '}
                  {formatBytes(maxBytes)}. Outlook .msg files are not supported.
                </p>
                <button
                  type="button"
                  className="button button--primary"
                  onClick={() => fileInput.current?.click()}
                >
                  <UploadIcon />
                  Choose file
                </button>
                <input
                  ref={fileInput}
                  type="file"
                  accept={ACCEPT_ATTRIBUTE}
                  hidden
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    // Reset so choosing the same file again still triggers a change.
                    event.target.value = '';
                    if (file) onFile(file);
                  }}
                />
              </div>
            </div>
          ) : (
            <form
              className="paste-panel"
              onSubmit={(event) => {
                event.preventDefault();
                onPaste(pasteText);
              }}
            >
              <label htmlFor={textareaId}>Raw message or headers</label>
              <textarea
                id={textareaId}
                ref={textarea}
                aria-describedby={hintId}
                value={pasteText}
                onChange={(event) => onPasteTextChange(event.target.value)}
                onKeyDown={(event) => {
                  if (
                    event.key === 'Enter' &&
                    (event.metaKey || event.ctrlKey) &&
                    pasteText.trim()
                  ) {
                    event.preventDefault();
                    onPaste(pasteText);
                  }
                }}
                spellCheck={false}
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                placeholder={
                  'Received: from mail.example.com ...\nFrom: "Sender" <sender@example.com>\nSubject: ...'
                }
              />
              <p id={hintId} className="paste-panel__hint">
                In Gmail use &ldquo;Show original&rdquo;, in Outlook the message&rsquo;s internet
                headers or &ldquo;View message source&rdquo;. Text before the first header, such as
                Gmail&rsquo;s summary, is skipped automatically. Press Ctrl+Enter (&#8984;+Enter on
                Mac) to analyse.
              </p>
              <div className="paste-panel__actions">
                <button
                  type="submit"
                  className="button button--primary"
                  disabled={!pasteText.trim()}
                >
                  Analyze message
                </button>
                <button
                  type="button"
                  className="button button--secondary"
                  disabled={!pasteText}
                  onClick={() => onPasteTextChange('')}
                >
                  Clear
                </button>
                <span
                  className={`paste-panel__meter${nearLimit ? ' paste-panel__meter--warn' : ''}`}
                >
                  {formatBytes(pasteBytes)} of {formatBytes(maxBytes)}
                  {nearLimit && <span role="status"> (close to the size limit)</span>}
                </span>
              </div>
            </form>
          )}
        </div>

        <section className="samples" aria-labelledby="samples-title">
          <h2 id="samples-title">No email at hand? Try a synthetic sample</h2>
          <p>Fictional messages using reserved example domains, analysed exactly like an upload.</p>
          <ul>
            {SAMPLES.map((sample) => (
              <li key={sample.id}>
                <button type="button" className="sample-button" onClick={() => onSample(sample)}>
                  <strong>{sample.title}</strong>
                  <span>{sample.description}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      </section>
    </div>
  );
}
