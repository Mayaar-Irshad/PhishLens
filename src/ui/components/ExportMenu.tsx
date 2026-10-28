import { useEffect, useId, useRef, useState } from 'react';
import { buildReport, reportAsText, reportFileName, serializeReport } from '../../core/report';
import type { AnalysisResult } from '../../core/types';
import { CloseIcon, CopyIcon, DownloadIcon } from './Icons';

/** Saves a file generated in memory. Uses a short-lived blob URL; nothing leaves the device. */
function saveFile(contents: string, fileName: string, type: string): void {
  const url = URL.createObjectURL(new Blob([contents], { type }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.rel = 'noopener';
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function ExportMenu({ result }: { result: AnalysisResult }) {
  const [open, setOpen] = useState(false);
  const [includeRecipients, setIncludeRecipients] = useState(false);
  const [redactEmails, setRedactEmails] = useState(true);
  const [status, setStatus] = useState('');
  const panelId = useId();
  const container = useRef<HTMLDivElement>(null);
  const toggle = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return undefined;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false);
        toggle.current?.focus();
      }
    };
    const onPointer = (event: PointerEvent) => {
      if (container.current && !container.current.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('pointerdown', onPointer);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('pointerdown', onPointer);
    };
  }, [open]);

  const close = () => {
    setOpen(false);
    toggle.current?.focus();
  };
  const report = () => buildReport(result, { includeRecipients, redactEmailsInUrls: redactEmails });
  const download = () => {
    saveFile(serializeReport(report()), reportFileName(result), 'application/json');
    setStatus(`Saved ${reportFileName(result)}`);
  };
  const copySummary = async () => {
    try {
      await navigator.clipboard.writeText(reportAsText(report()));
      setStatus('Summary copied to the clipboard');
    } catch {
      setStatus('Copying failed. Your browser may block clipboard access.');
    }
  };

  return (
    <div
      className="export"
      ref={container}
      onBlur={(event) => {
        // Close when keyboard focus moves outside the menu.
        if (open && !container.current?.contains(event.relatedTarget) && event.relatedTarget) {
          setOpen(false);
        }
      }}
    >
      <button
        ref={toggle}
        type="button"
        className="button button--primary"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen(!open)}
      >
        <DownloadIcon />
        Export report
      </button>
      <div
        id={panelId}
        className="export__panel"
        hidden={!open}
        role="group"
        aria-label="Export report"
      >
        <div className="export__head">
          <h2>Export or share the findings</h2>
          <button
            type="button"
            className="button button--quiet button--icon"
            aria-label="Close"
            onClick={close}
          >
            <CloseIcon />
          </button>
        </div>
        <p>
          Reports contain findings, defanged indicators and hashes. They never include the message
          body, raw headers or attachment contents, and are generated on this device.
        </p>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={redactEmails}
            onChange={(event) => setRedactEmails(event.target.checked)}
          />
          <span>Redact email addresses that appear inside links</span>
        </label>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={includeRecipients}
            onChange={(event) => setIncludeRecipients(event.target.checked)}
          />
          <span>
            Include recipient addresses (To, Cc). Off by default to protect recipients&rsquo;
            privacy.
          </span>
        </label>
        <div className="export__actions">
          <button type="button" className="button button--primary button--small" onClick={download}>
            <DownloadIcon />
            Download JSON
          </button>
          <button
            type="button"
            className="button button--secondary button--small"
            onClick={() => void copySummary()}
          >
            <CopyIcon />
            Copy summary
          </button>
        </div>
        <p role="status">{status}</p>
      </div>
    </div>
  );
}
