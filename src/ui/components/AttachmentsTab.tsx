import { severityRank } from '../../core/findings';
import { formatBytes, pluralize } from '../../core/text';
import type { AttachmentContents, AttachmentRecord } from '../../core/types';
import { CopyButton } from './CopyButton';
import { SeverityTag } from './SeverityTag';
import { UntrustedText } from './UntrustedText';

function AttachmentContentsView({ contents }: { contents: AttachmentContents }) {
  const facts: string[] = [];
  if (contents.macros) facts.push('Contains a VBA macro project');
  if (contents.html) {
    facts.push(
      `HTML scan: ${pluralize(contents.html.forms, 'form')}, ${pluralize(contents.html.passwordFields, 'password field')}, ${pluralize(contents.html.scripts, 'script')}`,
    );
  }
  if (contents.pdfKeywords && contents.pdfKeywords.length > 0) {
    facts.push(
      `PDF keywords: ${contents.pdfKeywords.map((entry) => `/${entry.keyword} \u00d7${entry.count}`).join(', ')}`,
    );
  }
  if (contents.links > 0)
    facts.push(`${pluralize(contents.links, 'link')} found inside (listed on the Links tab)`);

  return (
    <>
      {facts.length > 0 && (
        <p className="link-row__facts">
          {facts.map((fact) => (
            <span key={fact}>{fact}</span>
          ))}
        </p>
      )}
      {contents.archive && (
        <details className="disclosure archive">
          <summary>
            Archive contents: {pluralize(contents.archive.totalEntries, 'entry', 'entries')}
            {contents.archive.entries.some((entry) => entry.risk) && ' (some flagged)'}
          </summary>
          <ul className="archive__list">
            {contents.archive.entries.map((entry, index) => (
              <li key={index}>
                <span className="mono">
                  <UntrustedText value={entry.name} max={200} />
                </span>
                <span className="muted">
                  {entry.name.endsWith('/') ? 'folder' : formatBytes(entry.sizeBytes)}
                  {entry.encrypted && ', encrypted'}
                </span>
                {entry.risk && <span className="archive__risk">{entry.risk}</span>}
              </li>
            ))}
          </ul>
          {contents.archive.truncated && (
            <p className="muted small">
              Only the first {contents.archive.entries.length} entries are listed.
            </p>
          )}
        </details>
      )}
    </>
  );
}

interface AttachmentsTabProps {
  attachments: AttachmentRecord[];
  truncated: boolean;
  headersOnly: boolean;
  canAnalyze: (index: number) => boolean;
  onAnalyzeEmbedded: (index: number) => void;
}

export function AttachmentsTab({
  attachments,
  truncated,
  headersOnly,
  canAnalyze,
  onAnalyzeEmbedded,
}: AttachmentsTabProps) {
  return (
    <section aria-labelledby="attachments-title">
      <h2 id="attachments-title" className="visually-hidden">
        Attachments
      </h2>
      <p className="panel-intro">
        Names and types are declared by the sender and may be false. PhishLens never opens, renders,
        extracts or runs attachments. It reads their bytes as data: the leading bytes identify the
        format, archive directories are listed, PDFs and HTML files are searched for active content
        and links, and a SHA-256 hash is computed for manual lookup. These are heuristics and cannot
        show whether a file is malicious or safe.
      </p>
      {attachments.length === 0 ? (
        <p className="empty">
          {headersOnly
            ? 'Only headers were provided, so attachments could not be listed.'
            : 'The message has no attachments.'}
        </p>
      ) : (
        <ul className="link-list">
          {attachments.map((attachment) => {
            const flags = [...attachment.flags].sort(
              (a, b) => severityRank(a.severity) - severityRank(b.severity),
            );
            const worst = flags.find((flag) => flag.severity !== 'info')?.severity;
            return (
              <li
                key={attachment.index}
                className={`link-row${worst ? ` link-row--${worst}` : ''}`}
              >
                <p className="attachment-row__name">
                  {attachment.filename ? (
                    <UntrustedText value={attachment.filename} max={200} />
                  ) : (
                    <span className="muted">Unnamed attachment</span>
                  )}
                </p>
                <p className="link-row__facts">
                  <span>{formatBytes(attachment.sizeBytes)}</span>
                  <span>
                    Declared type{' '}
                    <span className="mono">
                      <UntrustedText value={attachment.declaredType || 'none'} max={120} />
                    </span>
                  </span>
                  <span>
                    Detected format{' '}
                    {attachment.signature ? attachment.signature.label : 'not recognised'}
                  </span>
                  {attachment.inline && <span>Inline</span>}
                </p>
                {attachment.sha256 && (
                  <p className="hash">
                    <span className="visually-hidden">SHA-256 </span>
                    <span>sha256:{attachment.sha256}</span>
                    <CopyButton value={attachment.sha256} label="SHA-256 hash" />
                  </p>
                )}
                <AttachmentContentsView contents={attachment.contents} />
                {flags.length > 0 ? (
                  <ul className="flag-list" aria-label="Flags">
                    {flags.map((flag) => (
                      <li key={flag.ruleId}>
                        <SeverityTag severity={flag.severity} />
                        <span>
                          <UntrustedText value={flag.label} max={300} markNonAscii />
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="muted small">
                    No rules matched. That does not make the file safe to open.
                  </p>
                )}
                {attachment.isEmbeddedMessage && canAnalyze(attachment.index) && (
                  <p>
                    <button
                      type="button"
                      className="button button--secondary button--small"
                      onClick={() => onAnalyzeEmbedded(attachment.index)}
                    >
                      Analyze attached message
                    </button>
                  </p>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {truncated && (
        <p className="notice">Only the first {attachments.length} attachments were analysed.</p>
      )}
    </section>
  );
}
