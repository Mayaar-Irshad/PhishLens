import { useState } from 'react';
import { defangUrl, defangUrlsInText } from '../../core/defang';
import { severityRank } from '../../core/findings';
import { describeSource } from '../../core/labels';
import type { Finding, Severity, UrlRecord } from '../../core/types';
import { CopyButton } from './CopyButton';
import { SeverityTag } from './SeverityTag';
import { UntrustedText } from './UntrustedText';

/**
 * Findings outside the link rules that cite this URL in their evidence, such
 * as the password form that submits to it.
 */
function relatedFindings(url: UrlRecord, findings: Finding[]): Finding[] {
  const forms = new Set([url.defanged, url.rawDefanged, defangUrl(url.raw)].filter(Boolean));
  return findings.filter(
    (finding) =>
      finding.category !== 'url' &&
      finding.instances.some((instance) => instance.evidence.some((item) => forms.has(item.value))),
  );
}

function worstSeverity(url: UrlRecord, related: Finding[]): Severity | null {
  const ranked = [
    ...url.flags.map((flag) => flag.severity),
    ...related.map((finding) => finding.severity),
  ].sort((a, b) => severityRank(a) - severityRank(b));
  return ranked[0] ?? null;
}

function LinkRow({ url, related }: { url: UrlRecord; related: Finding[] }) {
  const worst = worstSeverity(url, related);
  const texts = [
    ...new Set(
      url.sources
        .map((source) => source.text)
        .filter((text): text is string => Boolean(text))
        .map(defangUrlsInText),
    ),
  ];
  const where = [...new Set(url.sources.map(describeSource))];

  return (
    <li className={`link-row${worst && worst !== 'info' ? ` link-row--${worst}` : ''}`}>
      <div className="link-row__top">
        <p className="link-row__url">
          <span className="visually-hidden">Defanged link: </span>
          <UntrustedText value={url.defanged} max={400} />
        </p>
        <CopyButton value={url.defanged} label="defanged link" />
      </div>
      <p className="link-row__facts">
        {url.registrableDomain && (
          <span>
            Registered domain{' '}
            <strong className="mono">
              <UntrustedText value={url.registrableDomain.replace(/\./gu, '[.]')} />
            </strong>
          </span>
        )}
        {url.hostUnicode && (
          <span>
            Displays as{' '}
            <strong>
              <UntrustedText value={url.hostUnicode} max={120} markNonAscii />
            </strong>
          </span>
        )}
        {!url.host && url.scheme && <span>Scheme {url.scheme}:</span>}
        <span>Found in {where.join(', ')}</span>
      </p>
      {texts.length > 0 && (
        <p className="link-row__facts">
          <span>
            Link text: &ldquo;
            <UntrustedText value={texts.join('", "')} max={240} markNonAscii />
            &rdquo;
          </span>
        </p>
      )}
      {url.rawDefanged && (
        <p className="link-row__facts">
          <span>
            Written in the message as{' '}
            <span className="mono">
              <UntrustedText value={url.rawDefanged} max={300} />
            </span>
          </span>
        </p>
      )}
      {url.embedded.length > 0 && (
        <ul className="flag-list" aria-label="Embedded destinations">
          {url.embedded.map((entry, index) => (
            <li key={index}>
              <span className="muted">
                {entry.kind === 'security-wrapper'
                  ? 'Unwrapped destination'
                  : `Redirect parameter "${entry.parameter}"`}
                :
              </span>
              <span className="mono">
                <UntrustedText value={entry.defanged} max={300} />
              </span>
            </li>
          ))}
        </ul>
      )}
      {url.flags.length > 0 && (
        <ul className="flag-list" aria-label="Flags">
          {[...url.flags]
            .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
            .map((flag) => (
              <li key={flag.ruleId}>
                <SeverityTag severity={flag.severity} />
                <span>
                  <UntrustedText value={flag.label} max={300} markNonAscii />
                </span>
              </li>
            ))}
        </ul>
      )}
      {related.length > 0 && (
        <ul className="flag-list" aria-label="Referenced by findings">
          {related.map((finding) => (
            <li key={finding.ruleId}>
              <SeverityTag severity={finding.severity} />
              <span>Referenced by: {finding.title}</span>
            </li>
          ))}
        </ul>
      )}
      {url.flags.length === 0 && related.length === 0 && (
        <p className="muted small">
          No link rules matched. That does not make the destination safe.
        </p>
      )}
    </li>
  );
}

export function LinksTab({
  urls,
  findings,
  truncated,
  headersOnly,
}: {
  urls: UrlRecord[];
  findings: Finding[];
  truncated: boolean;
  headersOnly: boolean;
}) {
  const [onlyFlagged, setOnlyFlagged] = useState(false);
  const related = new Map(urls.map((url) => [url.id, relatedFindings(url, findings)]));
  const relatedOf = (url: UrlRecord) => related.get(url.id) ?? [];
  const isFlagged = (url: UrlRecord) =>
    url.flags.some((flag) => flag.severity !== 'info') ||
    relatedOf(url).some((finding) => finding.severity !== 'info');
  const sorted = [...urls].sort((a, b) => {
    const rank = (url: UrlRecord) => {
      const worst = worstSeverity(url, relatedOf(url));
      return worst ? severityRank(worst) : 9;
    };
    return rank(a) - rank(b) || a.id - b.id;
  });
  const visible = onlyFlagged ? sorted.filter(isFlagged) : sorted;

  return (
    <section aria-labelledby="links-title">
      <h2 id="links-title" className="visually-hidden">
        Links
      </h2>
      <p className="panel-intro">
        Links from the message and its attachments, shown defanged (
        <code>hxxps[://]example[.]com</code>) so they cannot be clicked or auto-linked when copied.
        PhishLens never opened, fetched or resolved any of them. Images and other remote resources
        are counted on the Findings tab, not listed here.
      </p>
      {urls.length > 0 && (
        <div className="filter-bar">
          <button
            type="button"
            className="chip"
            aria-pressed={onlyFlagged}
            onClick={() => setOnlyFlagged(!onlyFlagged)}
          >
            <span className="chip__check" aria-hidden="true">
              {onlyFlagged ? '\u2713' : ''}
            </span>
            Only flagged links ({urls.filter(isFlagged).length})
          </button>
        </div>
      )}
      {visible.length === 0 ? (
        <p className="empty">
          {headersOnly
            ? 'Only headers were provided, so there is no body to extract links from.'
            : urls.length === 0
              ? 'No links were found in the message or its attachments.'
              : 'No links match the filter.'}
        </p>
      ) : (
        <ul className="link-list">
          {visible.map((url) => (
            <LinkRow key={url.id} url={url} related={relatedOf(url)} />
          ))}
        </ul>
      )}
      {truncated && (
        <p className="notice">Only the first {urls.length} distinct links were analysed.</p>
      )}
    </section>
  );
}
