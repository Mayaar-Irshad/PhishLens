import { pluralize } from '../../core/text';
import type { HeaderAnalysis } from '../../core/types';
import { formatDate, formatDuration } from '../format';
import { UntrustedText } from './UntrustedText';

const LONG_FIELDS = new Set(['received', 'authentication-results', 'dkim-signature']);

function KeyFields({ headers }: { headers: HeaderAnalysis }) {
  const fields = headers.fields.filter((field) => !LONG_FIELDS.has(field.key));
  return (
    <div className="table-wrap">
      <table className="data-table data-table--stack">
        <caption className="visually-hidden">Key header fields</caption>
        <thead>
          <tr>
            <th scope="col">Header</th>
            <th scope="col">Value (decoded)</th>
          </tr>
        </thead>
        <tbody>
          {fields.map((field) => (
            <tr key={field.key}>
              <th scope="row">
                {field.label}
                {field.values.length > 1 && (
                  <span className="repeat-badge">×{field.values.length}</span>
                )}
              </th>
              <td>
                {field.values.length === 0 ? (
                  <span className="muted">Not present</span>
                ) : (
                  <span className="value-list">
                    {field.decoded.map((value, index) => (
                      <span key={index} className="mono">
                        <UntrustedText value={value} max={500} />
                      </span>
                    ))}
                  </span>
                )}
              </td>
            </tr>
          ))}
          <tr>
            <th scope="row">Received</th>
            <td>
              {pluralize(headers.counts['received'] ?? 0, 'header')}, shown in the transit path
              below
            </td>
          </tr>
          <tr>
            <th scope="row">Authentication-Results</th>
            <td>
              {pluralize(headers.counts['authentication-results'] ?? 0, 'header')}, see the
              Authentication tab
            </td>
          </tr>
          <tr>
            <th scope="row">DKIM-Signature</th>
            <td>
              {pluralize(headers.counts['dkim-signature'] ?? 0, 'header')}, see the Authentication
              tab
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}

function TransitPath({ headers }: { headers: HeaderAnalysis }) {
  if (headers.received.length === 0) {
    return (
      <p className="empty">
        No Received headers. Drafts, sent items and partial header copies have none.
      </p>
    );
  }
  const hops = [...headers.received].reverse();
  return (
    <ol className="hops">
      {hops.map((hop, index) => {
        const previous = hops[index - 1];
        const delta =
          previous?.dateIso && hop.dateIso
            ? Date.parse(hop.dateIso) - Date.parse(previous.dateIso)
            : null;
        return (
          <li key={hop.headerIndex} className="hop">
            <span className="hop__number" aria-hidden="true">
              {index + 1}
            </span>
            <div className="hop__body">
              <p className="hop__title">
                <span className="visually-hidden">Hop {index + 1}: </span>
                {hop.from ? (
                  <UntrustedText value={hop.from} max={120} />
                ) : (
                  <span className="muted">unknown sender</span>
                )}
                {' to '}
                {hop.by ? (
                  <UntrustedText value={hop.by} max={120} />
                ) : (
                  <span className="muted">unknown server</span>
                )}
              </p>
              <p className="hop__meta">
                {hop.ips.length > 0 && <>IP {hop.ips.join(', ')}. </>}
                {hop.with && (
                  <>
                    Protocol <UntrustedText value={hop.with} max={40} />.{' '}
                  </>
                )}
                {formatDate(hop.dateIso) ?? (hop.dateRaw ? 'Unparseable date' : 'No date')}
                {delta !== null && (
                  <>
                    {' '}
                    (
                    {delta < 0
                      ? `${formatDuration(delta)} earlier than the previous hop`
                      : `+${formatDuration(delta)}`}
                    )
                  </>
                )}
              </p>
              <details className="disclosure hop__raw">
                <summary>Raw header</summary>
                <p className="raw">
                  <UntrustedText value={hop.raw} />
                </p>
              </details>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

export function HeadersTab({ headers }: { headers: HeaderAnalysis }) {
  return (
    <>
      <section className="section" aria-labelledby="headers-key">
        <h2 id="headers-key" className="section-title">
          Key fields
        </h2>
        <p className="panel-intro">
          Header values are written by the sender and the servers that handled the message. Repeated
          headers are marked with a count, and hidden characters are shown as red markers.
        </p>
        <KeyFields headers={headers} />
      </section>

      {headers.notable.length > 0 && (
        <section className="section" aria-labelledby="headers-notable">
          <h2 id="headers-notable" className="section-title">
            Other notable headers
          </h2>
          <p className="panel-intro">
            Less common headers that can help an investigation, such as the sending software
            (X-Mailer) or the sender&rsquo;s IP address as recorded by their provider.
          </p>
          <div className="table-wrap">
            <table className="data-table data-table--stack">
              <caption className="visually-hidden">Other notable headers</caption>
              <tbody>
                {headers.notable.map((field) => (
                  <tr key={field.key}>
                    <th scope="row">{field.label}</th>
                    <td>
                      <span className="value-list">
                        {field.decoded.map((value, index) => (
                          <span key={index} className="mono">
                            <UntrustedText value={value} max={500} />
                          </span>
                        ))}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <section className="section" aria-labelledby="headers-path">
        <h2 id="headers-path" className="section-title">
          Transit path, oldest first
        </h2>
        <p className="panel-intro">
          Each server adds a Received header on top of the previous ones. Only the hops added by
          your own mail provider are trustworthy; earlier hops (the first ones listed) can be
          invented by the sender.
        </p>
        <TransitPath headers={headers} />
      </section>

      <section className="section" aria-labelledby="headers-all">
        <h2 id="headers-all" className="section-title">
          All headers
        </h2>
        <details className="disclosure">
          <summary>Show all {headers.all.length} headers in original order</summary>
          <ol className="header-list">
            {headers.all.map((entry) => (
              <li key={entry.index} className="header-line">
                <span className="header-line__index">{entry.index + 1}</span>
                <span className="header-line__name">
                  <UntrustedText value={entry.name} max={80} />
                </span>
                <span className="header-line__value">
                  <UntrustedText value={entry.value} max={2000} />
                </span>
              </li>
            ))}
          </ol>
        </details>
      </section>
    </>
  );
}
