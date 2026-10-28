import type {
  AuthenticationAnalysis,
  AuthResultsHeader,
  ReportedMethodSummary,
} from '../../core/types';
import { formatDate } from '../format';
import { WarningIcon } from './Icons';
import { UntrustedText } from './UntrustedText';

function SummaryCell({ name, summary }: { name: string; summary: ReportedMethodSummary | null }) {
  return (
    <div>
      <h3>{name} (reported)</h3>
      <p className={`auth-summary__result status-${summary?.status ?? 'missing'}`}>
        {summary ? <UntrustedText value={summary.result} max={30} /> : 'Not reported'}
      </p>
      <p className="auth-summary__detail">
        {summary ? (
          <>
            {summary.detail && (
              <>
                <UntrustedText value={summary.detail} max={200} />
                <br />
              </>
            )}
            Claimed by{' '}
            {summary.authservId ? (
              <UntrustedText value={summary.authservId} max={120} />
            ) : (
              'an unnamed server'
            )}
          </>
        ) : (
          'No Authentication-Results header mentions this check.'
        )}
      </p>
    </div>
  );
}

function ResultsTable({ header, position }: { header: AuthResultsHeader; position: number }) {
  return (
    <div className="section">
      <h3 className="subsection-title">
        {header.headerName} #{position}{' '}
        <span className="muted">
          from{' '}
          {header.authservId ? (
            <UntrustedText value={header.authservId} max={120} />
          ) : (
            'an unnamed server'
          )}
          {header.arcInstance !== null && <>, ARC instance {header.arcInstance}</>}
        </span>
      </h3>
      {header.results.length === 0 ? (
        <p className="empty">No results in this header.</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table data-table--wide">
            <thead>
              <tr>
                <th scope="col">Method</th>
                <th scope="col">Reported result</th>
                <th scope="col">Properties</th>
                <th scope="col">Comments</th>
              </tr>
            </thead>
            <tbody>
              {header.results.map((result, index) => (
                <tr key={index}>
                  <th scope="row">
                    <UntrustedText value={result.method} max={40} />
                  </th>
                  <td className={`status-${result.status}`}>
                    <UntrustedText value={result.result} max={40} />
                    {result.reason && (
                      <span className="muted">
                        {' '}
                        (reason: <UntrustedText value={result.reason} max={200} />)
                      </span>
                    )}
                  </td>
                  <td className="mono">
                    {result.properties.length === 0 ? (
                      <span className="muted">none</span>
                    ) : (
                      <span className="value-list">
                        {result.properties.map((property, propertyIndex) => (
                          <span key={propertyIndex}>
                            <UntrustedText value={`${property.key}=${property.value}`} max={200} />
                          </span>
                        ))}
                      </span>
                    )}
                  </td>
                  <td>
                    {result.comments.length === 0 ? (
                      <span className="muted">none</span>
                    ) : (
                      <UntrustedText value={result.comments.join(' ')} max={300} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {header.parseWarnings.length > 0 && <p className="muted">{header.parseWarnings.join(' ')}</p>}
      <details className="disclosure">
        <summary>Raw header</summary>
        <p className="raw">
          <UntrustedText value={header.raw} />
        </p>
      </details>
    </div>
  );
}

export function AuthenticationTab({ authentication }: { authentication: AuthenticationAnalysis }) {
  const { reported, authenticationResults, arcAuthenticationResults, receivedSpf, dkimSignatures } =
    authentication;
  return (
    <>
      <aside className="trust-notice" aria-labelledby="trust-title">
        <WarningIcon />
        <div>
          <h2 id="trust-title">Reported, not verified</h2>
          <p>
            Everything on this tab is copied from headers inside the message. PhishLens does not
            check SPF, DKIM or DMARC itself: that needs DNS lookups and the original delivery, which
            a browser-only tool does not have.
          </p>
          <p>
            Anyone who sends a message, or edits an .eml file, can write these headers. Only results
            added by your own receiving mail system are meaningful, and only if it removes forged
            copies. Usually that is the topmost Authentication-Results header, but PhishLens cannot
            confirm which server added which header. A genuine pass also proves only that the
            sending domain approved the message, not that the domain is trustworthy.
          </p>
        </div>
      </aside>

      <div
        className="auth-summary"
        role="group"
        aria-label="Reported results from the topmost header"
      >
        <SummaryCell name="SPF" summary={reported.spf} />
        <SummaryCell name="DKIM" summary={reported.dkim} />
        <SummaryCell name="DMARC" summary={reported.dmarc} />
      </div>

      <section className="section" aria-labelledby="auth-headers">
        <h2 id="auth-headers" className="section-title">
          Authentication-Results headers, topmost first
        </h2>
        {authenticationResults.length === 0 ? (
          <p className="empty">The message contains no Authentication-Results headers.</p>
        ) : (
          authenticationResults.map((header, index) => (
            <ResultsTable key={header.headerIndex} header={header} position={index + 1} />
          ))
        )}
      </section>

      {receivedSpf.length > 0 && (
        <section className="section" aria-labelledby="auth-spf">
          <h2 id="auth-spf" className="section-title">
            Received-SPF headers
          </h2>
          <div className="table-wrap">
            <table className="data-table data-table--wide">
              <thead>
                <tr>
                  <th scope="col">Reported result</th>
                  <th scope="col">Details</th>
                </tr>
              </thead>
              <tbody>
                {receivedSpf.map((spf) => (
                  <tr key={spf.headerIndex}>
                    <td className={`status-${spf.status}`}>
                      <UntrustedText value={spf.result} max={30} />
                    </td>
                    <td className="mono">
                      <UntrustedText
                        value={[spf.comment, ...spf.properties.map((p) => `${p.key}=${p.value}`)]
                          .filter(Boolean)
                          .join('; ')}
                        max={500}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <section className="section" aria-labelledby="auth-dkim">
        <h2 id="auth-dkim" className="section-title">
          DKIM signatures (not verified)
        </h2>
        {dkimSignatures.length === 0 ? (
          <p className="empty">The message has no DKIM-Signature headers.</p>
        ) : (
          <div className="table-wrap">
            <table className="data-table data-table--wide">
              <thead>
                <tr>
                  <th scope="col">Signing domain (d=)</th>
                  <th scope="col">Selector (s=)</th>
                  <th scope="col">Algorithm</th>
                  <th scope="col">Matches From domain</th>
                  <th scope="col">Signed headers</th>
                  <th scope="col">Notes</th>
                </tr>
              </thead>
              <tbody>
                {dkimSignatures.map((signature) => (
                  <tr key={signature.headerIndex}>
                    <td className="mono">
                      {signature.domain ? (
                        <UntrustedText value={signature.domain} max={120} />
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="mono">
                      {signature.selector ? (
                        <UntrustedText value={signature.selector} max={80} />
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="mono">
                      {signature.algorithm ? (
                        <UntrustedText value={signature.algorithm} max={40} />
                      ) : (
                        '—'
                      )}
                    </td>
                    <td>
                      {signature.alignedWithFrom === null
                        ? 'Unknown'
                        : signature.alignedWithFrom
                          ? 'Yes'
                          : 'No'}
                    </td>
                    <td className="mono">
                      <UntrustedText value={signature.signedHeaders.join(', ') || '—'} max={300} />
                    </td>
                    <td>
                      {[
                        signature.bodyLengthLimit !== null
                          ? `Covers only the first ${signature.bodyLengthLimit} body bytes (l=).`
                          : null,
                        signature.timestamp
                          ? `Signed ${formatDate(signature.timestamp) ?? signature.timestamp}.`
                          : null,
                        ...signature.parseWarnings,
                      ]
                        .filter(Boolean)
                        .join(' ') || <span className="muted">none</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {arcAuthenticationResults.length > 0 && (
        <section className="section" aria-labelledby="auth-arc">
          <h2 id="auth-arc" className="section-title">
            ARC authentication results
          </h2>
          <p className="panel-intro">
            ARC headers record results seen by intermediaries such as mailing lists. They are
            equally unverified here.
          </p>
          {arcAuthenticationResults.map((header, index) => (
            <ResultsTable key={header.headerIndex} header={header} position={index + 1} />
          ))}
        </section>
      )}
    </>
  );
}
