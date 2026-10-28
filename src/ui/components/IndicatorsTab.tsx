import { indicatorCount, indicatorsAsText, type Indicators } from '../../core/indicators';
import { CopyButton } from './CopyButton';
import { UntrustedText } from './UntrustedText';

function IndicatorGroup({
  title,
  values,
  note,
}: {
  title: string;
  values: string[];
  note?: string;
}) {
  if (values.length === 0) return null;
  return (
    <section className="ioc-group" aria-label={title}>
      <div className="ioc-group__head">
        <h3>
          {title} <span className="muted">({values.length})</span>
        </h3>
        <CopyButton value={values.join('\n')} label={`all ${title.toLowerCase()}`} />
      </div>
      {note && <p className="ioc-group__note">{note}</p>}
      <ul className="ioc-list">
        {values.map((value) => (
          <li key={value}>
            <span className="mono">
              <UntrustedText value={value} max={500} markNonAscii />
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function IndicatorsTab({ indicators }: { indicators: Indicators }) {
  const total = indicatorCount(indicators);
  return (
    <section aria-labelledby="indicators-title">
      <div className="panel-head">
        <div>
          <h2 id="indicators-title" className="section-title">
            Indicators of compromise
          </h2>
          <p className="panel-intro">
            Addresses, domains, IP addresses, links and file hashes from this message, defanged so
            they stay inert when pasted into tickets, chat or search tools. Recipient addresses are
            left out. These are leads to investigate, not confirmed malicious indicators.
          </p>
        </div>
        {total > 0 && (
          <CopyButton
            value={indicatorsAsText(indicators)}
            label="all indicators"
            text={`Copy all ${total}`}
            secondary
          />
        )}
      </div>
      {total === 0 ? (
        <p className="empty">No indicators were found in this message.</p>
      ) : (
        <div className="ioc-grid">
          <IndicatorGroup title="Sender addresses" values={indicators.senderAddresses} />
          <IndicatorGroup
            title="Domains"
            note="The sender's domains and those of links that matched a rule."
            values={indicators.domains}
          />
          <IndicatorGroup
            title="Other linked domains"
            note="Linked from the message without matching any rule. Many are legitimate; check before blocking."
            values={indicators.otherDomains}
          />
          <IndicatorGroup
            title="IP addresses"
            note="The claimed origin and any links that use a raw IP address."
            values={indicators.ips}
          />
          <IndicatorGroup title="URLs" values={indicators.urls} />
          <IndicatorGroup
            title="Attachment SHA-256 hashes"
            values={indicators.attachmentHashes.map((entry) => `${entry.sha256}  ${entry.name}`)}
          />
          {indicators.messageSha256 && (
            <IndicatorGroup title="Message SHA-256" values={[indicators.messageSha256]} />
          )}
        </div>
      )}
    </section>
  );
}
