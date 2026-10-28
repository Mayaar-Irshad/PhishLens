import type { RuleId } from '../../core/rules';
import { analystSteps, recommendedSteps } from '../../core/recommendations';
import type { AddressInfo, AnalysisResult, Finding, ReportedMethodSummary } from '../../core/types';
import { FindingList } from './FindingList';
import { SeverityTag } from './SeverityTag';
import { UntrustedText } from './UntrustedText';

/** Overview always lists every high finding, then fills up to this many rows. */
const OVERVIEW_ROWS = 6;

function AddressValue({ addresses }: { addresses: AddressInfo[] }) {
  if (addresses.length === 0) return <span className="muted">Not present</span>;
  return (
    <span className="value-list">
      {addresses.map((address, index) => (
        <span key={index}>
          {address.name && (
            <span className="address__name">
              <UntrustedText value={address.name} max={120} />{' '}
            </span>
          )}
          <span className="mono">
            &lt;
            <UntrustedText value={address.address} max={200} markNonAscii />
            &gt;
          </span>
          {address.domainUnicode && (
            <span className="muted">
              {' '}
              (displays as <UntrustedText value={address.domainUnicode} markNonAscii />)
            </span>
          )}
        </span>
      ))}
    </span>
  );
}

/** A compact marker linking a fact to the finding it triggered. */
function FactFlag({
  findings,
  ruleIds,
  note,
}: {
  findings: Finding[];
  ruleIds: RuleId[];
  note: string;
}) {
  const match = findings.find((finding) => ruleIds.includes(finding.ruleId));
  if (!match) return null;
  return (
    <span className="fact-flag">
      <SeverityTag severity={match.severity} /> <span>{note}</span>
    </span>
  );
}

function reportedText(summary: ReportedMethodSummary | null): string {
  return summary ? summary.result : 'not reported';
}

interface OverviewTabProps {
  result: AnalysisResult;
  onShowAllFindings: () => void;
}

export function OverviewTab({ result, onShowAllFindings }: OverviewTabProps) {
  const ranked = result.findings.filter((finding) => finding.severity !== 'info');
  const highs = ranked.filter((finding) => finding.severity === 'high');
  const important = ranked.slice(0, Math.max(OVERVIEW_ROWS, highs.length));
  const { headers, authentication, findings } = result;
  const flaggedLinks = result.urls.filter((url) =>
    url.flags.some((flag) => flag.severity !== 'info'),
  ).length;
  const flaggedAttachments = result.attachments.filter((attachment) =>
    attachment.flags.some((flag) => flag.severity !== 'info'),
  ).length;

  return (
    <div className="overview">
      <section aria-labelledby="overview-findings">
        <h2 id="overview-findings" className="section-title">
          Most important findings
        </h2>
        <FindingList
          findings={important}
          emptyMessage="No high, medium or low findings. That is not evidence that the message is safe; see the recommended steps."
        />
        {result.findings.length > important.length && (
          <p className="more-link">
            {important.length === 0
              ? `${result.findings.length} info ${result.findings.length === 1 ? 'finding gives' : 'findings give'} context only.`
              : `Showing ${important.length} of ${result.findings.length} findings.`}{' '}
            <button type="button" className="link-button" onClick={onShowAllFindings}>
              View all findings
            </button>
          </p>
        )}
        {result.meta.warnings.length > 0 && (
          <div className="notice" role="note">
            <p>
              <strong>Analysis notes</strong>
            </p>
            <ul>
              {result.meta.warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          </div>
        )}
      </section>

      <div>
        <section aria-labelledby="overview-glance" className="section">
          <h2 id="overview-glance" className="section-title">
            Message at a glance
          </h2>
          <dl className="facts">
            <dt>From</dt>
            <dd>
              <AddressValue addresses={headers.from} />
              <FactFlag
                findings={findings}
                ruleIds={[
                  'SENDER_LOOKALIKE_DOMAIN',
                  'SENDER_MIXED_SCRIPT_DOMAIN',
                  'SENDER_FREEMAIL_BRAND',
                ]}
                note="impersonation signs"
              />
              <FactFlag
                findings={findings}
                ruleIds={[
                  'SENDER_DISPLAY_NAME_BRAND',
                  'SENDER_DISPLAY_NAME_ADDRESS',
                  'SENDER_BRAND_IN_DOMAIN',
                ]}
                note="name and address disagree"
              />
            </dd>
            <dt>Reply-To</dt>
            <dd>
              <AddressValue addresses={headers.replyTo} />
              <FactFlag
                findings={findings}
                ruleIds={['SENDER_REPLY_TO_FREEMAIL', 'SENDER_REPLY_TO_DIFFERENT_DOMAIN']}
                note="differs from the From domain"
              />
            </dd>
            <dt>Return-Path</dt>
            <dd>
              <AddressValue addresses={headers.returnPath} />
              <FactFlag
                findings={findings}
                ruleIds={['SENDER_RETURN_PATH_DIFFERENT_DOMAIN']}
                note="differs from the From domain"
              />
            </dd>
            <dt>Reported auth</dt>
            <dd>
              SPF {reportedText(authentication.reported.spf)}, DKIM{' '}
              {reportedText(authentication.reported.dkim)}, DMARC{' '}
              {reportedText(authentication.reported.dmarc)}
              <span className="muted"> (unverified)</span>
            </dd>
            <dt>Claimed origin</dt>
            <dd>
              {headers.originIp ? (
                <>
                  <span className="mono">{headers.originIp.ip.replace(/\./gu, '[.]')}</span>
                  <span className="muted">
                    {' '}
                    (
                    {headers.originIp.source === 'received'
                      ? 'earliest Received header'
                      : 'X-Originating-IP header'}
                    , forgeable)
                  </span>
                </>
              ) : (
                <span className="muted">No public IP recorded</span>
              )}
            </dd>
            <dt>Links</dt>
            <dd>
              {result.urls.length} found, {flaggedLinks} flagged
            </dd>
            <dt>Attachments</dt>
            <dd>
              {result.attachments.length} found, {flaggedAttachments} flagged
            </dd>
          </dl>
        </section>

        <section aria-labelledby="overview-steps" className="section">
          <h2 id="overview-steps" className="section-title">
            Recommended next steps
          </h2>
          <h3 className="steps-title">If you received this message</h3>
          <ol className="steps">
            {recommendedSteps(result).map((step) => (
              <li key={step}>
                <span>{step}</span>
              </li>
            ))}
          </ol>
          <h3 className="steps-title">If you are investigating it</h3>
          <ol className="steps">
            {analystSteps(result).map((step) => (
              <li key={step}>
                <span>
                  <UntrustedText value={step} max={400} />
                </span>
              </li>
            ))}
          </ol>
        </section>
      </div>
    </div>
  );
}
