import { useEffect, useRef } from 'react';
import { collectIndicators, indicatorCount } from '../../core/indicators';
import { formatBytes } from '../../core/text';
import type { AnalysisResult } from '../../core/types';
import { formatDate } from '../format';
import { AttachmentsTab } from './AttachmentsTab';
import { AuthenticationTab } from './AuthenticationTab';
import { ContentTab } from './ContentTab';
import { ExportMenu } from './ExportMenu';
import { FindingsTab } from './FindingsTab';
import { HeadersTab } from './HeadersTab';
import { BackIcon } from './Icons';
import { IndicatorsTab } from './IndicatorsTab';
import { LinksTab } from './LinksTab';
import { MethodTab } from './MethodTab';
import { OverviewTab } from './OverviewTab';
import { TabPanel, Tabs, type TabDefinition } from './Tabs';
import { UntrustedText } from './UntrustedText';
import { Verdict } from './Verdict';

export type ResultsTab =
  | 'overview'
  | 'findings'
  | 'headers'
  | 'authentication'
  | 'links'
  | 'attachments'
  | 'content'
  | 'indicators'
  | 'method';

interface ResultsViewProps {
  result: AnalysisResult;
  tab: ResultsTab;
  onTabChange: (tab: ResultsTab) => void;
  sourceLabel: string;
  /** Labels of parent messages when viewing an attached message. */
  trail: string[];
  canAnalyzeEmbedded: (index: number) => boolean;
  onAnalyzeEmbedded: (index: number) => void;
  onBack: (() => void) | null;
  onNew: () => void;
}

/** Moves focus to an element once it has been rendered, scrolling it into view. */
function focusWhenRendered(id: string) {
  requestAnimationFrame(() => {
    const element = document.getElementById(id);
    if (!element) return;
    element.focus({ preventScroll: true });
    if (typeof element.scrollIntoView === 'function') {
      element.scrollIntoView({ block: 'start', behavior: 'smooth' });
    }
  });
}

export function ResultsView({
  result,
  tab,
  onTabChange,
  sourceLabel,
  trail,
  canAnalyzeEmbedded,
  onAnalyzeEmbedded,
  onBack,
  onNew,
}: ResultsViewProps) {
  const heading = useRef<HTMLHeadingElement>(null);
  const { headers } = result;

  useEffect(() => {
    heading.current?.focus();
  }, []);

  const indicators = collectIndicators(result);
  const tabs: TabDefinition<ResultsTab>[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'findings', label: 'Findings', count: result.findings.length },
    { id: 'headers', label: 'Headers', count: headers.all.length },
    { id: 'authentication', label: 'Authentication' },
    { id: 'links', label: 'Links', count: result.urls.length },
    { id: 'attachments', label: 'Attachments', count: result.attachments.length },
    { id: 'content', label: 'Content' },
    { id: 'indicators', label: 'Indicators', count: indicatorCount(indicators) },
    { id: 'method', label: 'Method' },
  ];
  const sender = headers.from[0];
  const date = formatDate(headers.date.iso);

  const showMethod = () => {
    onTabChange('method');
    focusWhenRendered('method-assessment');
  };
  const showFindings = () => {
    onTabChange('findings');
    focusWhenRendered('findings-title');
  };

  return (
    <div className="container">
      <div className="results-bar">
        <div className="results-bar__nav">
          {onBack && (
            <button type="button" className="button button--secondary" onClick={onBack}>
              <BackIcon />
              Back to parent message
            </button>
          )}
          <button type="button" className="button button--secondary" onClick={onNew}>
            New analysis
          </button>
        </div>
        <ExportMenu result={result} />
      </div>

      {trail.length > 0 && (
        <p className="breadcrumb">
          Attached to: <UntrustedText value={trail.join(' › ')} max={200} />
        </p>
      )}

      <div className="message-head">
        <h1 ref={heading} tabIndex={-1}>
          {headers.subject ? (
            <UntrustedText value={headers.subject} max={300} />
          ) : (
            <span className="muted">(no subject)</span>
          )}
        </h1>
        <dl className="message-head__meta">
          <div>
            <dt>From</dt>
            <dd>
              {sender ? (
                <>
                  {sender.name && (
                    <>
                      <UntrustedText value={sender.name} max={120} />{' '}
                    </>
                  )}
                  <span className="mono">
                    &lt;
                    <UntrustedText value={sender.address} max={200} markNonAscii />
                    &gt;
                  </span>
                </>
              ) : (
                'No From header'
              )}
            </dd>
          </div>
          <div>
            <dt>Sent</dt>
            <dd>{date ?? (headers.date.raw ? 'Unparseable date' : 'No date')}</dd>
          </div>
          <div>
            <dt>Analysed</dt>
            <dd>
              <UntrustedText value={sourceLabel} max={120} /> ({formatBytes(result.meta.sizeBytes)})
              in this browser
            </dd>
          </div>
        </dl>
      </div>

      <Verdict assessment={result.assessment} onShowMethod={showMethod} />

      <Tabs
        tabs={tabs}
        selected={tab}
        onSelect={onTabChange}
        idPrefix="results"
        label="Analysis sections"
      />
      <TabPanel idPrefix="results" id={tab}>
        {tab === 'overview' && <OverviewTab result={result} onShowAllFindings={showFindings} />}
        {tab === 'findings' && <FindingsTab findings={result.findings} />}
        {tab === 'headers' && <HeadersTab headers={headers} />}
        {tab === 'authentication' && <AuthenticationTab authentication={result.authentication} />}
        {tab === 'links' && (
          <LinksTab
            urls={result.urls}
            findings={result.findings}
            truncated={result.urlsTruncated}
            headersOnly={result.meta.headersOnly}
          />
        )}
        {tab === 'attachments' && (
          <AttachmentsTab
            attachments={result.attachments}
            truncated={result.attachmentsTruncated}
            headersOnly={result.meta.headersOnly}
            canAnalyze={canAnalyzeEmbedded}
            onAnalyzeEmbedded={onAnalyzeEmbedded}
          />
        )}
        {tab === 'content' && (
          <ContentTab body={result.body} headersOnly={result.meta.headersOnly} />
        )}
        {tab === 'indicators' && <IndicatorsTab indicators={indicators} />}
        {tab === 'method' && (
          <MethodTab matchedRuleIds={new Set(result.findings.map((finding) => finding.ruleId))} />
        )}
      </TabPanel>
    </div>
  );
}
