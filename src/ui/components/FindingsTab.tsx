import { useState } from 'react';
import { SEVERITY_LABELS } from '../../core/labels';
import type { Finding, Severity } from '../../core/types';
import { FindingList } from './FindingList';

const SEVERITIES: readonly Severity[] = ['high', 'medium', 'low', 'info'];

export function FindingsTab({ findings }: { findings: Finding[] }) {
  const [enabled, setEnabled] = useState<ReadonlySet<Severity>>(() => new Set(SEVERITIES));
  const visible = findings.filter((finding) => enabled.has(finding.severity));

  const toggle = (severity: Severity) => {
    const next = new Set(enabled);
    if (next.has(severity)) next.delete(severity);
    else next.add(severity);
    setEnabled(next);
  };

  return (
    <section aria-labelledby="findings-title">
      <h2 id="findings-title" className="visually-hidden" tabIndex={-1}>
        All findings
      </h2>
      <p className="panel-intro">
        Each finding comes from a documented rule. Expand one to see the evidence, why it may
        matter, and what commonly causes it in legitimate mail. Info findings are context only and
        do not affect the assessment.
      </p>
      <FindingList
        bulkControls
        toolbar={
          <div className="filter-bar" role="group" aria-label="Filter by severity">
            <span className="filter-bar__label">Show</span>
            {SEVERITIES.map((severity) => {
              const count = findings.filter((finding) => finding.severity === severity).length;
              return (
                <button
                  key={severity}
                  type="button"
                  className="chip"
                  aria-pressed={enabled.has(severity)}
                  onClick={() => toggle(severity)}
                >
                  <span className="chip__check" aria-hidden="true">
                    {enabled.has(severity) ? '\u2713' : ''}
                  </span>
                  {SEVERITY_LABELS[severity]} ({count})
                </button>
              );
            })}
          </div>
        }
        findings={visible}
        emptyMessage={
          findings.length === 0
            ? 'No rules matched this message.'
            : 'No findings match the selected severities.'
        }
      />
    </section>
  );
}
