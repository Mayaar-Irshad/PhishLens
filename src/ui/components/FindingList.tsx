import { useId, useState, type ReactNode } from 'react';
import type { Finding } from '../../core/types';
import { ChevronIcon } from './Icons';
import { SeverityTag } from './SeverityTag';
import { UntrustedText } from './UntrustedText';

interface FindingRowProps {
  finding: Finding;
  headingLevel: 3 | 4;
  open: boolean;
  onToggle: () => void;
}

function FindingRow({ finding, headingLevel, open, onToggle }: FindingRowProps) {
  const bodyId = useId();
  const summaryId = useId();
  const Heading = headingLevel === 3 ? 'h3' : 'h4';
  const hidden = finding.occurrences - finding.instances.length;
  const first = finding.instances[0]?.message;

  return (
    <li className="finding">
      <Heading>
        <button
          type="button"
          className="finding__toggle"
          aria-expanded={open}
          aria-controls={bodyId}
          aria-describedby={!open && first ? summaryId : undefined}
          onClick={onToggle}
        >
          <SeverityTag severity={finding.severity} />
          <span className="finding__title">{finding.title}</span>
          <span className="finding__count">
            {finding.occurrences > 1 ? `${finding.occurrences} occurrences` : ''}
          </span>
          <ChevronIcon className="finding__chevron" />
        </button>
      </Heading>
      {!open && first && (
        <p id={summaryId} className="finding__summary">
          <UntrustedText value={first} max={180} markNonAscii />
        </p>
      )}
      <div id={bodyId} className="finding__body" hidden={!open}>
        <ul className="instances">
          {finding.instances.map((instance, index) => (
            <li key={index} className="instance">
              <p>
                <UntrustedText value={instance.message} max={600} markNonAscii />
              </p>
              {instance.evidence.length > 0 && (
                <dl className="evidence">
                  {instance.evidence.map((item, itemIndex) => (
                    <div key={itemIndex} className="evidence__row">
                      <dt>{item.label}</dt>
                      <dd>
                        <UntrustedText value={item.value} max={400} markNonAscii />
                      </dd>
                    </div>
                  ))}
                </dl>
              )}
            </li>
          ))}
          {hidden > 0 && (
            <li className="muted">
              {hidden} more occurrence{hidden === 1 ? '' : 's'} not listed. See the Links or
              Attachments tab for all of them.
            </li>
          )}
        </ul>
        <div className="explain">
          <div>
            <h4>Why it may deserve investigation</h4>
            <p>{finding.rationale}</p>
          </div>
          <div>
            <h4>Common legitimate causes</h4>
            <p>{finding.benignCauses}</p>
          </div>
          <div>
            <h4>What to do</h4>
            <p>{finding.recommendation}</p>
          </div>
        </div>
        <p className="rule-id">
          Rule <code>{finding.ruleId}</code>
        </p>
      </div>
    </li>
  );
}

interface FindingListProps {
  findings: Finding[];
  headingLevel?: 3 | 4;
  emptyMessage: string;
  /** Show "Expand all / Collapse all". */
  bulkControls?: boolean;
  /** Controls shown on the same row as the bulk controls, kept when the list is empty. */
  toolbar?: ReactNode;
}

export function FindingList({
  findings,
  headingLevel = 3,
  emptyMessage,
  bulkControls = false,
  toolbar,
}: FindingListProps) {
  const [open, setOpen] = useState<ReadonlySet<string>>(() => new Set());
  const empty = findings.length === 0;
  const allOpen = findings.every((finding) => open.has(finding.ruleId));
  const toggle = (ruleId: string) => {
    const next = new Set(open);
    if (next.has(ruleId)) next.delete(ruleId);
    else next.add(ruleId);
    setOpen(next);
  };

  return (
    <>
      {(toolbar || bulkControls) && (
        <div className="list-controls">
          {toolbar}
          {bulkControls && !empty && (
            <button
              type="button"
              className="button button--quiet button--small list-controls__bulk"
              onClick={() =>
                setOpen(allOpen ? new Set() : new Set(findings.map((finding) => finding.ruleId)))
              }
            >
              {allOpen ? 'Collapse all' : 'Expand all'}
            </button>
          )}
        </div>
      )}
      {empty ? (
        <p className="empty">{emptyMessage}</p>
      ) : (
        <ul className="finding-list">
          {findings.map((finding) => (
            <FindingRow
              key={finding.ruleId}
              finding={finding}
              headingLevel={headingLevel}
              open={open.has(finding.ruleId)}
              onToggle={() => toggle(finding.ruleId)}
            />
          ))}
        </ul>
      )}
    </>
  );
}
