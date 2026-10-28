import { SEVERITY_LABELS } from '../../core/labels';
import type { Assessment, AssessmentLevel, Severity } from '../../core/types';
import { SeverityIcon } from './Icons';

const LEVEL_ICON: Record<AssessmentLevel, Severity> = {
  high: 'high',
  elevated: 'medium',
  low: 'low',
  none: 'info',
};

const COUNT_ORDER: readonly Severity[] = ['high', 'medium', 'low', 'info'];

interface VerdictProps {
  assessment: Assessment;
  onShowMethod: () => void;
}

export function Verdict({ assessment, onShowMethod }: VerdictProps) {
  return (
    <section className={`verdict verdict--${assessment.level}`} aria-labelledby="verdict-level">
      <div>
        <h2 id="verdict-level" className="verdict__level">
          <SeverityIcon severity={LEVEL_ICON[assessment.level]} />
          {assessment.label}
        </h2>
        <p className="verdict__summary">{assessment.summary}</p>
        <p className="verdict__reasons">
          Why: {assessment.reasons.join(' and ')}. A rule-based rating, not a probability.{' '}
          <button type="button" onClick={onShowMethod}>
            How this is decided
          </button>
        </p>
      </div>
      <dl className="verdict__counts" aria-label="Findings by severity">
        {COUNT_ORDER.map((severity) => (
          <div
            key={severity}
            className={`count sev--${severity}${assessment.counts[severity] === 0 ? ' count--zero' : ''}`}
          >
            <dt>
              <SeverityIcon severity={severity} />
              {SEVERITY_LABELS[severity]}
            </dt>
            <dd>{assessment.counts[severity]}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
