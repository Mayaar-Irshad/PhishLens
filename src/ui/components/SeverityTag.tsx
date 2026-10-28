import { SEVERITY_LABELS } from '../../core/labels';
import type { Severity } from '../../core/types';
import { SeverityIcon } from './Icons';

export function SeverityTag({ severity }: { severity: Severity }) {
  return (
    <span className={`sev sev--${severity}`}>
      <SeverityIcon severity={severity} />
      {SEVERITY_LABELS[severity]}
    </span>
  );
}
