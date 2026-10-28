import type { Assessment, AssessmentLevel, Finding, Severity } from './types';

/**
 * The overall assessment is a documented threshold rule over finding
 * severities, not a probability. It is deliberately simple so anyone can
 * reproduce it by hand from the findings list.
 */
export const ASSESSMENT_THRESHOLDS: readonly {
  level: AssessmentLevel;
  label: string;
  rule: string;
}[] = [
  {
    level: 'high',
    label: 'High concern',
    rule: 'At least 1 high-severity finding, or at least 3 medium-severity findings.',
  },
  {
    level: 'elevated',
    label: 'Elevated concern',
    rule: 'At least 1 medium-severity finding, or at least 4 low-severity findings.',
  },
  { level: 'low', label: 'Some indicators', rule: 'At least 1 low-severity finding.' },
  {
    level: 'none',
    label: 'No indicators matched',
    rule: 'No high, medium or low findings. Informational notes are not counted.',
  },
];

const SUMMARIES: Record<AssessmentLevel, string> = {
  high: 'Several strong phishing indicators were found. Treat this message as suspicious and verify it through a trusted channel before acting on it.',
  elevated:
    'Indicators that often accompany phishing were found. Review the findings below before trusting the message.',
  low: 'Only weak indicators were found. These are common in legitimate mail too, so consider them in context.',
  none: "None of PhishLens's documented rules matched. This does not mean the message is safe: many phishing messages contain no detectable technical indicators, and PhishLens cannot verify senders or open links.",
};

export function assess(findings: Finding[]): Assessment {
  const counts: Record<Severity, number> = { high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;

  let level: AssessmentLevel;
  const reasons: string[] = [];
  const matched = (count: number, severity: string) =>
    `${count} ${severity}-severity rule${count === 1 ? '' : 's'} matched`;
  if (counts.high >= 1 || counts.medium >= 3) {
    level = 'high';
    if (counts.high >= 1)
      reasons.push(`${matched(counts.high, 'high')} (one is enough for High concern)`);
    if (counts.medium >= 3)
      reasons.push(`${matched(counts.medium, 'medium')} (three are enough for High concern)`);
  } else if (counts.medium >= 1 || counts.low >= 4) {
    level = 'elevated';
    if (counts.medium >= 1)
      reasons.push(`${matched(counts.medium, 'medium')} (one is enough for Elevated concern)`);
    if (counts.low >= 4)
      reasons.push(`${matched(counts.low, 'low')} (four are enough for Elevated concern)`);
  } else if (counts.low >= 1) {
    level = 'low';
    reasons.push(matched(counts.low, 'low'));
  } else {
    level = 'none';
    reasons.push('no high, medium or low rules matched');
  }

  const label =
    ASSESSMENT_THRESHOLDS.find((threshold) => threshold.level === level)?.label ?? level;
  return { level, label, summary: SUMMARIES[level], counts, reasons };
}
