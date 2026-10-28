import { RULES, type RuleId } from './rules';
import type { Evidence, Finding, Severity, UrlFlag } from './types';

export const SEVERITY_ORDER: readonly Severity[] = ['high', 'medium', 'low', 'info'];

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

/**
 * Collects rule matches. Repeated matches of the same rule are grouped into a
 * single finding with several instances, so one message with forty tracking
 * links produces one "insecure HTTP" finding rather than forty.
 */
export class FindingCollector {
  private readonly byRule = new Map<RuleId, Finding>();
  private readonly maxInstances: number;

  constructor(maxInstances: number) {
    this.maxInstances = maxInstances;
  }

  add(ruleId: RuleId, message: string, evidence: Evidence[] = []): void {
    const existing = this.byRule.get(ruleId);
    if (existing) {
      existing.occurrences += 1;
      if (existing.instances.length < this.maxInstances) {
        existing.instances.push({ message, evidence });
      }
      return;
    }
    const definition = RULES[ruleId];
    this.byRule.set(ruleId, {
      ruleId,
      category: definition.category,
      severity: definition.severity,
      title: definition.title,
      rationale: definition.rationale,
      benignCauses: definition.benignCauses,
      recommendation: definition.recommendation,
      occurrences: 1,
      instances: [{ message, evidence }],
    });
  }

  has(ruleId: RuleId): boolean {
    return this.byRule.has(ruleId);
  }

  list(): Finding[] {
    return [...this.byRule.values()].sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) || b.occurrences - a.occurrences,
    );
  }
}

export function flag(ruleId: RuleId, label: string): UrlFlag {
  return { ruleId, severity: RULES[ruleId].severity, label };
}
