import { ASSESSMENT_THRESHOLDS } from '../../core/assessment';
import { severityRank } from '../../core/findings';
import { RULE_LIST, type RuleDefinition } from '../../core/rules';
import type { FindingCategory } from '../../core/types';
import { SeverityTag } from './SeverityTag';

const CATEGORY_LABELS: Record<FindingCategory, string> = {
  input: 'Input',
  sender: 'Sender',
  header: 'Headers',
  authentication: 'Reported authentication',
  url: 'Links',
  html: 'HTML content',
  attachment: 'Attachments',
  content: 'Wording',
};

function RuleTable({
  rules,
  matchedRuleIds,
}: {
  rules: readonly RuleDefinition[];
  matchedRuleIds?: ReadonlySet<string>;
}) {
  return (
    <div className="table-wrap">
      <table className="data-table data-table--wide">
        <thead>
          <tr>
            <th scope="col">Severity</th>
            <th scope="col">Rule</th>
            <th scope="col">Why it may matter</th>
            <th scope="col">Common legitimate causes</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((rule) => (
            <tr key={rule.id}>
              <td>
                <SeverityTag severity={rule.severity} />
              </td>
              <th scope="row">
                {rule.title}
                {matchedRuleIds?.has(rule.id) && (
                  <span className="matched-badge">
                    <span aria-hidden="true">{'\u2713'} </span>Matched
                  </span>
                )}
                <br />
                <code className="rule-id">{rule.id}</code>
              </th>
              <td>{rule.rationale}</td>
              <td>{rule.benignCauses}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function MethodTab({ matchedRuleIds }: { matchedRuleIds: ReadonlySet<string> }) {
  const categories = Object.keys(CATEGORY_LABELS) as FindingCategory[];
  const matched = RULE_LIST.filter((rule) => matchedRuleIds.has(rule.id)).sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity),
  );
  return (
    <>
      <section className="section" aria-labelledby="method-assessment">
        <h2 id="method-assessment" className="section-title" tabIndex={-1}>
          How the assessment is decided
        </h2>
        <p className="panel-intro">
          The assessment counts findings by severity and applies the first threshold that matches.
          It is a transparent rule, not a calculated probability of phishing, and it never declares
          a message safe.
        </p>
        <div className="table-wrap">
          <table className="data-table data-table--stack">
            <thead>
              <tr>
                <th scope="col">Assessment</th>
                <th scope="col">Rule</th>
              </tr>
            </thead>
            <tbody>
              {ASSESSMENT_THRESHOLDS.map((threshold) => (
                <tr key={threshold.level}>
                  <th scope="row">{threshold.label}</th>
                  <td>{threshold.rule}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="section" aria-labelledby="method-rules">
        <h2 id="method-rules" className="section-title">
          Rules that matched this message
        </h2>
        {matched.length === 0 ? (
          <p className="empty">No rules matched this message.</p>
        ) : (
          <RuleTable rules={matched} />
        )}
        <h3 className="steps-title">Full rule catalogue</h3>
        <p className="panel-intro">
          Every rule PhishLens can apply, with its fixed severity, grouped by what it examines.
        </p>
        {categories.map((category) => {
          const rules = RULE_LIST.filter((rule) => rule.category === category);
          return (
            <details key={category} className="disclosure rule-group">
              <summary>
                {CATEGORY_LABELS[category]} ({rules.length} rules
                {rules.some((rule) => matchedRuleIds.has(rule.id))
                  ? `, ${rules.filter((rule) => matchedRuleIds.has(rule.id)).length} matched`
                  : ''}
                )
              </summary>
              <RuleTable rules={rules} matchedRuleIds={matchedRuleIds} />
            </details>
          );
        })}
      </section>

      <section className="section" aria-labelledby="method-limits">
        <h2 id="method-limits" className="section-title">
          What PhishLens cannot tell you
        </h2>
        <ul className="steps">
          <li>
            <span>
              Whether SPF, DKIM or DMARC actually pass. It shows what the headers report, which can
              be forged.
            </span>
          </li>
          <li>
            <span>
              Where a link really leads. Links are never opened, redirects are never followed, and
              domains are never looked up.
            </span>
          </li>
          <li>
            <span>
              Whether an attachment is malicious. Only names, declared types, leading bytes and
              hashes are examined.
            </span>
          </li>
          <li>
            <span>
              Whether the sender is who they claim to be. Brand and domain lists are small, static
              and incomplete.
            </span>
          </li>
        </ul>
      </section>
    </>
  );
}
