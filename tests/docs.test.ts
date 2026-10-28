import { expect, it } from 'vitest';
import { ASSESSMENT_THRESHOLDS } from '../src/core/assessment';
import { RULE_LIST } from '../src/core/rules';
import type { FindingCategory } from '../src/core/types';

const CATEGORY_TITLES: Record<FindingCategory, string> = {
  input: 'Input',
  sender: 'Sender',
  header: 'Headers',
  authentication: 'Reported authentication',
  url: 'Links',
  html: 'HTML content',
  attachment: 'Attachments',
  content: 'Wording',
};

const cell = (value: string) => value.replace(/\|/gu, '\\|').replace(/\s+/gu, ' ');

/**
 * docs/RULES.md is generated from the rule catalogue so the documentation can
 * never drift from the code. Regenerate with `npm run docs:rules`.
 */
it('docs/RULES.md matches the rule catalogue', async () => {
  const lines = [
    '# PhishLens detection rules',
    '',
    '<!-- Generated from src/core/rules.ts by tests/docs.test.ts. Run `npm run docs:rules` to update. -->',
    '',
    'Every finding PhishLens reports comes from one of these rules. Severities are fixed per rule. Findings are heuristics: they describe characteristics worth investigating, not proof of phishing, and the absence of findings is not proof of safety.',
    '',
    '## How the overall assessment is decided',
    '',
    'Findings are counted by severity and the first matching threshold applies. Repeated matches of one rule (for example several insecure links) count once.',
    '',
    '| Assessment | Rule |',
    '| --- | --- |',
    ...ASSESSMENT_THRESHOLDS.map((threshold) => `| ${threshold.label} | ${cell(threshold.rule)} |`),
    '',
  ];
  for (const [category, title] of Object.entries(CATEGORY_TITLES)) {
    const rules = RULE_LIST.filter((rule) => rule.category === category);
    lines.push(
      `## ${title}`,
      '',
      '| Rule | Severity | Why it may matter | Common legitimate causes |',
      '| --- | --- | --- | --- |',
    );
    for (const rule of rules) {
      lines.push(
        `| **${cell(rule.title)}**<br>\`${rule.id}\` | ${rule.severity} | ${cell(rule.rationale)} | ${cell(rule.benignCauses)} |`,
      );
    }
    lines.push('');
  }
  await expect(lines.join('\n')).toMatchFileSnapshot('../docs/RULES.md');
});
