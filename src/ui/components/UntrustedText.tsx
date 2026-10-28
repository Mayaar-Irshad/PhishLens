import { Fragment, useMemo, useState, type ReactNode } from 'react';
import { codePointLabel, segmentHiddenCharacters } from '../../core/text';

interface UntrustedTextProps {
  value: string;
  /** Characters to show before offering "Show all". */
  max?: number;
  /**
   * Highlight every non-ASCII character. Use for domains, addresses and
   * findings about them, where a Cyrillic "a" (U+0430) posing as a Latin "a" matters.
   */
  markNonAscii?: boolean;
  className?: string;
}

const NON_ASCII_RUN = /[\u0080-\u{10FFFF}]+/gu;

function markRuns(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  for (const match of text.matchAll(NON_ASCII_RUN)) {
    if (match.index > last) out.push(text.slice(last, match.index));
    const run = match[0];
    out.push(
      <mark key={match.index} className="non-ascii" title={[...run].map(codePointLabel).join(' ')}>
        {run}
      </mark>,
    );
    last = match.index + run.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

/**
 * Renders a string that came from the message. React escapes it as text, and
 * hidden or direction-changing characters are replaced by visible markers, so
 * the value can neither inject markup nor visually reorder itself. The <bdi>
 * element isolates its direction from the surrounding interface.
 */
export function UntrustedText({ value, max, markNonAscii = false, className }: UntrustedTextProps) {
  const [expanded, setExpanded] = useState(false);
  const limit = max ?? Number.POSITIVE_INFINITY;
  const truncated = !expanded && value.length > limit;
  const shown = truncated ? value.slice(0, limit) : value;
  const segments = useMemo(() => segmentHiddenCharacters(shown), [shown]);

  return (
    <bdi className={className}>
      {segments.map((segment, index) =>
        segment.kind === 'text' ? (
          <Fragment key={index}>{markNonAscii ? markRuns(segment.value) : segment.value}</Fragment>
        ) : (
          <span key={index} className="hidden-char" title={`Hidden character ${segment.value}`}>
            <span className="visually-hidden">hidden character </span>
            {segment.value}
          </span>
        ),
      )}
      {truncated && (
        <>
          …
          <button type="button" className="show-more" onClick={() => setExpanded(true)}>
            Show all {value.length.toLocaleString()} characters
          </button>
        </>
      )}
    </bdi>
  );
}
