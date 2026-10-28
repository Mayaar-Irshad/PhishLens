import type { Severity, UrlSource } from './types';

/** Display labels shared by the UI and the report. Kept dependency-free for the main bundle. */
const SOURCE_LABELS: Record<UrlSource['kind'], string> = {
  'html-link': 'HTML link',
  'html-form': 'HTML form',
  'html-image': 'HTML image',
  'html-frame': 'HTML frame',
  'html-resource': 'HTML resource',
  'html-refresh': 'Automatic redirect (meta refresh)',
  'html-script': 'Script redirect',
  'html-text': 'Text in HTML',
  'plain-text': 'Plain text',
  'pdf-link': 'PDF link',
  shortcut: 'Shortcut target',
};

/** Describes where a link was found, including the attachment name when relevant. */
export function describeSource(source: UrlSource): string {
  const base = SOURCE_LABELS[source.kind];
  return source.attachment === undefined
    ? `${base} in the message`
    : `${base} in attachment "${source.attachment}"`;
}

export const SEVERITY_LABELS: Record<Severity, string> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};
