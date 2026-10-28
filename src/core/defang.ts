/**
 * Defanging rewrites indicators so they cannot be clicked or auto-linked by
 * chat tools, ticket systems or mail clients, following common threat-intel
 * conventions: `https://evil.example/a` becomes `hxxps[://]evil[.]example/a`.
 */

function defangScheme(scheme: string): string {
  if (/^https?$/iu.test(scheme)) return scheme.replace(/tt/iu, (tt) => (tt === 'TT' ? 'XX' : 'xx'));
  if (/^ftps?$/iu.test(scheme)) return scheme.replace(/t/iu, (t) => (t === 'T' ? 'X' : 'x'));
  return scheme;
}

function defangAuthority(authority: string): string {
  return authority.replace(/\./gu, '[.]').replace(/@/gu, '[@]');
}

export function defangUrl(input: string): string {
  const value = input.trim();
  const hierarchical = /^([a-z][a-z0-9+.-]*):\/\/([^/?#\\]*)(.*)$/isu.exec(value);
  if (hierarchical) {
    const [, scheme = '', authority = '', rest = ''] = hierarchical;
    return `${defangScheme(scheme)}[://]${defangAuthority(authority)}${rest}`;
  }
  const opaque = /^([a-z][a-z0-9+.-]*):(.*)$/isu.exec(value);
  if (opaque) {
    const [, scheme = '', rest = ''] = opaque;
    return `${defangScheme(scheme)}[:]${defangAuthority(rest)}`;
  }
  // Scheme-less ("www.example.com/path"): defang the host part.
  const slash = value.search(/[/?#]/u);
  const host = slash === -1 ? value : value.slice(0, slash);
  const rest = slash === -1 ? '' : value.slice(slash);
  return `${defangAuthority(host)}${rest}`;
}

const URL_IN_TEXT = /\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s"'<>]{1,4096}|\bwww\.[^\s"'<>]{1,4096}/giu;

/** Defangs every URL-like substring in free text, such as visible link text. */
export function defangUrlsInText(text: string): string {
  return text.replace(URL_IN_TEXT, (match) => defangUrl(match));
}

export function defangEmail(address: string): string {
  return address.replace(/\./gu, '[.]').replace(/@/gu, '[@]');
}

export function defangHost(host: string): string {
  return host.replace(/\./gu, '[.]');
}

/** Reverses defanging. Used by tests to prove defanging is lossless. */
export function refangUrl(value: string): string {
  return value
    .replace(/\[:\/\/\]/gu, '://')
    .replace(/\[:\]/gu, ':')
    .replace(/\[\.\]/gu, '.')
    .replace(/\[@\]/gu, '@')
    .replace(/^hxxp/iu, (m) => (m.startsWith('H') ? 'HTTP' : 'http'))
    .replace(/^fxp/iu, (m) => (m.startsWith('F') ? 'FTP' : 'ftp'));
}
