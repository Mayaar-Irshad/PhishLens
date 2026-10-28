import { parse, type DefaultTreeAdapterTypes } from 'parse5';
import { collapseWhitespace } from './text';
import type { HtmlSummary, UrlSourceKind } from './types';

type Node = DefaultTreeAdapterTypes.Node;
type Element = DefaultTreeAdapterTypes.Element;

/**
 * Static analysis of an HTML body.
 *
 * parse5 is a spec-compliant HTML parser written in plain JavaScript. It builds
 * an inert tree of plain objects: there is no DOM, no rendering, no script
 * execution and no resource loading, and this module runs inside a Web
 * Worker with no network code. The original HTML is never rendered.
 */

export interface HtmlUrlOccurrence {
  kind: UrlSourceKind;
  url: string;
  text?: string;
}

export interface HtmlScan {
  occurrences: HtmlUrlOccurrence[];
  /** All visible text, for content heuristics. */
  visibleText: string;
  /** Visible text outside links, scanned for unlinked URLs (clients do not linkify inside anchors). */
  unlinkedText: string;
  /** Concatenated inline script source (bounded), inspected as text and never run. */
  scriptText: string;
  summary: HtmlSummary;
}

const MAX_SCRIPT_TEXT = 512 * 1024;
/** Inline styles that hide content from the reader. */
const CSS_HIDDEN =
  /display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?\s*(?:;|!|$)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|!|$)|max-height\s*:\s*0(?:px)?\s*(?:;|!|$)/iu;
/** Script statements that navigate to a literal URL. */
const SCRIPT_REDIRECT =
  /\blocation(?:\.href)?\s{0,8}=\s{0,8}(['"`])([^'"`\s]{4,2048})\1|\blocation\.(?:replace|assign)\(\s{0,8}(['"`])([^'"`\s]{4,2048})\3/gu;
/** The same navigation with the URL hidden in base64: `location.href = atob("aHR0cHM6Ly8...")`. */
const SCRIPT_REDIRECT_ATOB =
  /\blocation(?:\.href)?\s{0,8}(?:=|\.(?:replace|assign)\()\s{0,8}(?:window\.)?atob\(\s{0,8}(['"`])([A-Za-z0-9+/=]{8,4096})\1\s{0,8}\)/gu;

function decodeBase64(value: string): string | null {
  try {
    return atob(value);
  } catch {
    return null;
  }
}

/** Literal URLs a script would navigate to, e.g. `window.location.href = "https://..."`. */
export function scriptRedirectTargets(script: string): string[] {
  const out: string[] = [];
  for (const match of script.matchAll(SCRIPT_REDIRECT)) {
    const url = match[2] ?? match[4];
    if (url) out.push(url);
    if (out.length >= 20) return out;
  }
  for (const match of script.matchAll(SCRIPT_REDIRECT_ATOB)) {
    const decoded = decodeBase64(match[2] ?? '');
    if (decoded && /^(?:https?:)?\/\//iu.test(decoded)) out.push(decoded);
    if (out.length >= 20) break;
  }
  return out;
}

/** Script types that browsers execute; data blocks such as JSON-LD are not active content. */
function isExecutableScript(type: string | null): boolean {
  if (type === null) return true;
  const value = type.trim().toLowerCase();
  return (
    value === '' ||
    value === 'module' ||
    /^(?:text|application)\/(?:x-)?(?:java|ecma)script$/u.test(value)
  );
}

/** Outlook renders `<!--[if mso]>...<![endif]-->` blocks that other clients ignore. */
const CONDITIONAL_COMMENT = /^\[if [^\]]{1,64}\]>/u;

const MAX_LINK_TEXT = 300;
const MAX_REMOTE_HOSTS = 20;
const NON_VISIBLE = new Set([
  'script',
  'style',
  'template',
  'head',
  'title',
  'noembed',
  'noframes',
]);
// Bounded quantifiers and no '(' in the URL class keep this linear on hostile CSS.
const CSS_URL = /url\(\s{0,16}(['"]?)([^'"()\s]{1,2048})\1\s{0,16}\)/giu;

function isElement(node: Node): node is Element {
  return 'tagName' in node;
}

/** Appends without spreading: spreading 100k+ children as arguments overflows the call stack. */
function pushAll<T>(target: T[], items: readonly T[]): void {
  for (const item of items) target.push(item);
}

function childrenOf(node: Node): Node[] {
  const children: Node[] = 'childNodes' in node ? [...node.childNodes] : [];
  if (isElement(node) && node.tagName === 'template' && 'content' in node) {
    pushAll(children, node.content.childNodes);
  }
  return children;
}

function attr(element: Element, name: string): string | null {
  return element.attrs.find((attribute) => attribute.name === name)?.value ?? null;
}

/** Visible text inside an element, bounded, including image alt text. */
function textWithin(root: Element): string {
  let text = '';
  const stack: Node[] = [...childrenOf(root)].reverse();
  while (stack.length > 0 && text.length < MAX_LINK_TEXT * 2) {
    const node = stack.pop();
    if (!node) break;
    if (node.nodeName === '#text' && 'value' in node) {
      text += ` ${node.value.slice(0, MAX_LINK_TEXT * 2)}`;
    } else if (isElement(node)) {
      if (NON_VISIBLE.has(node.tagName)) continue;
      if (node.tagName === 'img') {
        const alt = attr(node, 'alt');
        if (alt) text += ` ${alt.slice(0, MAX_LINK_TEXT * 2)}`;
      }
      pushAll(stack, childrenOf(node).reverse());
    }
  }
  const collapsed = collapseWhitespace(text);
  return collapsed.length > MAX_LINK_TEXT ? `${collapsed.slice(0, MAX_LINK_TEXT)}…` : collapsed;
}

function isRemote(url: string): boolean {
  return /^\s*(?:https?:)?\/\//iu.test(url);
}

function hostOf(url: string): string | null {
  try {
    return (
      new URL(url.trim().startsWith('//') ? `https:${url.trim()}` : url.trim()).hostname || null
    );
  } catch {
    return null;
  }
}

/** Extracts the URL from a meta refresh value such as "0; url='https://example.com'". */
export function refreshTarget(content: string): string | null {
  const match = /url\s*=\s*(['"]?)([^'"]+)\1/iu.exec(content);
  return match?.[2]?.trim() ?? null;
}

function srcsetUrls(srcset: string): string[] {
  return srcset
    .split(',')
    .map((candidate) => candidate.trim().split(/\s+/u)[0] ?? '')
    .filter(Boolean);
}

/** Browsers stop nesting at a similar depth (Blink: 512) and attach deeper elements to the last allowed ancestor. */
export const MAX_HTML_DEPTH = 512;

const VOID_ELEMENTS = new Set([
  'area',
  'base',
  'br',
  'col',
  'embed',
  'hr',
  'img',
  'input',
  'link',
  'meta',
  'source',
  'track',
  'wbr',
]);
/** Elements whose attributes the analysis reads; they are never dropped while flattening. */
const ANALYSED_ELEMENTS = new Set([
  'a',
  'area',
  'form',
  'input',
  'button',
  'img',
  'iframe',
  'frame',
  'meta',
  'base',
  'link',
  'script',
  'style',
  'object',
  'embed',
  'applet',
  'video',
  'audio',
  'source',
  'track',
  'table',
  'td',
  'body',
]);
// [^<>] stops at the next tag boundary, keeping the scan linear on unterminated tags.
const TAG = /<(\/?)([a-zA-Z][a-zA-Z0-9-]{0,63})\b[^<>]{0,4096}?(\/?)>/gu;

/**
 * parse5 slows down quadratically with nesting depth, so deeply nested hostile
 * markup could stall analysis. This linear pre-pass removes structural tags
 * nested beyond MAX_HTML_DEPTH, keeping all text and every element whose
 * attributes are analysed, so nothing can be hidden by nesting it deeply.
 * The depth is approximate (it ignores parser error recovery), which only
 * matters for markup far deeper than any real email.
 */
export function flattenExcessiveNesting(
  html: string,
  maxDepth = MAX_HTML_DEPTH,
): { html: string; removed: number } {
  let depth = 0;
  let excess = 0;
  let removed = 0;
  const output = html.replace(TAG, (tag, slash: string, rawName: string, selfClosing: string) => {
    const name = rawName.toLowerCase();
    if (VOID_ELEMENTS.has(name) || selfClosing) return tag;
    if (slash) {
      if (excess > 0 && !ANALYSED_ELEMENTS.has(name)) {
        excess -= 1;
        removed += 1;
        return '';
      }
      depth = Math.max(0, depth - 1);
      return tag;
    }
    if (depth >= maxDepth && !ANALYSED_ELEMENTS.has(name)) {
      excess += 1;
      removed += 1;
      return '';
    }
    depth += 1;
    return tag;
  });
  return { html: output, removed };
}

export function scanHtml(
  input: string,
  maxChars: number,
  maxOccurrences: number,
  allowConditional = true,
): HtmlScan {
  const truncated = input.length > maxChars;
  const { html, removed } = flattenExcessiveNesting(truncated ? input.slice(0, maxChars) : input);
  // scriptingEnabled: false parses <noscript> content as markup, which is how
  // a mail client (which never runs scripts) would display it.
  const document = parse(html, { scriptingEnabled: false });

  const occurrences: HtmlUrlOccurrence[] = [];
  const textParts: string[] = [];
  const unlinkedParts: string[] = [];
  const scriptParts: string[] = [];
  let scriptLength = 0;
  let textLength = 0;
  const remoteHosts = new Set<string>();
  const summary: HtmlSummary = {
    present: true,
    truncated,
    flattenedTags: removed,
    links: 0,
    forms: [],
    scripts: 0,
    frames: 0,
    embeddedObjects: 0,
    eventHandlerAttributes: 0,
    metaRefresh: 0,
    remoteImages: 0,
    remoteResources: 0,
    remoteHosts: [],
    baseHref: null,
    hiddenTextChars: 0,
    passwordInputs: 0,
    images: 0,
  };

  const addUrl = (kind: UrlSourceKind, url: string | null, text?: string) => {
    if (!url?.trim() || occurrences.length >= maxOccurrences) return;
    occurrences.push(text ? { kind, url, text } : { kind, url });
  };
  const addRemote = (url: string | null, kind: 'image' | 'resource') => {
    if (!url || !isRemote(url)) return;
    if (kind === 'image') summary.remoteImages += 1;
    else summary.remoteResources += 1;
    const host = hostOf(url);
    if (host && remoteHosts.size < MAX_REMOTE_HOSTS) remoteHosts.add(host);
  };
  const addCssUrls = (css: string) => {
    for (const match of css.matchAll(CSS_URL)) addRemote(match[2] ?? null, 'resource');
  };

  // Iterative walk: deeply nested hostile HTML cannot overflow the call stack.
  // `hidden`: inside script/style/head; `cssHidden`: hidden from the reader by inline CSS.
  const stack: { node: Node; hidden: boolean; cssHidden: boolean; inLink: boolean }[] = [
    { node: document, hidden: false, cssHidden: false, inLink: false },
  ];
  while (stack.length > 0) {
    const entry = stack.pop();
    if (!entry) break;
    const { node, hidden, cssHidden, inLink } = entry;

    if (node.nodeName === '#text' && 'value' in node) {
      if (hidden) continue;
      if (cssHidden) {
        summary.hiddenTextChars += node.value.replace(/\s+/gu, '').length;
      } else if (textLength < maxChars) {
        textParts.push(node.value);
        if (!inLink) unlinkedParts.push(node.value);
        textLength += node.value.length + 1;
      }
      continue;
    }
    if (node.nodeName === '#comment' && 'data' in node) {
      // Links inside Outlook conditional comments are shown by Outlook desktop.
      if (allowConditional && CONDITIONAL_COMMENT.test(node.data)) {
        const inner = scanHtml(node.data, maxChars, maxOccurrences - occurrences.length, false);
        for (const occurrence of inner.occurrences)
          addUrl(occurrence.kind, occurrence.url, occurrence.text);
        summary.passwordInputs += inner.summary.passwordInputs;
      }
      continue;
    }
    if (!isElement(node)) {
      for (const child of childrenOf(node).reverse()) {
        stack.push({ node: child, hidden, cssHidden, inLink });
      }
      continue;
    }

    const tag = node.tagName;
    for (const attribute of node.attrs) {
      if (/^on[a-z]/iu.test(attribute.name)) {
        summary.eventHandlerAttributes += 1;
        for (const target of scriptRedirectTargets(attribute.value.slice(0, 8192))) {
          addUrl('html-script', target);
        }
      }
      if (attribute.name === 'style') addCssUrls(attribute.value);
      if (attribute.name === 'background') addRemote(attribute.value, 'image');
    }

    switch (tag) {
      case 'a':
      case 'area': {
        const href = attr(node, 'href');
        if (href) {
          summary.links += 1;
          const text =
            tag === 'area' ? (attr(node, 'alt') ?? '').slice(0, MAX_LINK_TEXT) : textWithin(node);
          addUrl('html-link', href, text || undefined);
        }
        break;
      }
      case 'form': {
        const inputs: Element[] = [];
        const formStack: Node[] = [...childrenOf(node)];
        while (formStack.length > 0) {
          const child = formStack.pop();
          if (!child) break;
          if (isElement(child)) {
            if (['input', 'select', 'textarea', 'button'].includes(child.tagName))
              inputs.push(child);
            pushAll(formStack, childrenOf(child));
          }
        }
        const action = attr(node, 'action');
        summary.forms.push({
          action,
          method: (attr(node, 'method') ?? 'get').toLowerCase(),
          hasPassword: inputs.some((input) => attr(input, 'type')?.toLowerCase() === 'password'),
          inputCount: inputs.filter((input) => input.tagName !== 'button').length,
        });
        addUrl('html-form', action);
        break;
      }
      case 'input':
      case 'button':
        if (tag === 'input' && attr(node, 'type')?.toLowerCase() === 'password')
          summary.passwordInputs += 1;
        addUrl('html-form', attr(node, 'formaction'));
        break;
      case 'img':
        summary.images += 1;
        addRemote(attr(node, 'src'), 'image');
        for (const url of srcsetUrls(attr(node, 'srcset') ?? '')) addRemote(url, 'image');
        break;
      case 'iframe':
      case 'frame':
        summary.frames += 1;
        addUrl('html-frame', attr(node, 'src'));
        break;
      case 'script': {
        if (!isExecutableScript(attr(node, 'type'))) break;
        summary.scripts += 1;
        addRemote(attr(node, 'src'), 'resource');
        for (const child of node.childNodes) {
          if (child.nodeName !== '#text' || !('value' in child) || scriptLength >= MAX_SCRIPT_TEXT)
            continue;
          const source = child.value.slice(0, MAX_SCRIPT_TEXT - scriptLength);
          scriptParts.push(source);
          scriptLength += source.length;
          for (const target of scriptRedirectTargets(source)) addUrl('html-script', target);
        }
        break;
      }
      case 'object':
      case 'embed':
      case 'applet':
        summary.embeddedObjects += 1;
        addRemote(attr(node, 'data') ?? attr(node, 'src'), 'resource');
        break;
      case 'link':
        addRemote(attr(node, 'href'), 'resource');
        break;
      case 'video':
      case 'audio':
      case 'source':
      case 'track':
        addRemote(attr(node, 'src'), 'resource');
        addRemote(attr(node, 'poster'), 'image');
        break;
      case 'meta': {
        if (attr(node, 'http-equiv')?.toLowerCase() === 'refresh') {
          summary.metaRefresh += 1;
          addUrl('html-refresh', refreshTarget(attr(node, 'content') ?? ''));
        }
        break;
      }
      case 'base':
        summary.baseHref ??= attr(node, 'href');
        break;
      case 'style':
        for (const child of node.childNodes) {
          if (child.nodeName === '#text' && 'value' in child) addCssUrls(child.value);
        }
        break;
      default:
        break;
    }

    const childHidden = hidden || NON_VISIBLE.has(tag);
    const childCssHidden =
      cssHidden || attr(node, 'hidden') !== null || CSS_HIDDEN.test(attr(node, 'style') ?? '');
    const childInLink = inLink || tag === 'a';
    for (const child of childrenOf(node).reverse()) {
      stack.push({
        node: child,
        hidden: childHidden,
        cssHidden: childCssHidden,
        inLink: childInLink,
      });
    }
  }

  summary.remoteHosts = [...remoteHosts];
  return {
    occurrences,
    visibleText: textParts.join(' '),
    unlinkedText: unlinkedParts.join(' '),
    scriptText: scriptParts.join('\n'),
    summary,
  };
}
