import type { RuleId } from './rules';

/**
 * Data model for an analysis. Everything here is plain, structured-cloneable
 * data so it can cross the Web Worker boundary. Every string that originates
 * from the message is untrusted and must be rendered as text, never markup.
 */

export type Severity = 'high' | 'medium' | 'low' | 'info';

export type FindingCategory =
  'input' | 'sender' | 'header' | 'authentication' | 'url' | 'html' | 'attachment' | 'content';

export interface InputSource {
  kind: 'file' | 'paste' | 'sample' | 'attachment';
  /** File or sample name supplied by the user. Untrusted. */
  name?: string;
}

export interface Evidence {
  label: string;
  value: string;
}

export interface FindingInstance {
  message: string;
  evidence: Evidence[];
}

export interface Finding {
  ruleId: RuleId;
  category: FindingCategory;
  severity: Severity;
  title: string;
  rationale: string;
  benignCauses: string;
  recommendation: string;
  /** Total occurrences, which may exceed `instances.length` when capped. */
  occurrences: number;
  instances: FindingInstance[];
}

// ---------------------------------------------------------------- headers

export interface HeaderEntry {
  /** Position in the header block, 0 = topmost (most recently added). */
  index: number;
  /** Header name as written in the message. */
  name: string;
  /** Lowercase header name. */
  key: string;
  /** Unfolded raw value. */
  value: string;
}

export interface AddressInfo {
  name: string;
  address: string;
  /** Lowercase ASCII domain, or null when the address has no usable domain. */
  domain: string | null;
  /** Unicode rendering of the domain when it is an internationalized (punycode) name. */
  domainUnicode: string | null;
  registrableDomain: string | null;
  valid: boolean;
  /**
   * The domain exactly as written, when it differs from its canonical form for
   * reasons other than case: e.g. full-width letters that mail software maps
   * to ASCII ("ｐａｙｐａｌ.com" becomes "paypal.com").
   */
  domainWrittenAs: string | null;
  group?: string;
}

export interface HeaderField {
  key: string;
  label: string;
  /** Raw unfolded values, in header order (repeated headers keep every value). */
  values: string[];
  /** Values with RFC 2047 encoded-words decoded. */
  decoded: string[];
}

export interface ReceivedHop {
  /** 0 = topmost header (the most recent hop). */
  headerIndex: number;
  raw: string;
  from: string | null;
  by: string | null;
  with: string | null;
  ips: string[];
  dateRaw: string | null;
  dateIso: string | null;
}

export interface OriginIp {
  ip: string;
  /** Where the address was found. Every source can be forged by the sender. */
  source: 'received' | 'x-originating-ip';
  headerIndex: number;
}

export interface HeaderAnalysis {
  fields: HeaderField[];
  /** Less common headers useful for investigation (X-Mailer, X-Originating-IP...), when present. */
  notable: HeaderField[];
  /** Earliest public IP address recorded in the transit headers. Claimed, not verified. */
  originIp: OriginIp | null;
  from: AddressInfo[];
  replyTo: AddressInfo[];
  returnPath: AddressInfo[];
  sender: AddressInfo[];
  to: AddressInfo[];
  cc: AddressInfo[];
  subject: string | null;
  date: { raw: string | null; iso: string | null; valid: boolean };
  messageId: string | null;
  /** Received headers in header order (topmost first). */
  received: ReceivedHop[];
  all: HeaderEntry[];
  /** Count of each header name, lowercase. */
  counts: Record<string, number>;
}

// ---------------------------------------------------------- authentication

export type AuthStatus = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'error' | 'other';

export interface AuthProperty {
  key: string;
  value: string;
}

export interface AuthMethodResult {
  method: string;
  result: string;
  status: AuthStatus;
  reason: string | null;
  properties: AuthProperty[];
  comments: string[];
}

export interface AuthResultsHeader {
  headerIndex: number;
  /** `Authentication-Results` or `ARC-Authentication-Results`. */
  headerName: string;
  /** The server that claims to have performed the checks, or null if not stated. */
  authservId: string | null;
  arcInstance: number | null;
  results: AuthMethodResult[];
  raw: string;
  parseWarnings: string[];
}

export interface ReceivedSpf {
  headerIndex: number;
  result: string;
  status: AuthStatus;
  comment: string | null;
  properties: AuthProperty[];
  raw: string;
}

export interface DkimSignatureInfo {
  headerIndex: number;
  version: string | null;
  algorithm: string | null;
  domain: string | null;
  selector: string | null;
  identity: string | null;
  canonicalization: string | null;
  signedHeaders: string[];
  bodyLengthLimit: number | null;
  timestamp: string | null;
  expiration: string | null;
  hasSignature: boolean;
  hasBodyHash: boolean;
  /** Whether the d= organizational domain matches the From organizational domain. */
  alignedWithFrom: boolean | null;
  parseWarnings: string[];
}

export interface ReportedMethodSummary {
  method: 'spf' | 'dkim' | 'dmarc';
  result: string;
  status: AuthStatus;
  /** Key properties such as smtp.mailfrom or header.d. */
  detail: string | null;
  authservId: string | null;
  headerIndex: number;
}

export interface AuthenticationAnalysis {
  /** Always false: this browser-only tool never verifies SPF, DKIM or DMARC itself. */
  independentlyVerified: false;
  authenticationResults: AuthResultsHeader[];
  arcAuthenticationResults: AuthResultsHeader[];
  receivedSpf: ReceivedSpf[];
  dkimSignatures: DkimSignatureInfo[];
  /** Per-method results taken from the topmost header that reports each method. */
  reported: {
    spf: ReportedMethodSummary | null;
    dkim: ReportedMethodSummary | null;
    dmarc: ReportedMethodSummary | null;
  };
  authservIds: string[];
}

// -------------------------------------------------------------------- URLs

export type UrlSourceKind =
  | 'html-link'
  | 'html-form'
  | 'html-image'
  | 'html-frame'
  | 'html-resource'
  | 'html-refresh'
  | 'html-script'
  | 'html-text'
  | 'plain-text'
  | 'pdf-link'
  | 'shortcut';

export interface UrlSource {
  kind: UrlSourceKind;
  /** Visible text of the link, if any. Untrusted. */
  text?: string;
  /** Name of the attachment the link was found in, if not the message body. Untrusted. */
  attachment?: string;
}

export type UrlSchemeClass = 'web' | 'contact' | 'dangerous' | 'unusual' | 'unknown';

export interface UrlFlag {
  ruleId: RuleId;
  severity: Severity;
  label: string;
}

export interface UrlRecord {
  id: number;
  /** As found in the message (truncated if extremely long). Untrusted; never navigate to it. */
  raw: string;
  /** WHATWG-normalized form, or null when unparseable. */
  normalized: string | null;
  /** Defanged normalized form (or raw form when unparseable). */
  defanged: string;
  /** Defanged raw form, set only when it differs visibly from the normalized form. */
  rawDefanged: string | null;
  scheme: string | null;
  schemeClass: UrlSchemeClass;
  host: string | null;
  hostUnicode: string | null;
  registrableDomain: string | null;
  isIpHost: boolean;
  port: string | null;
  sources: UrlSource[];
  /** Destinations found inside the URL (security-gateway wrappers, redirect parameters). */
  embedded: {
    kind: 'security-wrapper' | 'redirect-parameter';
    parameter: string;
    url: string;
    defanged: string;
    registrableDomain: string | null;
  }[];
  flags: UrlFlag[];
}

// ------------------------------------------------------------- attachments

export type FileSignatureKind =
  | 'pe-executable'
  | 'elf-executable'
  | 'macho-or-java'
  | 'pdf'
  | 'zip'
  | 'ole'
  | 'rar'
  | '7z'
  | 'gzip'
  | 'cab'
  | 'iso'
  | 'vhdx'
  | 'lnk'
  | 'onenote'
  | 'png'
  | 'jpeg'
  | 'gif'
  | 'webp'
  | 'rtf'
  | 'html'
  | 'svg'
  | 'email';

export interface AttachmentRecord {
  index: number;
  /** Decoded filename as declared by the sender. Untrusted. */
  filename: string | null;
  extension: string | null;
  declaredType: string;
  disposition: string | null;
  sizeBytes: number;
  sha256: string | null;
  signature: { kind: FileSignatureKind; label: string } | null;
  encryptedArchive: boolean;
  inline: boolean;
  isEmbeddedMessage: boolean;
  /** What static inspection of the bytes found. Nothing is opened, rendered or executed. */
  contents: AttachmentContents;
  flags: UrlFlag[];
}

export interface ArchiveEntry {
  name: string;
  sizeBytes: number;
  encrypted: boolean;
  /** Short reason when the entry name is risky, e.g. "executable". */
  risk: string | null;
}

export interface AttachmentContents {
  /** Entries listed in a ZIP archive's directory (contents are never extracted). */
  archive: { entries: ArchiveEntry[]; totalEntries: number; truncated: boolean } | null;
  /** PDF dictionary keywords associated with active content, with counts. */
  pdfKeywords: { keyword: string; count: number }[] | null;
  /** Names of files embedded in a PDF, when it declares any. */
  pdfEmbeddedFiles: string[] | null;
  /** Static scan of an HTML or SVG attachment. */
  html: { forms: number; passwordFields: number; scripts: number; smuggling: boolean } | null;
  /** True when a VBA macro project was found in an Office document. */
  macros: boolean;
  /** Links extracted from the attachment and added to the Links tab. */
  links: number;
}

// -------------------------------------------------------------------- body

export interface HtmlSummary {
  present: boolean;
  truncated: boolean;
  /** Structural tags removed because they were nested beyond the parser depth limit. */
  flattenedTags: number;
  links: number;
  forms: { action: string | null; method: string; hasPassword: boolean; inputCount: number }[];
  scripts: number;
  frames: number;
  embeddedObjects: number;
  eventHandlerAttributes: number;
  metaRefresh: number;
  remoteImages: number;
  remoteResources: number;
  /** Distinct hosts of remote images and resources (capped). None were contacted. */
  remoteHosts: string[];
  baseHref: string | null;
  /** Characters of text hidden with CSS (display:none, zero font size...). */
  hiddenTextChars: number;
  /** Password inputs anywhere in the document, inside or outside forms. */
  passwordInputs: number;
  /** Images in the body, local (cid:) or remote. */
  images: number;
}

export interface BodySummary {
  hasText: boolean;
  hasHtml: boolean;
  textLength: number;
  htmlLength: number;
  html: HtmlSummary;
  /**
   * Bounded previews for reading the message as plain text. Kept in memory for
   * display only and never included in exported reports.
   */
  preview: { plainText: string; visibleText: string; htmlSource: string; truncated: boolean };
}

// --------------------------------------------------------------- assessment

export type AssessmentLevel = 'high' | 'elevated' | 'low' | 'none';

export interface Assessment {
  level: AssessmentLevel;
  label: string;
  summary: string;
  counts: Record<Severity, number>;
  /** Which documented thresholds produced this level. */
  reasons: string[];
}

// ------------------------------------------------------------------ result

export interface AnalysisMeta {
  toolVersion: string;
  analyzedAt: string;
  source: InputSource;
  sizeBytes: number;
  sha256: string | null;
  headersOnly: boolean;
  warnings: string[];
}

export interface AnalysisResult {
  meta: AnalysisMeta;
  headers: HeaderAnalysis;
  authentication: AuthenticationAnalysis;
  body: BodySummary;
  urls: UrlRecord[];
  urlsTruncated: boolean;
  attachments: AttachmentRecord[];
  attachmentsTruncated: boolean;
  findings: Finding[];
  assessment: Assessment;
}

export interface EmbeddedMessage {
  attachmentIndex: number;
  bytes: Uint8Array;
}

export interface AnalysisOutput {
  result: AnalysisResult;
  /** Raw bytes of attached email messages, kept in memory only so the user can analyze them next. */
  embeddedMessages: EmbeddedMessage[];
}

export type AnalysisStage =
  'validating' | 'parsing' | 'headers' | 'authentication' | 'attachments' | 'links' | 'assessing';
