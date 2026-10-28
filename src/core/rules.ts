import type { FindingCategory, Severity } from './types';

export interface RuleDefinition {
  id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  /** Why this may deserve investigation. */
  rationale: string;
  /** Common legitimate explanations, stated so users do not over-read a match. */
  benignCauses: string;
  recommendation: string;
}

const VERIFY_SENDER =
  'Confirm the request through a channel you already trust (a known phone number, the official website typed by hand, or your security team) rather than replying or using links in the message.';
const DO_NOT_OPEN_LINKS =
  'Do not open the link. If you need to examine it, use an isolated analysis environment or ask your security team.';
const DO_NOT_OPEN_ATTACHMENT =
  'Do not open the attachment. If it must be examined, submit it to your security team or analyse it in an isolated sandbox. The SHA-256 hash can be looked up manually in threat-intelligence services.';
const REPORTED_ONLY =
  'This is a result written inside the message, not a check PhishLens performed. Treat it as a claim.';

function rule(definition: RuleDefinition): RuleDefinition {
  return Object.freeze(definition);
}

export const RULES = {
  // ------------------------------------------------------------- input
  INPUT_HEADERS_ONLY: rule({
    id: 'INPUT_HEADERS_ONLY',
    category: 'input',
    severity: 'info',
    title: 'Only headers were provided',
    rationale:
      'No message body was found, so links, HTML content and attachments could not be analysed.',
    benignCauses: 'Expected when you paste only the header block.',
    recommendation: 'Analyse the complete .eml file if you need link and attachment checks.',
  }),
  INPUT_MALFORMED_HEADER_LINES: rule({
    id: 'INPUT_MALFORMED_HEADER_LINES',
    category: 'input',
    severity: 'low',
    title: 'Malformed lines in the header block',
    rationale:
      'Some lines in the header section are neither valid header fields nor folded continuations. Malformed headers can confuse mail clients and filters, and are sometimes used to hide content.',
    benignCauses:
      'Copy-and-paste from a mail client often breaks header formatting. Some poorly written mail software also emits invalid headers.',
    recommendation:
      'If you pasted the headers, try exporting the original message as an .eml file instead.',
  }),

  // ------------------------------------------------------------ sender
  SENDER_FROM_MISSING: rule({
    id: 'SENDER_FROM_MISSING',
    category: 'sender',
    severity: 'medium',
    title: 'No From header',
    rationale:
      'Every message is required to have a From header. A missing From header is unusual and prevents sender checks.',
    benignCauses:
      'Incomplete copy-and-paste of headers, or an automated system with a broken mailer.',
    recommendation: 'Make sure the full header block was provided.',
  }),
  SENDER_MULTIPLE_FROM_HEADERS: rule({
    id: 'SENDER_MULTIPLE_FROM_HEADERS',
    category: 'sender',
    severity: 'medium',
    title: 'More than one From header',
    rationale:
      'RFC 5322 allows exactly one From header. Duplicates are a known technique for showing one sender to the user while filters evaluate another.',
    benignCauses: 'Very rare in legitimate mail; occasionally caused by buggy forwarding software.',
    recommendation: VERIFY_SENDER,
  }),
  SENDER_MULTIPLE_FROM_ADDRESSES: rule({
    id: 'SENDER_MULTIPLE_FROM_ADDRESSES',
    category: 'sender',
    severity: 'high',
    title: 'From header lists more than one address',
    rationale:
      'A single From header contains several mailboxes. Mail clients usually display only the first, while DMARC and filters may evaluate another, a known way to show a trusted sender while passing authentication for an attacker-controlled domain.',
    benignCauses:
      'Messages with several genuine authors are allowed by RFC 5322 but are extremely rare in practice.',
    recommendation: VERIFY_SENDER,
  }),
  SENDER_INVALID_ADDRESS: rule({
    id: 'SENDER_INVALID_ADDRESS',
    category: 'sender',
    severity: 'medium',
    title: 'From address could not be parsed',
    rationale:
      'The From header does not contain a well-formed address with a domain, so the sender cannot be identified reliably.',
    benignCauses: 'Some automated or internal systems send with malformed From headers.',
    recommendation: VERIFY_SENDER,
  }),
  SENDER_DISPLAY_NAME_ADDRESS: rule({
    id: 'SENDER_DISPLAY_NAME_ADDRESS',
    category: 'sender',
    severity: 'medium',
    title: 'Display name contains a different email address',
    rationale:
      'The sender name shows an email address that differs from the actual sending address. Many mail apps display only the name, so this can make the message appear to come from someone else.',
    benignCauses:
      'Some mailing lists and forwarding services rewrite the From header and keep the original address in the name.',
    recommendation: VERIFY_SENDER,
  }),
  SENDER_DISPLAY_NAME_BRAND: rule({
    id: 'SENDER_DISPLAY_NAME_BRAND',
    category: 'sender',
    severity: 'medium',
    title: 'Sender name mentions a brand that does not match the sending domain',
    rationale:
      'The display name refers to a well-known organisation, but the address is not on a domain PhishLens associates with that organisation. Impersonating trusted brands is the most common phishing technique.',
    benignCauses:
      'Organisations use many domains and third-party senders (marketing platforms, resellers, partners). The brand domain list is not exhaustive.',
    recommendation: VERIFY_SENDER,
  }),
  SENDER_FREEMAIL_BRAND: rule({
    id: 'SENDER_FREEMAIL_BRAND',
    category: 'sender',
    severity: 'high',
    title: 'Brand name sent from a free webmail account',
    rationale:
      'The display name refers to a well-known organisation, but the message comes from a free consumer mailbox (such as Gmail or Outlook.com). Large organisations do not normally send official messages from free accounts.',
    benignCauses:
      'An individual may legitimately mention a company in their own name, for example "Alex (Contoso fan club)".',
    recommendation: VERIFY_SENDER,
  }),
  SENDER_LOOKALIKE_DOMAIN: rule({
    id: 'SENDER_LOOKALIKE_DOMAIN',
    category: 'sender',
    severity: 'high',
    title: 'Sender or reply domain resembles a well-known brand',
    rationale:
      'The sending or reply-to domain closely resembles a known brand domain (character substitution, a typo, or visually confusable letters), a pattern commonly used for impersonation.',
    benignCauses:
      'Coincidental similarity with an unrelated, legitimate business name is possible.',
    recommendation: VERIFY_SENDER,
  }),
  SENDER_BRAND_IN_DOMAIN: rule({
    id: 'SENDER_BRAND_IN_DOMAIN',
    category: 'sender',
    severity: 'medium',
    title: 'Sender domain contains a brand name it may not belong to',
    rationale:
      'The sending domain embeds a well-known brand name (for example "brand-support.example") without being one of the domains PhishLens associates with that brand.',
    benignCauses:
      'Brands sometimes register campaign domains, and partners or fan sites can include brand names.',
    recommendation: VERIFY_SENDER,
  }),
  SENDER_IDN_DOMAIN: rule({
    id: 'SENDER_IDN_DOMAIN',
    category: 'sender',
    severity: 'low',
    title: 'Sender uses an internationalized domain name',
    rationale:
      'The sending domain contains non-ASCII characters (shown as punycode, "xn--"). Internationalized names are legitimate, but can also imitate familiar domains with look-alike letters.',
    benignCauses: 'Common and legitimate for organisations using non-Latin scripts.',
    recommendation:
      'Compare the Unicode and punycode forms of the domain with the organisation you expect.',
  }),
  SENDER_MIXED_SCRIPT_DOMAIN: rule({
    id: 'SENDER_MIXED_SCRIPT_DOMAIN',
    category: 'sender',
    severity: 'high',
    title: 'Sender domain mixes look-alike alphabets',
    rationale:
      'A label in the sending domain mixes Latin with Cyrillic, Greek or Armenian letters. Browsers treat this as a homograph risk, because such names can be visually indistinguishable from familiar domains.',
    benignCauses: 'Extremely rare in legitimate domain names.',
    recommendation: VERIFY_SENDER,
  }),
  SENDER_COUSIN_DOMAIN: rule({
    id: 'SENDER_COUSIN_DOMAIN',
    category: 'sender',
    severity: 'high',
    title: 'Sender or reply domain is a near-copy of a familiar domain',
    rationale:
      'A sender or Reply-To domain differs from the recipient\'s own domain, or from the From domain, by one character or a look-alike substitution (for example "acrne-corp" for "acme-corp"). Business email compromise uses such cousin domains to impersonate colleagues and suppliers.',
    benignCauses: 'Unrelated organisations occasionally have very similar names.',
    recommendation: VERIFY_SENDER,
  }),
  SENDER_TENANT_DOMAIN: rule({
    id: 'SENDER_TENANT_DOMAIN',
    category: 'sender',
    severity: 'low',
    title: "Sent from a cloud mail tenant's default domain",
    rationale:
      'The sender uses a default tenant domain such as "contoso.onmicrosoft.com". Anyone can create one, and attackers use them to send mail through reputable infrastructure that looks official.',
    benignCauses:
      'Organisations that have not configured their own domain, and some system notifications.',
    recommendation: VERIFY_SENDER,
  }),
  SENDER_REPLY_TO_DIFFERENT_DOMAIN: rule({
    id: 'SENDER_REPLY_TO_DIFFERENT_DOMAIN',
    category: 'sender',
    severity: 'low',
    title: 'Replies go to a different domain than the sender',
    rationale:
      'The Reply-To header directs replies to a different organisational domain than the From address. Attackers use this to receive replies while showing a trusted sender.',
    benignCauses:
      'Very common for newsletters, ticketing systems, recruiters and marketing platforms that collect replies on another domain.',
    recommendation:
      'Before replying with any sensitive information, check where your reply would actually go.',
  }),
  SENDER_REPLY_TO_FREEMAIL: rule({
    id: 'SENDER_REPLY_TO_FREEMAIL',
    category: 'sender',
    severity: 'medium',
    title: 'Replies go to a free webmail account',
    rationale:
      'Replies are directed to a free consumer mailbox that differs from the sender. This is a hallmark of business email compromise and advance-fee fraud.',
    benignCauses: 'Small businesses and individuals sometimes use personal mailboxes for replies.',
    recommendation: VERIFY_SENDER,
  }),
  SENDER_RETURN_PATH_DIFFERENT_DOMAIN: rule({
    id: 'SENDER_RETURN_PATH_DIFFERENT_DOMAIN',
    category: 'sender',
    severity: 'info',
    title: 'Return-Path domain differs from the From domain',
    rationale:
      'The envelope sender (Return-Path), which receives bounces and is what SPF checks, belongs to a different organisational domain than the visible From address.',
    benignCauses:
      'Extremely common: bulk mail services (for example Amazon SES, SendGrid, Mailchimp) use their own bounce domains.',
    recommendation:
      'Consider it alongside the reported DMARC result, which accounts for alignment.',
  }),
  SENDER_HEADER_DIFFERS: rule({
    id: 'SENDER_HEADER_DIFFERS',
    category: 'sender',
    severity: 'info',
    title: 'Sender header differs from From',
    rationale:
      'A Sender header names a different organisational domain than From, meaning the message was submitted on someone else\'s behalf. Some clients show "on behalf of".',
    benignCauses: 'Delegated mailboxes, mailing lists and calendar systems commonly do this.',
    recommendation: 'Check whether the on-behalf-of relationship makes sense for this message.',
  }),

  // ----------------------------------------------------------- headers
  HEADER_MESSAGE_ID_MISSING: rule({
    id: 'HEADER_MESSAGE_ID_MISSING',
    category: 'header',
    severity: 'low',
    title: 'No Message-ID header',
    rationale:
      'Almost all legitimate mail servers add a Message-ID. Its absence can indicate custom bulk-sending tools.',
    benignCauses: 'Some receiving systems add Message-IDs later; some header copies omit it.',
    recommendation: 'Consider together with other findings.',
  }),
  HEADER_DATE_MISSING: rule({
    id: 'HEADER_DATE_MISSING',
    category: 'header',
    severity: 'low',
    title: 'No Date header',
    rationale: 'A Date header is required by RFC 5322. Missing dates are unusual.',
    benignCauses: 'Incomplete header copies.',
    recommendation: 'Consider together with other findings.',
  }),
  HEADER_DATE_INVALID: rule({
    id: 'HEADER_DATE_INVALID',
    category: 'header',
    severity: 'low',
    title: 'Date header is not a valid date',
    rationale:
      'The Date header could not be interpreted, which suggests a non-standard sending tool.',
    benignCauses: 'Some older or custom mail software formats dates incorrectly.',
    recommendation: 'Consider together with other findings.',
  }),
  HEADER_DATE_FUTURE: rule({
    id: 'HEADER_DATE_FUTURE',
    category: 'header',
    severity: 'low',
    title: 'Date header is in the future',
    rationale:
      'The message claims to have been written more than a day after the time of analysis. Spammers sometimes set future dates so messages stay at the top of inboxes.',
    benignCauses: 'Clock errors on the sending computer.',
    recommendation: 'Consider together with other findings.',
  }),
  HEADER_SUBJECT_BIDI: rule({
    id: 'HEADER_SUBJECT_BIDI',
    category: 'header',
    severity: 'medium',
    title: 'Hidden or direction-changing characters in sender name or subject',
    rationale:
      'The subject or sender name contains invisible or bidirectional control characters, which can reorder or hide text on screen to evade filters or mislead readers.',
    benignCauses:
      'Right-to-left marks occur legitimately in Arabic or Hebrew text, and some mailers insert zero-width characters.',
    recommendation: 'Review the revealed characters shown in the evidence.',
  }),
  HEADER_RECEIVED_TIME_ORDER: rule({
    id: 'HEADER_RECEIVED_TIME_ORDER',
    category: 'header',
    severity: 'low',
    title: 'Received timestamps are out of order',
    rationale:
      'Each mail server adds a Received header on top of the previous ones, so timestamps should increase towards the top. A significant reversal can indicate forged Received headers.',
    benignCauses: 'Clock skew on one of the servers is the most common explanation.',
    recommendation:
      "Remember that Received headers below your own provider's servers are written by systems you do not control.",
  }),
  HEADER_NO_RECEIVED: rule({
    id: 'HEADER_NO_RECEIVED',
    category: 'header',
    severity: 'info',
    title: 'No Received headers',
    rationale:
      'The message shows no transit history. Messages delivered through the internet normally carry several Received headers.',
    benignCauses: 'Drafts, sent items, some exports and pasted partial headers have none.',
    recommendation: 'If this message arrived in your inbox, export the original with full headers.',
  }),

  // -------------------------------------------------------- authentication
  AUTH_RESULTS_ABSENT: rule({
    id: 'AUTH_RESULTS_ABSENT',
    category: 'authentication',
    severity: 'info',
    title: 'No Authentication-Results header',
    rationale:
      'No SPF/DKIM/DMARC results were recorded in the message, so there is nothing to report. PhishLens cannot perform these checks itself.',
    benignCauses: 'Many mail systems and exports do not include these headers.',
    recommendation:
      'Ask your mail administrator whether your provider records authentication results.',
  }),
  AUTH_REPORTED_DMARC_FAIL: rule({
    id: 'AUTH_REPORTED_DMARC_FAIL',
    category: 'authentication',
    severity: 'high',
    title: 'Reported DMARC failure',
    rationale: `A header in the message reports that DMARC failed: the visible From domain was not authenticated by an aligned SPF or DKIM result. ${REPORTED_ONLY} Attackers who forge results usually forge passes, so a reported failure is worth taking seriously.`,
    benignCauses:
      'Forwarding and mailing lists can break DMARC for legitimate mail; misconfigured legitimate senders also fail.',
    recommendation: VERIFY_SENDER,
  }),
  AUTH_REPORTED_SPF_FAIL: rule({
    id: 'AUTH_REPORTED_SPF_FAIL',
    category: 'authentication',
    severity: 'medium',
    title: 'Reported SPF failure',
    rationale: `A header reports that the sending server was not authorised by the envelope domain's SPF policy. ${REPORTED_ONLY}`,
    benignCauses:
      'Forwarded mail commonly fails SPF; SPF also checks the envelope sender, not the visible From.',
    recommendation:
      'Consider the reported DMARC result, which accounts for forwarding and alignment.',
  }),
  AUTH_REPORTED_SPF_SOFTFAIL: rule({
    id: 'AUTH_REPORTED_SPF_SOFTFAIL',
    category: 'authentication',
    severity: 'low',
    title: 'Reported SPF soft failure',
    rationale: `A header reports an SPF soft fail: the domain owner says the server is probably not authorised. ${REPORTED_ONLY}`,
    benignCauses: 'Common for forwarded mail and domains still configuring SPF.',
    recommendation: 'Consider the reported DMARC result as well.',
  }),
  AUTH_REPORTED_DKIM_FAIL: rule({
    id: 'AUTH_REPORTED_DKIM_FAIL',
    category: 'authentication',
    severity: 'medium',
    title: 'Reported DKIM failure',
    rationale: `A header reports that a DKIM signature did not verify, meaning the message may have been altered or the signature is not genuine. ${REPORTED_ONLY}`,
    benignCauses:
      'Mailing lists and security gateways that modify messages often break DKIM signatures.',
    recommendation: 'Consider the reported DMARC result as well.',
  }),
  AUTH_REPORTED_ERROR: rule({
    id: 'AUTH_REPORTED_ERROR',
    category: 'authentication',
    severity: 'low',
    title: 'Reported authentication error',
    rationale: `A header reports a temporary or permanent error for SPF, DKIM or DMARC, so the check produced no usable result. ${REPORTED_ONLY}`,
    benignCauses: 'DNS outages and misconfigured but legitimate domains.',
    recommendation: 'Consider together with other findings.',
  }),
  AUTH_REPORTED_PASS: rule({
    id: 'AUTH_REPORTED_PASS',
    category: 'authentication',
    severity: 'info',
    title: 'Reported authentication passes are claims, not proof',
    rationale: `The message contains passing SPF, DKIM or DMARC results. ${REPORTED_ONLY} Such headers can be forged by the sender, and a genuine pass only shows that the sending domain authorised the message, not that the domain or message is trustworthy. Attackers routinely pass authentication for domains they own.`,
    benignCauses: 'Legitimate mail usually passes.',
    recommendation: 'Do not treat a pass as evidence that the message is safe.',
  }),
  AUTH_MULTIPLE_AUTHSERV: rule({
    id: 'AUTH_MULTIPLE_AUTHSERV',
    category: 'authentication',
    severity: 'info',
    title: 'Results from more than one reporting server',
    rationale:
      'Authentication-Results headers claim to come from several different servers. Only one of them, added by your own receiving provider, can be meaningful; the others were written by systems you may not trust.',
    benignCauses: 'Normal when mail passes through a security gateway and then a mailbox provider.',
    recommendation:
      'Focus on the results added by your own mail provider, which are usually the topmost.',
  }),
  AUTH_RESULTS_DOMAIN_MISMATCH: rule({
    id: 'AUTH_RESULTS_DOMAIN_MISMATCH',
    category: 'authentication',
    severity: 'medium',
    title: 'Reported DMARC result refers to a different domain',
    rationale:
      'The DMARC result in the message refers to a header.from domain that differs from the visible From address. A copied or forged Authentication-Results header is one possible explanation.',
    benignCauses: 'Messages with multiple From addresses, or edited copies of a message.',
    recommendation: VERIFY_SENDER,
  }),
  AUTH_DKIM_NOT_ALIGNED: rule({
    id: 'AUTH_DKIM_NOT_ALIGNED',
    category: 'authentication',
    severity: 'info',
    title: 'No DKIM signature claims the From domain',
    rationale:
      'DKIM signatures are present, but none uses the organisational domain of the From address (d=). PhishLens did not verify any signature.',
    benignCauses:
      'Very common for mail sent through third-party platforms that sign with their own domain.',
    recommendation: 'Consider the reported DMARC result, which accounts for alignment.',
  }),
  AUTH_DKIM_BODY_LENGTH: rule({
    id: 'AUTH_DKIM_BODY_LENGTH',
    category: 'authentication',
    severity: 'low',
    title: 'DKIM signature covers only part of the body',
    rationale:
      'A DKIM signature uses the l= tag, which limits the signed body length. Content appended after the signed portion would not invalidate the signature.',
    benignCauses:
      'A small number of legitimate mailers still set l=, for mailing-list compatibility.',
    recommendation: 'Be cautious of any content near the end of the message.',
  }),
  AUTH_DKIM_MALFORMED: rule({
    id: 'AUTH_DKIM_MALFORMED',
    category: 'authentication',
    severity: 'low',
    title: 'Malformed DKIM-Signature header',
    rationale:
      'A DKIM-Signature header is missing required tags (such as d=, s=, b= or a signed From header), so it could not be valid.',
    benignCauses: 'Truncated header copies.',
    recommendation: 'Consider together with other findings.',
  }),

  // --------------------------------------------------------------- URLs
  URL_TEXT_MISMATCH: rule({
    id: 'URL_TEXT_MISMATCH',
    category: 'url',
    severity: 'medium',
    title: 'Link text shows a different domain or address than its destination',
    rationale:
      'The visible link text looks like one web or email address, but the link actually points to a different organisational domain. This is a classic way of disguising a malicious destination.',
    benignCauses:
      'Marketing platforms rewrite links for click tracking, so legitimate newsletters often trigger this.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_TEXT_BRAND_MISMATCH: rule({
    id: 'URL_TEXT_BRAND_MISMATCH',
    category: 'url',
    severity: 'high',
    title: 'Link text shows a brand domain but points elsewhere',
    rationale:
      "The link text displays a well-known brand's web address, but the link goes to a domain that is not associated with that brand.",
    benignCauses: 'Click-tracking services used by the brand itself.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_IP_HOST: rule({
    id: 'URL_IP_HOST',
    category: 'url',
    severity: 'medium',
    title: 'Link points to a raw IP address',
    rationale:
      'Legitimate organisations almost always link to domain names. Links to bare IP addresses avoid domain reputation checks.',
    benignCauses: 'Internal corporate systems and network devices are sometimes linked by IP.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_OBFUSCATED_IP: rule({
    id: 'URL_OBFUSCATED_IP',
    category: 'url',
    severity: 'high',
    title: 'Link hides an IP address in an unusual notation',
    rationale:
      'The host is written as a decimal, hexadecimal or octal number that browsers silently convert into an IP address. This notation has no common legitimate use and is used to disguise destinations.',
    benignCauses: 'Essentially none in normal email.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_USERINFO: rule({
    id: 'URL_USERINFO',
    category: 'url',
    severity: 'high',
    title: 'Link contains an "@" before the real host',
    rationale:
      'Everything before "@" in a web address is a user name, not the destination. "https://trusted.example@attacker.example/" actually goes to attacker.example.',
    benignCauses: 'Rare; some FTP links legitimately include a user name.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_DANGEROUS_SCHEME: rule({
    id: 'URL_DANGEROUS_SCHEME',
    category: 'url',
    severity: 'high',
    title: 'Link uses a script or data scheme',
    rationale:
      'Links using the javascript, vbscript or data scheme can run code or display attacker-controlled pages without a web address. They have no legitimate use in email links.',
    benignCauses: 'None in normal email.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_UNUSUAL_SCHEME: rule({
    id: 'URL_UNUSUAL_SCHEME',
    category: 'url',
    severity: 'medium',
    title: 'Link uses an unusual scheme',
    rationale:
      'The link uses a scheme other than http, https, mailto or tel (for example file:, smb: or an application protocol handler). Such links can open local programs, leak credentials or trigger application vulnerabilities.',
    benignCauses: 'Meeting invitations (for example zoommtg:, msteams:) and internal tools.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_PUNYCODE: rule({
    id: 'URL_PUNYCODE',
    category: 'url',
    severity: 'low',
    title: 'Link uses an internationalized (punycode) domain',
    rationale:
      'The domain contains non-ASCII characters, encoded as "xn--". Internationalized names are legitimate, but can imitate familiar domains with look-alike letters.',
    benignCauses: 'Common for websites in non-Latin scripts.',
    recommendation: 'Compare the Unicode form shown with the domain you expect.',
  }),
  URL_MIXED_SCRIPT: rule({
    id: 'URL_MIXED_SCRIPT',
    category: 'url',
    severity: 'high',
    title: 'Link domain mixes look-alike alphabets',
    rationale:
      'A domain label mixes Latin letters with Cyrillic, Greek or Armenian letters, a homograph technique that can be visually indistinguishable from a familiar domain.',
    benignCauses: 'Extremely rare in legitimate domains.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_LOOKALIKE_DOMAIN: rule({
    id: 'URL_LOOKALIKE_DOMAIN',
    category: 'url',
    severity: 'high',
    title: 'Link domain resembles a well-known brand',
    rationale:
      'The domain closely resembles a known brand (character substitution, a one-letter typo, or confusable letters), a common impersonation technique.',
    benignCauses: 'Coincidental similarity with an unrelated business.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_BRAND_IN_SUBDOMAIN: rule({
    id: 'URL_BRAND_IN_SUBDOMAIN',
    category: 'url',
    severity: 'high',
    title: 'Brand domain used as a subdomain of another site',
    rationale:
      'A brand\'s domain appears at the start of the host name, but the real registered domain is different, for example "brand.com.attacker.example". Readers tend to notice only the beginning of the address.',
    benignCauses: 'Rare; some hosting and tracking setups produce such names.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_BRAND_KEYWORD: rule({
    id: 'URL_BRAND_KEYWORD',
    category: 'url',
    severity: 'medium',
    title: 'Link domain contains a brand name it may not belong to',
    rationale:
      'The host name includes a well-known brand name without belonging to a domain PhishLens associates with that brand.',
    benignCauses: 'Partners, resellers, campaign sites and the limits of the brand domain list.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_SHORTENER: rule({
    id: 'URL_SHORTENER',
    category: 'url',
    severity: 'low',
    title: 'Link uses a URL shortener',
    rationale: 'Shortened links hide their final destination until opened.',
    benignCauses: 'Widely used in legitimate marketing and social media.',
    recommendation:
      'Do not open it to find out where it goes; ask your security team if the destination matters.',
  }),
  URL_INSECURE_HTTP: rule({
    id: 'URL_INSECURE_HTTP',
    category: 'url',
    severity: 'low',
    title: 'Link uses unencrypted HTTP',
    rationale: 'The link is not encrypted. Login or payment pages should always use HTTPS.',
    benignCauses: 'Many tracking redirects and older sites still use HTTP.',
    recommendation: 'Never enter credentials on a page reached through an HTTP link.',
  }),
  URL_NONSTANDARD_PORT: rule({
    id: 'URL_NONSTANDARD_PORT',
    category: 'url',
    severity: 'low',
    title: 'Link uses a non-standard port',
    rationale:
      'The link specifies an explicit port number. Public websites rarely need one; attacker infrastructure sometimes does.',
    benignCauses: 'Development servers, internal tools and some hosting providers.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_ENCODED_HOST: rule({
    id: 'URL_ENCODED_HOST',
    category: 'url',
    severity: 'medium',
    title: 'Link host name is percent-encoded',
    rationale:
      'The host name contains percent-encoded characters, which browsers decode silently. Encoding the host only makes sense as an attempt to hide it.',
    benignCauses: 'Essentially none.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_RISKY_TLD: rule({
    id: 'URL_RISKY_TLD',
    category: 'url',
    severity: 'low',
    title: 'Link uses a top-level domain frequently seen in abuse',
    rationale:
      'The domain ends in a top-level domain that abuse reports frequently associate with phishing and spam, often because names are cheap or free.',
    benignCauses: 'Many legitimate sites use these TLDs; abuse statistics change over time.',
    recommendation: 'Treat this as a weak signal and consider other findings.',
  }),
  URL_SHARED_HOSTING: rule({
    id: 'URL_SHARED_HOSTING',
    category: 'url',
    severity: 'low',
    title: 'Link points to a shared hosting or user-content platform',
    rationale:
      "The link is on a platform where anyone can publish content under the platform's domain (for example cloud storage buckets or static site hosts). Phishing pages are frequently hosted this way to borrow the platform's reputation.",
    benignCauses: 'Legitimate organisations also host content and images on these platforms.',
    recommendation: 'Do not assume content is trustworthy because of the platform domain.',
  }),
  URL_TUNNEL_OR_DYNAMIC_DNS: rule({
    id: 'URL_TUNNEL_OR_DYNAMIC_DNS',
    category: 'url',
    severity: 'medium',
    title: 'Link uses a dynamic DNS or tunnelling service',
    rationale:
      'The host belongs to a dynamic DNS or tunnelling service, which allows anyone to publish a temporary address. These are rarely used in legitimate business email.',
    benignCauses: 'Hobbyist and development use.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_IPFS: rule({
    id: 'URL_IPFS',
    category: 'url',
    severity: 'medium',
    title: 'Link points to IPFS content',
    rationale:
      'The link points to decentralised IPFS content, which is hard to take down and has been heavily used to host phishing pages.',
    benignCauses: 'Legitimate decentralised-web projects.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_COMPLEX_HOSTNAME: rule({
    id: 'URL_COMPLEX_HOSTNAME',
    category: 'url',
    severity: 'low',
    title: 'Link has an unusually long or deeply nested host name',
    rationale:
      'Long host names with many subdomains can push the real domain out of view, especially on mobile screens.',
    benignCauses: 'Content delivery networks and cloud services often use long host names.',
    recommendation: 'Read the registered domain shown for this link carefully.',
  }),
  URL_EMBEDDED_REDIRECT: rule({
    id: 'URL_EMBEDDED_REDIRECT',
    category: 'url',
    severity: 'low',
    title: 'Link carries another web address as a parameter',
    rationale:
      'The link contains a second address in a redirect-style parameter that points to a different domain. Open redirects on reputable sites are abused to bounce victims to malicious pages.',
    benignCauses: 'Click tracking and login flows use redirect parameters legitimately.',
    recommendation: 'Review the embedded destination listed for this link.',
  }),
  URL_SECURITY_WRAPPER: rule({
    id: 'URL_SECURITY_WRAPPER',
    category: 'url',
    severity: 'info',
    title: 'Links were rewritten by an email security gateway',
    rationale:
      'Links have been wrapped by a security service (such as Microsoft Safe Links or Proofpoint URL Defense). Where possible PhishLens extracts and analyses the original destination.',
    benignCauses: 'Normal in organisations that use these services.',
    recommendation: 'Wrapped links are not proof that a destination is safe.',
  }),
  URL_RISKY_DOWNLOAD: rule({
    id: 'URL_RISKY_DOWNLOAD',
    category: 'url',
    severity: 'medium',
    title: 'Link appears to download a risky file type',
    rationale:
      'The link path ends with an extension associated with executables, scripts, disk images or archives. Links to files avoid attachment scanning.',
    benignCauses: 'Software vendors and file-sharing notifications link to downloads.',
    recommendation: DO_NOT_OPEN_LINKS,
  }),
  URL_UNPARSEABLE: rule({
    id: 'URL_UNPARSEABLE',
    category: 'url',
    severity: 'low',
    title: 'Malformed link',
    rationale:
      'A link could not be parsed as a valid web address. Mail clients and browsers may interpret malformed links in different ways.',
    benignCauses: 'Broken templates and line-wrapped plain-text links.',
    recommendation: 'Do not try to repair and open the link.',
  }),

  // --------------------------------------------------------------- HTML
  HTML_FORM: rule({
    id: 'HTML_FORM',
    category: 'html',
    severity: 'medium',
    title: 'Message contains an HTML form',
    rationale:
      'Forms inside an email can submit information directly to an attacker without visiting a website first. Legitimate email rarely contains forms.',
    benignCauses: 'Some surveys and feedback widgets embed simple forms.',
    recommendation: 'Do not enter information into forms inside email.',
  }),
  HTML_PASSWORD_FIELD: rule({
    id: 'HTML_PASSWORD_FIELD',
    category: 'html',
    severity: 'high',
    title: 'Message contains a password field',
    rationale:
      'The email body includes a password input. Legitimate services never ask you to type a password into an email.',
    benignCauses: 'None in normal email.',
    recommendation: 'Do not enter any password. Report the message to your security team.',
  }),
  HTML_ACTIVE_CONTENT: rule({
    id: 'HTML_ACTIVE_CONTENT',
    category: 'html',
    severity: 'medium',
    title: 'Message HTML contains active content',
    rationale:
      'The HTML includes scripts, frames, embedded objects, event-handler attributes or automatic redirects. Mail clients normally block these, so their presence suggests the message was not built by a normal mail tool. PhishLens never runs or renders them.',
    benignCauses: 'Some poorly designed newsletter templates include leftover website code.',
    recommendation: 'Avoid viewing the message in a client that renders HTML without restrictions.',
  }),
  HTML_REMOTE_CONTENT: rule({
    id: 'HTML_REMOTE_CONTENT',
    category: 'html',
    severity: 'info',
    title: 'Message loads remote images or resources',
    rationale:
      'The HTML references images or resources on remote servers. Loading them can confirm to the sender that you opened the message. PhishLens did not load them.',
    benignCauses: 'Nearly all newsletters and marketing emails do this.',
    recommendation: 'Consider disabling automatic image loading in your mail client.',
  }),
  HTML_HIDDEN_TEXT: rule({
    id: 'HTML_HIDDEN_TEXT',
    category: 'html',
    severity: 'low',
    title: 'Message HTML contains a lot of hidden text',
    rationale:
      'A substantial amount of text is hidden with CSS (for example display:none or a zero font size). Phishing kits pad messages with invisible text to confuse spam filters while showing the reader something else.',
    benignCauses:
      'Newsletters hide a short preview line ("preheader"); PhishLens only flags larger amounts of hidden text.',
    recommendation:
      'Read the visible text in the Content tab and compare it with what the message claims.',
  }),
  HTML_BASE_TAG: rule({
    id: 'HTML_BASE_TAG',
    category: 'html',
    severity: 'low',
    title: 'Message HTML sets a base URL',
    rationale:
      'A <base> tag changes how relative links are resolved, which has been used to evade link scanners.',
    benignCauses: 'Occasionally left in templates copied from web pages.',
    recommendation: 'Consider together with other findings.',
  }),

  // -------------------------------------------------------- attachments
  ATTACHMENT_EXECUTABLE: rule({
    id: 'ATTACHMENT_EXECUTABLE',
    category: 'attachment',
    severity: 'high',
    title: 'Executable, script or shortcut attachment',
    rationale:
      'The attachment name ends with an extension that Windows or macOS can run directly (programs, scripts, shortcuts, installers). This is one of the most common malware delivery methods.',
    benignCauses: 'IT departments occasionally send scripts or installers internally.',
    recommendation: DO_NOT_OPEN_ATTACHMENT,
  }),
  ATTACHMENT_DOUBLE_EXTENSION: rule({
    id: 'ATTACHMENT_DOUBLE_EXTENSION',
    category: 'attachment',
    severity: 'high',
    title: 'Attachment name uses a double extension',
    rationale:
      'The name looks like a document (for example ".pdf") but actually ends with a risky extension, as in "invoice.pdf.exe". Systems that hide known extensions show only the harmless-looking part.',
    benignCauses: 'Very rare for risky final extensions.',
    recommendation: DO_NOT_OPEN_ATTACHMENT,
  }),
  ATTACHMENT_BIDI_FILENAME: rule({
    id: 'ATTACHMENT_BIDI_FILENAME',
    category: 'attachment',
    severity: 'high',
    title: 'Attachment name contains hidden or direction-changing characters',
    rationale:
      'The filename contains bidirectional overrides or invisible characters. The right-to-left override can make "invoice[U+202E]fdp.exe" display as "invoiceexe.pdf".',
    benignCauses: 'Filenames in right-to-left languages may contain direction marks.',
    recommendation: DO_NOT_OPEN_ATTACHMENT,
  }),
  ATTACHMENT_DISGUISED_EXECUTABLE: rule({
    id: 'ATTACHMENT_DISGUISED_EXECUTABLE',
    category: 'attachment',
    severity: 'high',
    title: 'Attachment content looks like a program despite its name',
    rationale:
      'The first bytes of the attachment match an executable file format, but the filename suggests something else. PhishLens only read the leading bytes; it did not open or run the file.',
    benignCauses: 'Essentially none.',
    recommendation: DO_NOT_OPEN_ATTACHMENT,
  }),
  ATTACHMENT_DISK_IMAGE: rule({
    id: 'ATTACHMENT_DISK_IMAGE',
    category: 'attachment',
    severity: 'medium',
    title: 'Disk image attachment',
    rationale:
      'Disk images (.iso, .img, .vhd) can contain programs and have been used to bypass security warnings that apply to downloaded files.',
    benignCauses: 'Rare in normal email; sometimes used for software distribution.',
    recommendation: DO_NOT_OPEN_ATTACHMENT,
  }),
  ATTACHMENT_HTML: rule({
    id: 'ATTACHMENT_HTML',
    category: 'attachment',
    severity: 'medium',
    title: 'HTML or SVG attachment',
    rationale:
      'HTML and SVG files open in a browser and can display a convincing fake login page locally or assemble a malicious download ("HTML smuggling"), bypassing link scanners.',
    benignCauses: 'Some receipts, reports and voicemail notifications are sent as HTML files.',
    recommendation: DO_NOT_OPEN_ATTACHMENT,
  }),
  ATTACHMENT_MACRO_DOCUMENT: rule({
    id: 'ATTACHMENT_MACRO_DOCUMENT',
    category: 'attachment',
    severity: 'medium',
    title: 'Macro-enabled Office document',
    rationale:
      'The file is an Office document that can contain macros, either by its extension or because a VBA macro project was found inside it. Macros are a long-standing malware delivery method.',
    benignCauses: 'Finance and engineering teams share macro workbooks legitimately.',
    recommendation:
      'Never enable macros or editing in a document you did not expect. ' + DO_NOT_OPEN_ATTACHMENT,
  }),
  ATTACHMENT_ONENOTE: rule({
    id: 'ATTACHMENT_ONENOTE',
    category: 'attachment',
    severity: 'medium',
    title: 'OneNote attachment',
    rationale:
      'OneNote files can embed other files behind fake "click to view" buttons and have been widely abused to deliver malware.',
    benignCauses: 'Sharing notebooks by email is uncommon but legitimate.',
    recommendation: DO_NOT_OPEN_ATTACHMENT,
  }),
  ATTACHMENT_ARCHIVE: rule({
    id: 'ATTACHMENT_ARCHIVE',
    category: 'attachment',
    severity: 'low',
    title: 'Archive attachment',
    rationale:
      'Archives can hide their contents from mail scanners and from you until extracted. PhishLens does not look inside archives.',
    benignCauses: 'Very common for sharing several files.',
    recommendation: 'Only open archives you were expecting from a sender you have verified.',
  }),
  ATTACHMENT_ENCRYPTED_ARCHIVE: rule({
    id: 'ATTACHMENT_ENCRYPTED_ARCHIVE',
    category: 'attachment',
    severity: 'medium',
    title: 'Password-protected archive',
    rationale:
      'The ZIP archive is encrypted, which prevents mail scanners from inspecting it. Malware campaigns often send the password in the message body.',
    benignCauses: 'Some organisations encrypt sensitive documents this way.',
    recommendation: DO_NOT_OPEN_ATTACHMENT,
  }),
  ATTACHMENT_ARCHIVE_EXECUTABLE: rule({
    id: 'ATTACHMENT_ARCHIVE_EXECUTABLE',
    category: 'attachment',
    severity: 'high',
    title: 'Archive contains executable, script or shortcut files',
    rationale:
      'The archive directory lists files that can run code when opened (programs, scripts, shortcuts, installers or disk images), or names with double extensions. Packing them in an archive is a common way to get past attachment filters. PhishLens read only the file names; nothing was extracted.',
    benignCauses: 'Software distribution and IT support occasionally send installers in archives.',
    recommendation: DO_NOT_OPEN_ATTACHMENT,
  }),
  ATTACHMENT_ARCHIVE_ACTIVE_CONTENT: rule({
    id: 'ATTACHMENT_ARCHIVE_ACTIVE_CONTENT',
    category: 'attachment',
    severity: 'medium',
    title: 'Archive contains HTML pages or macro documents',
    rationale:
      'The archive directory lists HTML or SVG files (which can show fake login pages) or macro-enabled Office documents. PhishLens read only the file names; nothing was extracted.',
    benignCauses: 'Exported websites, reports and spreadsheets are sometimes shared as archives.',
    recommendation: DO_NOT_OPEN_ATTACHMENT,
  }),
  ATTACHMENT_PDF_ACTIVE: rule({
    id: 'ATTACHMENT_PDF_ACTIVE',
    category: 'attachment',
    severity: 'medium',
    title: 'PDF contains scripts, launch actions, forms or embedded files',
    rationale:
      'The PDF declares JavaScript, actions that launch programs, embedded files, submittable forms or rich media. These features are rarely needed in an ordinary document and are used by malicious PDFs. PhishLens searched the raw bytes for these keywords; content inside compressed streams is not visible to this check.',
    benignCauses:
      'Fillable business forms and some generated reports use JavaScript or forms legitimately.',
    recommendation: DO_NOT_OPEN_ATTACHMENT,
  }),
  ATTACHMENT_CREDENTIAL_FORM: rule({
    id: 'ATTACHMENT_CREDENTIAL_FORM',
    category: 'attachment',
    severity: 'high',
    title: 'HTML attachment contains a login form',
    rationale:
      'An HTML or SVG attachment contains a password field. Opening it would show a local login page, a common credential-phishing technique that avoids link scanners.',
    benignCauses: 'None in normal email.',
    recommendation:
      'Do not open the attachment or enter any password. Report the message to your security team.',
  }),
  ATTACHMENT_HTML_SMUGGLING: rule({
    id: 'ATTACHMENT_HTML_SMUGGLING',
    category: 'attachment',
    severity: 'high',
    title: 'HTML attachment shows signs of HTML smuggling',
    rationale:
      'Scripts in an HTML or SVG attachment decode a large embedded payload and build a file in the browser (for example with atob and Blob). This "HTML smuggling" technique delivers malware without the file ever passing through mail filters.',
    benignCauses: 'Very rare in legitimate email attachments.',
    recommendation: DO_NOT_OPEN_ATTACHMENT,
  }),
  ATTACHMENT_SIGNATURE_MISMATCH: rule({
    id: 'ATTACHMENT_SIGNATURE_MISMATCH',
    category: 'attachment',
    severity: 'low',
    title: 'Attachment content does not match its extension',
    rationale:
      'The first bytes of the file indicate a different format than its extension suggests. PhishLens only read the leading bytes.',
    benignCauses:
      'Files are sometimes saved with the wrong extension (for example RTF saved as .doc).',
    recommendation: 'Treat the file according to its detected type, not its name.',
  }),
  ATTACHMENT_TYPE_MISMATCH: rule({
    id: 'ATTACHMENT_TYPE_MISMATCH',
    category: 'attachment',
    severity: 'low',
    title: 'Declared content type does not match the extension',
    rationale:
      'The MIME type declared by the sender is inconsistent with the filename extension, which can confuse scanners that rely on one or the other.',
    benignCauses: 'Mail software frequently declares imprecise types.',
    recommendation: 'Consider together with other findings.',
  }),
  ATTACHMENT_EMBEDDED_MESSAGE: rule({
    id: 'ATTACHMENT_EMBEDDED_MESSAGE',
    category: 'attachment',
    severity: 'info',
    title: 'An email message is attached',
    rationale:
      'The message contains another email as an attachment. Its headers, links and attachments are not part of this analysis.',
    benignCauses: 'Common when phishing is reported by forwarding "as attachment".',
    recommendation: 'Use "Analyze attached message" to examine it separately.',
  }),

  // ------------------------------------------------------------ content
  CONTENT_URGENCY_LANGUAGE: rule({
    id: 'CONTENT_URGENCY_LANGUAGE',
    category: 'content',
    severity: 'low',
    title: 'Pressure or account-threat language',
    rationale:
      'The subject or body uses phrases typical of phishing pretexts, such as account suspension, urgent verification or unusual sign-in activity. Pressure discourages careful checking.',
    benignCauses: 'Genuine security notifications use similar wording.',
    recommendation: 'Slow down and verify the claim independently.',
  }),
  CONTENT_PAYMENT_DIVERSION: rule({
    id: 'CONTENT_PAYMENT_DIVERSION',
    category: 'content',
    severity: 'medium',
    title: 'Message asks to change payment details or send money',
    rationale:
      'The text mentions changed bank details, new payment instructions or an urgent transfer. Redirecting payments is the core of business email compromise (BEC), which often contains no links or attachments at all.',
    benignCauses:
      'Suppliers do occasionally change banks, and finance teams discuss transfers routinely.',
    recommendation:
      'Confirm any change of payment details by phone, using a number you already have on file, before paying.',
  }),
  CONTENT_QR_CODE_LURE: rule({
    id: 'CONTENT_QR_CODE_LURE',
    category: 'content',
    severity: 'medium',
    title: 'Message asks you to scan a QR code for your account',
    rationale:
      'The text connects a QR code with signing in, multi-factor authentication or account verification. QR-code phishing ("quishing") moves the victim to a phone, away from desktop protections, and hides the link from filters; PhishLens cannot read the code itself.',
    benignCauses:
      'Some genuine authenticator set-up instructions use QR codes, usually after you started the process yourself.',
    recommendation:
      'Do not scan QR codes in unexpected emails. Set up or verify accounts from the official app or website instead.',
  }),
  AUTH_REPORTED_COMPAUTH_FAIL: rule({
    id: 'AUTH_REPORTED_COMPAUTH_FAIL',
    category: 'authentication',
    severity: 'medium',
    title: 'Reported Microsoft composite authentication failure',
    rationale: `Microsoft 365 reports compauth=fail: its combined SPF, DKIM, DMARC and reputation check concluded the sender could not be authenticated, which catches spoofing of domains without a DMARC policy. ${REPORTED_ONLY}`,
    benignCauses: 'Forwarded mail and misconfigured legitimate senders.',
    recommendation: VERIFY_SENDER,
  }),
  CONTENT_IMAGE_ONLY: rule({
    id: 'CONTENT_IMAGE_ONLY',
    category: 'content',
    severity: 'low',
    title: 'Message body is mostly images',
    rationale:
      'The body has images but almost no readable text. Image-only messages hide their wording from filters, and are often used to deliver QR codes ("quishing") that PhishLens and many filters cannot read.',
    benignCauses: 'Some marketing emails and flyers are designed as a single image.',
    recommendation:
      'Do not scan QR codes in unexpected emails. Verify the request through a trusted channel.',
  }),
  CONTENT_CREDENTIAL_REQUEST: rule({
    id: 'CONTENT_CREDENTIAL_REQUEST',
    category: 'content',
    severity: 'medium',
    title: 'Message asks for credentials or payment details',
    rationale:
      'The text asks you to confirm, update or enter a password, account details or payment information. Legitimate organisations rarely ask for these through email links.',
    benignCauses: 'Password-reset emails you requested yourself.',
    recommendation: VERIFY_SENDER,
  }),
} as const satisfies Record<string, RuleDefinition>;

export type RuleId = keyof typeof RULES;

export const RULE_LIST: readonly RuleDefinition[] = Object.freeze(Object.values(RULES));
