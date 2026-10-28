/**
 * Reference lists used by the heuristics. All lists are static and bundled;
 * PhishLens never downloads lists or queries reputation services. They are
 * deliberately conservative and will go out of date: treat matches as hints.
 */

/** Free consumer mailbox providers (registrable domains). */
export const FREEMAIL_DOMAINS: ReadonlySet<string> = new Set([
  'gmail.com',
  'googlemail.com',
  'outlook.com',
  'hotmail.com',
  'hotmail.co.uk',
  'live.com',
  'msn.com',
  'yahoo.com',
  'yahoo.co.uk',
  'yahoo.fr',
  'ymail.com',
  'rocketmail.com',
  'aol.com',
  'icloud.com',
  'me.com',
  'mac.com',
  'proton.me',
  'protonmail.com',
  'pm.me',
  'gmx.com',
  'gmx.net',
  'gmx.de',
  'web.de',
  'mail.com',
  'yandex.com',
  'yandex.ru',
  'mail.ru',
  'zoho.com',
  'tutanota.com',
  'tuta.io',
  'qq.com',
  '163.com',
  '126.com',
  'fastmail.com',
]);

/** Public URL-shortening services (registrable domains). */
export const URL_SHORTENERS: ReadonlySet<string> = new Set([
  'bit.ly',
  'bitly.com',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'v.gd',
  'buff.ly',
  'rebrand.ly',
  'cutt.ly',
  'shorturl.at',
  'tiny.cc',
  'rb.gy',
  't.ly',
  's.id',
  'bl.ink',
  'shorte.st',
  'adf.ly',
  'qrco.de',
  'clck.ru',
  'tiny.one',
  'urlz.fr',
]);

/**
 * Top-level domains that public abuse reports (for example Spamhaus and
 * Interisle phishing landscape studies) repeatedly rank among the most abused.
 * Rankings change over time; this is a weak, low-severity signal.
 */
export const ABUSED_TLDS: ReadonlySet<string> = new Set([
  'zip',
  'mov',
  'top',
  'xyz',
  'click',
  'country',
  'gq',
  'tk',
  'ml',
  'cf',
  'ga',
  'work',
  'support',
  'rest',
  'quest',
  'cam',
  'buzz',
  'icu',
  'cyou',
  'sbs',
  'cfd',
  'bond',
  'monster',
  'lol',
]);

/** Dynamic DNS and tunnelling services (host suffixes). */
export const TUNNEL_AND_DYNAMIC_DNS_SUFFIXES: readonly string[] = [
  'duckdns.org',
  'ddns.net',
  'hopto.org',
  'zapto.org',
  'sytes.net',
  'no-ip.org',
  'no-ip.biz',
  'dynu.net',
  'dyndns.org',
  'freedns.afraid.org',
  'ngrok.io',
  'ngrok.app',
  'ngrok-free.app',
  'ngrok-free.dev',
  'trycloudflare.com',
  'loca.lt',
  'serveo.net',
  'localhost.run',
];

/** Public IPFS gateways (host suffixes). */
export const IPFS_GATEWAY_SUFFIXES: readonly string[] = [
  'ipfs.io',
  'dweb.link',
  'cloudflare-ipfs.com',
  'gateway.pinata.cloud',
  'nftstorage.link',
  'w3s.link',
  'ipfs.w3s.link',
  'fleek.co',
];

/** Parameter names that commonly carry a redirect destination. */
export const REDIRECT_PARAMETERS: ReadonlySet<string> = new Set([
  'url',
  'u',
  'q',
  'r',
  'link',
  'target',
  'dest',
  'destination',
  'redirect',
  'redirect_url',
  'redirect_uri',
  'redirecturl',
  'redir',
  'next',
  'goto',
  'go',
  'return',
  'returnurl',
  'return_url',
  'continue',
  'out',
  'to',
]);

/** Schemes considered normal in email links. */
export const WEB_SCHEMES: ReadonlySet<string> = new Set(['http:', 'https:']);
export const CONTACT_SCHEMES: ReadonlySet<string> = new Set(['mailto:', 'tel:', 'sms:', 'callto:']);
// A detection list: these strings are compared against parsed URLs, never navigated to.
/* eslint-disable no-script-url */
export const DANGEROUS_SCHEMES: ReadonlySet<string> = new Set([
  'javascript:',
  'vbscript:',
  'data:',
]);
/* eslint-enable no-script-url */
/** Schemes that only make sense inside the message and are ignored. */
export const INTERNAL_SCHEMES: ReadonlySet<string> = new Set(['cid:', 'mid:', 'about:']);

/**
 * Multi-tenant SaaS platforms that put each customer's name in a subdomain.
 * A brand name in the subdomain of these is expected, not impersonation.
 */
export const SAAS_TENANT_DOMAINS: ReadonlySet<string> = new Set([
  'zendesk.com',
  'freshdesk.com',
  'service-now.com',
  'servicenow.com',
  'atlassian.net',
  'slack.com',
  'okta.com',
  'oktapreview.com',
  'greenhouse.io',
  'lever.co',
  'myworkdayjobs.com',
  'myworkday.com',
  'salesforce.com',
  'force.com',
  'my.salesforce.com',
  'hubspot.com',
  'box.com',
  'zoom.us',
  'webex.com',
  'smartsheet.com',
  'docusign.net',
]);

/** Default tenant domains of cloud mail services, which anyone can register. */
export const TENANT_PLATFORMS: ReadonlyMap<string, string> = new Map([
  ['onmicrosoft.com', 'Microsoft 365'],
]);

/**
 * Hosts where any customer can publish files or forms under the brand's own
 * domain. Link text showing a brand does not match a link to these.
 */
export const USER_CONTENT_HOSTS: readonly string[] = [
  'sharepoint.com',
  'docs.google.com',
  'drive.google.com',
  'sites.google.com',
  'forms.gle',
  'script.google.com',
  'onedrive.live.com',
  '1drv.ms',
  'dropbox.com',
  'dropboxusercontent.com',
  'googleusercontent.com',
];

/**
 * Email-marketing click trackers. Their links hide the final destination, so
 * link text showing a different (non-brand) domain is expected rather than
 * suspicious. Attackers abuse these services too, so brand text still counts.
 */
export const CLICK_TRACKER_SUFFIXES: readonly string[] = [
  'list-manage.com',
  'mailchi.mp',
  'ct.sendgrid.net',
  'sendgrid.net',
  'mandrillapp.com',
  'rs6.net',
  'hubspotlinks.com',
  'hs-sites.com',
  'exacttarget.com',
  'sailthru.com',
  'klclick.com',
  'klclick1.com',
  'customeriomail.com',
  'createsend.com',
  'cmail19.com',
  'cmail20.com',
  'awstrack.me',
  'mjt.lu',
  'sendibt3.com',
  'pstmrk.it',
  'mailgun.org',
  'links.iterable.com',
];

/**
 * Common file extensions that are also top-level domains. Link text such as
 * "README.md" or "setup.py" names a file, not a website.
 */
export const FILE_EXTENSION_TLDS: ReadonlySet<string> = new Set([
  'md',
  'py',
  'sh',
  'rs',
  'pm',
  'ps',
  'so',
  'ai',
  'cc',
  'ws',
  'zip',
  'mov',
  'ml',
  'sc',
  'cs',
]);
