/**
 * Frequently impersonated brands and domains PhishLens treats as belonging to
 * them. The list is intentionally small and NOT exhaustive: organisations use
 * many more domains than listed here, which is why brand findings are framed
 * as "not a domain PhishLens associates with the brand", never "fake".
 */
export interface Brand {
  name: string;
  /** Lowercase tokens matched against domain labels. */
  keywords: string[];
  /**
   * When true, a keyword may match inside a longer label ("brandsupport").
   * Disabled for keywords that occur inside ordinary words ("chase" in "purchase").
   */
  substring: boolean;
  /**
   * When true, the brand name in a display name only counts if accompanied by
   * a service word, because it is also a common personal name or word.
   */
  ambiguousName: boolean;
  /** Registrable domains associated with the brand. */
  domains: string[];
}

export const BRANDS: readonly Brand[] = [
  {
    name: 'Microsoft',
    keywords: ['microsoft', 'office365', 'onedrive', 'sharepoint', 'o365', 'm365'],
    substring: true,
    ambiguousName: false,
    domains: [
      'microsoft.com',
      'microsoftonline.com',
      'office.com',
      'office.net',
      'office365.com',
      'outlook.com',
      'live.com',
      'hotmail.com',
      'msn.com',
      'onedrive.com',
      'sharepoint.com',
      'azure.com',
      'windows.net',
      'microsoft365.com',
      'skype.com',
      'bing.com',
      'xbox.com',
      'msft.net',
      'cloud.microsoft',
      'microsoftonline-p.com',
      'microsoftstore.com',
      'sharepointonline.com',
      'microsoftonline.us',
    ],
  },
  {
    name: 'Outlook',
    keywords: ['outlook'],
    substring: false,
    ambiguousName: true,
    domains: ['outlook.com', 'office.com', 'microsoft.com', 'live.com', 'office365.com'],
  },
  {
    name: 'Google',
    keywords: ['google', 'gmail'],
    substring: true,
    ambiguousName: false,
    domains: [
      'google.com',
      'gmail.com',
      'googlemail.com',
      'youtube.com',
      'googleusercontent.com',
      'withgoogle.com',
      'goo.gl',
      'g.co',
      'googleapis.com',
      'googleadservices.com',
      'google-analytics.com',
      'googlesyndication.com',
      'googletagmanager.com',
      'googlevideo.com',
      'googlegroups.com',
      'googledrive.com',
    ],
  },
  {
    name: 'Apple',
    keywords: ['apple', 'icloud', 'itunes', 'appleid'],
    substring: false,
    ambiguousName: true,
    domains: ['apple.com', 'icloud.com', 'me.com', 'mac.com', 'itunes.com', 'apple.news'],
  },
  {
    name: 'Amazon',
    keywords: ['amazon'],
    substring: true,
    ambiguousName: false,
    domains: [
      'amazon.com',
      'amazon.co.uk',
      'amazon.de',
      'amazon.ca',
      'amazon.fr',
      'amazon.in',
      'amazon.co.jp',
      'amazonaws.com',
      'amazonses.com',
      'aws.amazon.com',
      'a2z.com',
      'media-amazon.com',
      'amazonpay.com',
      'amazontrust.com',
      'amazon-adsystem.com',
    ],
  },
  {
    name: 'PayPal',
    keywords: ['paypal'],
    substring: true,
    ambiguousName: false,
    domains: [
      'paypal.com',
      'paypal.me',
      'paypalobjects.com',
      'paypal-communication.com',
      'paypal-community.com',
    ],
  },
  {
    name: 'Netflix',
    keywords: ['netflix'],
    substring: true,
    ambiguousName: false,
    domains: ['netflix.com', 'netflix.net', 'nflxext.com', 'nflximg.net'],
  },
  {
    name: 'Meta',
    keywords: ['facebook', 'instagram', 'whatsapp'],
    substring: true,
    ambiguousName: false,
    domains: [
      'facebook.com',
      'facebookmail.com',
      'fb.com',
      'meta.com',
      'instagram.com',
      'whatsapp.com',
      'messenger.com',
      'facebook.net',
      'whatsapp.net',
    ],
  },
  {
    // "Messenger" is also an ordinary word (and newspaper name), so it is matched only as a whole token.
    name: 'Messenger',
    keywords: ['messenger'],
    substring: false,
    ambiguousName: true,
    domains: ['messenger.com', 'facebook.com', 'fb.com', 'meta.com'],
  },
  {
    name: 'LinkedIn',
    keywords: ['linkedin'],
    substring: true,
    ambiguousName: false,
    domains: ['linkedin.com', 'licdn.com', 'lnkd.in'],
  },
  {
    name: 'DocuSign',
    keywords: ['docusign'],
    substring: true,
    ambiguousName: false,
    domains: ['docusign.com', 'docusign.net'],
  },
  {
    name: 'Dropbox',
    keywords: ['dropbox'],
    substring: true,
    ambiguousName: false,
    domains: [
      'dropbox.com',
      'dropboxmail.com',
      'dropboxusercontent.com',
      'dropboxstatic.com',
      'dropboxapi.com',
    ],
  },
  {
    name: 'Adobe',
    keywords: ['adobe'],
    substring: true,
    ambiguousName: false,
    domains: [
      'adobe.com',
      'adobesign.com',
      'adobe.io',
      'echosign.com',
      'adobelogin.com',
      'adobecc.com',
    ],
  },
  {
    name: 'DHL',
    keywords: ['dhl'],
    substring: false,
    ambiguousName: false,
    domains: ['dhl.com', 'dhl.de', 'dhl.co.uk'],
  },
  {
    name: 'FedEx',
    keywords: ['fedex'],
    substring: true,
    ambiguousName: false,
    domains: ['fedex.com'],
  },
  {
    name: 'UPS',
    keywords: ['ups'],
    substring: false,
    ambiguousName: true,
    domains: ['ups.com'],
  },
  {
    name: 'USPS',
    keywords: ['usps'],
    substring: true,
    ambiguousName: false,
    domains: ['usps.com', 'usps.gov'],
  },
  {
    name: 'Wells Fargo',
    keywords: ['wellsfargo'],
    substring: true,
    ambiguousName: false,
    domains: ['wellsfargo.com', 'wf.com'],
  },
  {
    name: 'Bank of America',
    keywords: ['bankofamerica'],
    substring: true,
    ambiguousName: false,
    domains: ['bankofamerica.com', 'bofa.com', 'ml.com'],
  },
  {
    name: 'Chase',
    keywords: ['chase'],
    substring: false,
    ambiguousName: true,
    domains: ['chase.com', 'jpmorgan.com', 'jpmorganchase.com'],
  },
  {
    name: 'Coinbase',
    keywords: ['coinbase'],
    substring: true,
    ambiguousName: false,
    domains: ['coinbase.com'],
  },
  {
    name: 'Binance',
    keywords: ['binance'],
    substring: true,
    ambiguousName: false,
    domains: ['binance.com'],
  },
  {
    name: 'MetaMask',
    keywords: ['metamask'],
    substring: true,
    ambiguousName: false,
    domains: ['metamask.io', 'consensys.io'],
  },
  {
    name: 'Zoom',
    keywords: ['zoom'],
    substring: false,
    ambiguousName: true,
    domains: ['zoom.us', 'zoom.com', 'zoomgov.com'],
  },
  {
    name: 'Steam',
    keywords: ['steampowered', 'steamcommunity'],
    substring: true,
    ambiguousName: false,
    domains: ['steampowered.com', 'steamcommunity.com', 'steamstatic.com'],
  },
  {
    name: 'IRS',
    keywords: ['irs'],
    substring: false,
    ambiguousName: false,
    domains: ['irs.gov'],
  },
];

/** Words that make an ambiguous brand name in a display name look like an organisation. */
export const SERVICE_WORDS = [
  'account',
  'alert',
  'bank',
  'billing',
  'customer',
  'delivery',
  'helpdesk',
  'id',
  'mail',
  'notification',
  'online',
  'payment',
  'secure',
  'security',
  'service',
  'services',
  'support',
  'team',
  'verification',
];
