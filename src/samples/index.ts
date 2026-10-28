import attachmentLure from './attachment-lure.eml?raw';
import credentialPhish from './credential-phish.eml?raw';
import newsletter from './newsletter.eml?raw';

/**
 * Synthetic messages for trying PhishLens without a real phishing email.
 * They use reserved example domains and documentation IP ranges, and the
 * results shown for them are produced by the same analysis as any upload.
 */
export interface Sample {
  id: string;
  title: string;
  description: string;
  fileName: string;
  raw: string;
}

export const SAMPLES: readonly Sample[] = [
  {
    id: 'credential-phish',
    title: 'Credential phishing',
    description: 'Look-alike sender, disguised links and a login form.',
    fileName: 'credential-phish.eml',
    raw: credentialPhish,
  },
  {
    id: 'attachment-lure',
    title: 'Attachment lure',
    description:
      'Double extension, a hidden-character name, an encrypted ZIP and a bank-details change.',
    fileName: 'attachment-lure.eml',
    raw: attachmentLure,
  },
  {
    id: 'newsletter',
    title: 'Ordinary newsletter',
    description: 'A legitimate-looking message, to see what "no indicators" means.',
    fileName: 'newsletter.eml',
    raw: newsletter,
  },
];
