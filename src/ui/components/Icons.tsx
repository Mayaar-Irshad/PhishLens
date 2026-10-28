import type { SVGProps } from 'react';
import type { Severity } from '../../core/types';

type IconProps = SVGProps<SVGSVGElement>;

function base(props: IconProps) {
  return {
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true,
    focusable: false,
    ...props,
  };
}

/** A lens over an envelope flap. */
export function LogoMark(props: IconProps) {
  return (
    <svg {...base(props)} viewBox="0 0 32 32" strokeWidth={2}>
      <path d="M3.5 8.5h19v13h-19z" />
      <path d="M3.5 8.5l9.5 7 9.5-7" />
      <circle cx="21.5" cy="20.5" r="5.5" fill="var(--surface)" />
      <path d="M25.5 24.5l3.5 3.5" />
    </svg>
  );
}

export function ShieldIcon(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6z" />
      <path d="M8.8 12.2l2.3 2.3 4.2-4.6" />
    </svg>
  );
}

export function UploadIcon(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M12 15V4M7.5 8.5L12 4l4.5 4.5" />
      <path d="M4 15v4h16v-4" />
    </svg>
  );
}

export function ChevronIcon(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M6 9l6 6 6-6" />
    </svg>
  );
}

export function BackIcon(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M15 18l-6-6 6-6" />
    </svg>
  );
}

export function DownloadIcon(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M12 4v11M7.5 10.5L12 15l4.5-4.5" />
      <path d="M4 19h16" />
    </svg>
  );
}

export function CopyIcon(props: IconProps) {
  return (
    <svg {...base(props)}>
      <rect x="8" y="8" width="12" height="12" rx="2" />
      <path d="M16 8V5a1 1 0 00-1-1H5a1 1 0 00-1 1v10a1 1 0 001 1h3" />
    </svg>
  );
}

export function CloseIcon(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M6 6l12 12M18 6L6 18" />
    </svg>
  );
}

export function WarningIcon(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M12 3.5l9.5 16.5h-19z" />
      <path d="M12 10v4.5M12 17.2v.3" />
    </svg>
  );
}

export function HeaderIcon(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M4 6h16M4 10h10M4 14h16M4 18h8" />
    </svg>
  );
}

export function LinkIcon(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1" />
      <path d="M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1" />
    </svg>
  );
}

export function PaperclipIcon(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M20 11.5l-8.2 8.2a5 5 0 01-7.1-7.1l8.6-8.6a3.4 3.4 0 014.8 4.8l-8.6 8.6a1.7 1.7 0 01-2.4-2.4l7.9-7.9" />
    </svg>
  );
}

export function KeyIcon(props: IconProps) {
  return (
    <svg {...base(props)}>
      <circle cx="8" cy="15" r="4" />
      <path d="M11 12l8-8M16 7l2.5 2.5M14 9l2 2" />
    </svg>
  );
}

/** Each severity has a distinct shape so it never depends on colour alone. */
export function SeverityIcon({ severity, ...props }: IconProps & { severity: Severity }) {
  switch (severity) {
    case 'high':
      return (
        <svg {...base(props)} strokeWidth={0} fill="currentColor">
          <path d="M8 2h8l6 6v8l-6 6H8l-6-6V8z" />
        </svg>
      );
    case 'medium':
      return (
        <svg {...base(props)} strokeWidth={0} fill="currentColor">
          <path d="M12 2l11 19H1z" />
        </svg>
      );
    case 'low':
      return (
        <svg {...base(props)} strokeWidth={3.5}>
          <circle cx="12" cy="12" r="8" />
        </svg>
      );
    case 'info':
      return (
        <svg {...base(props)} strokeWidth={3}>
          <path d="M12 10.5V18M12 6v.5" />
        </svg>
      );
  }
}
