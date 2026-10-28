import { useEffect, useState } from 'react';
import { CopyIcon } from './Icons';

interface CopyButtonProps {
  value: string;
  /** Accessible description of what is copied, e.g. "defanged link". */
  label: string;
  /** Visible text before copying. */
  text?: string;
  /** Use the outlined style, for the main copy action of a section. */
  secondary?: boolean;
}

type CopyState = 'idle' | 'copied' | 'failed';

export function CopyButton({
  value,
  label,
  text: idleText = 'Copy',
  secondary = false,
}: CopyButtonProps) {
  const [state, setState] = useState<CopyState>('idle');

  useEffect(() => {
    if (state === 'idle') return undefined;
    const timer = setTimeout(() => setState('idle'), 2000);
    return () => clearTimeout(timer);
  }, [state]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setState('copied');
    } catch {
      setState('failed');
    }
  };

  const text = state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : idleText;
  return (
    <button
      type="button"
      className={`button ${secondary ? 'button--secondary' : 'button--quiet'} button--small`}
      onClick={() => void copy()}
      aria-label={state === 'idle' ? `Copy ${label}` : `${text}: ${label}`}
    >
      <CopyIcon />
      <span aria-live="polite">{text}</span>
    </button>
  );
}
