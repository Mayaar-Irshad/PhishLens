import { useEffect, useRef, useState } from 'react';

function carriesFiles(event: DragEvent): boolean {
  return [...(event.dataTransfer?.types ?? [])].includes('Files');
}

/**
 * Accepts a file dropped anywhere on the page. File drags are always
 * intercepted, even while `enabled` is false: otherwise a missed drop makes
 * the browser open the file itself, which for an HTML attachment would render
 * it, exactly what PhishLens must never do.
 */
export function usePageDrop(onFile: (file: File) => void, enabled: boolean): boolean {
  const [dragging, setDragging] = useState(false);
  const latest = useRef({ onFile, enabled });
  useEffect(() => {
    latest.current = { onFile, enabled };
  });

  useEffect(() => {
    let depth = 0;
    const onDragEnter = (event: DragEvent) => {
      if (!carriesFiles(event)) return;
      event.preventDefault();
      depth += 1;
      if (latest.current.enabled) setDragging(true);
    };
    const onDragOver = (event: DragEvent) => {
      if (!carriesFiles(event)) return;
      event.preventDefault();
      if (event.dataTransfer)
        event.dataTransfer.dropEffect = latest.current.enabled ? 'copy' : 'none';
    };
    const onDragLeave = (event: DragEvent) => {
      if (!carriesFiles(event)) return;
      depth = Math.max(0, depth - 1);
      if (depth === 0) setDragging(false);
    };
    const onDrop = (event: DragEvent) => {
      if (!carriesFiles(event)) return;
      event.preventDefault();
      depth = 0;
      setDragging(false);
      const file = event.dataTransfer?.files[0];
      if (file && latest.current.enabled) latest.current.onFile(file);
    };
    window.addEventListener('dragenter', onDragEnter);
    window.addEventListener('dragover', onDragOver);
    window.addEventListener('dragleave', onDragLeave);
    window.addEventListener('drop', onDrop);
    return () => {
      window.removeEventListener('dragenter', onDragEnter);
      window.removeEventListener('dragover', onDragOver);
      window.removeEventListener('dragleave', onDragLeave);
      window.removeEventListener('drop', onDrop);
    };
  }, []);

  return dragging && enabled;
}
