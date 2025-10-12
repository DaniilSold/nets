import { useEffect, useMemo, useState } from 'react';

interface Options {
  delay?: number;
  pause?: number;
  enabled?: boolean;
  once?: boolean;
}

export function useTypewriter(lines: string[], options: Options = {}) {
  const { delay = 80, pause = 2000, enabled = true, once = false } = options;
  const sanitized = useMemo(() => lines.filter(Boolean), [lines]);
  const [index, setIndex] = useState(0);
  const [display, setDisplay] = useState('');

  useEffect(() => {
    if (!enabled || sanitized.length === 0) {
      setDisplay(sanitized[0] ?? '');
      return;
    }

    let active = true;
    let timeout: number;

    const tick = (position: number, forward: boolean) => {
      if (!active) return;
      const fullText = sanitized[index % sanitized.length];
      const next = forward ? fullText.slice(0, position + 1) : fullText.slice(0, position - 1);
      setDisplay(next);

      if (forward && next.length === fullText.length) {
        if (once) {
          active = false;
          return;
        }
        timeout = window.setTimeout(() => tick(next.length, false), pause);
      } else if (!forward && next.length === 0) {
        setIndex((prev) => (prev + 1) % sanitized.length);
        timeout = window.setTimeout(() => tick(0, true), delay);
      } else {
        timeout = window.setTimeout(() => tick(next.length, forward), delay);
      }
    };

    timeout = window.setTimeout(() => tick(0, true), delay);

    return () => {
      active = false;
      window.clearTimeout(timeout);
    };
  }, [delay, pause, sanitized, index, enabled]);

  return display;
}
