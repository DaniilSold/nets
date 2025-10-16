import { useEffect } from 'react';

type Handler = () => void;

type ShortcutMap = Record<string, Handler>;

export function useHotkeys(map: ShortcutMap) {
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const key = event.key.toLowerCase();
      const ctrl = event.ctrlKey || event.metaKey;
      if (map['/'] && key === '/' && !ctrl) {
        event.preventDefault();
        map['/']();
      }
      if (map['f'] && key === 'f' && ctrl) {
        event.preventDefault();
        map['f']();
      }
      if (map['a'] && key === 'a' && !ctrl) {
        event.preventDefault();
        map['a']();
      }
      if (map['g'] && key === 'g' && !ctrl) {
        event.preventDefault();
        map['g']();
      }
      if (map['s'] && key === 's' && !ctrl) {
        event.preventDefault();
        map['s']();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [map]);
}
