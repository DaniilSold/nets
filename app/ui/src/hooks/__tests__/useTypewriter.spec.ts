import { renderHook, act } from '@testing-library/react';
import { useTypewriter } from '../useTypewriter';

vi.useFakeTimers();

describe('useTypewriter', () => {
  afterEach(() => {
    vi.clearAllTimers();
  });

  it('returns first line when disabled', () => {
    const { result } = renderHook(() => useTypewriter(['hello', 'world'], { enabled: false }));
    expect(result.current).toBe('hello');
  });

  it('cycles through lines', () => {
    const { result } = renderHook(() => useTypewriter(['alpha', 'beta'], { delay: 10, pause: 20 }));
    act(() => {
      vi.advanceTimersByTime(50);
    });
    expect(result.current.length).toBeGreaterThan(0);
  });
});
