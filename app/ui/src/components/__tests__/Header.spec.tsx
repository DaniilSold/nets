import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import { describe, it, expect, vi } from 'vitest';
import { I18nextProvider } from 'react-i18next';
import i18n from '../../setup-i18n';
import { Header } from '../Header';
import type { DaemonStatus } from '../../types/ui';

const status: DaemonStatus = {
  connected: true,
  mode: 'Guardian',
  cpu_load: 2.5,
  memory_mb: 30.2,
  last_heartbeat: new Date().toISOString(),
  capture_enabled: true,
  flows_per_second: 15,
  sample_ratio: '1:10',
  drop_rate: 0.2
};

describe('Header', () => {
  it('renders branding and toggles locale', () => {
    const handleLocale = vi.fn();
    render(
      <I18nextProvider i18n={i18n}>
        <Header
          status={status}
          locale="en"
          brandLine="Created by dsold"
          animatedLine="Offline ready"
          onChangeLocale={handleLocale}
          onToggleMode={vi.fn()}
          onToggleCapture={vi.fn()}
          onOpenSettings={vi.fn()}
          onShowAbout={vi.fn()}
        />
      </I18nextProvider>
    );

    expect(screen.getByText('Created by dsold')).toBeInTheDocument();
    fireEvent.click(screen.getByText('RU'));
    expect(handleLocale).toHaveBeenCalledWith('ru');
  });
});
