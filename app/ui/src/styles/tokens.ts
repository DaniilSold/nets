export const spacing = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 20,
  xl: 32,
} as const;

export const typography = {
  title: {
    fontSize: '24px',
    fontWeight: 700,
    letterSpacing: '-0.02em',
  },
  subtitle: {
    fontSize: '16px',
    fontWeight: 500,
    letterSpacing: '-0.01em',
  },
  body: {
    fontSize: '14px',
    fontWeight: 400,
    letterSpacing: '0em',
  },
} as const;

export const palette = {
  primary: 'var(--color-primary)',
  primarySoft: 'var(--color-primary-soft)',
  text: 'var(--color-text)',
  muted: 'var(--color-muted)',
  surface: 'var(--color-surface)',
  border: 'var(--color-border)',
  danger: 'var(--color-danger)',
  warning: 'var(--color-warning)',
  success: 'var(--color-success)',
} as const;
