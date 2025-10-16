# Nets UI Style Guide

## Brand Principles
- **Offline-first**: all assets, fonts, and scripts are bundled with the application.
- **Dual-language**: every user-facing string is localized (English and Russian) via `i18next`.
- **Friendly minimalism**: neutral palette, generous spacing, and subtle depth via soft shadows.

## Design Tokens
```json
{
  "colors": {
    "backgroundLight": "#f5f7fb",
    "backgroundDark": "#0f141f",
    "surface": "rgba(255,255,255,0.85)",
    "textPrimary": "#1f2330",
    "textMuted": "#4f566b",
    "accent": "#3a7afe",
    "accentSoft": "rgba(58,122,254,0.12)",
    "success": "#46c988",
    "warning": "#ffb347",
    "danger": "#ff5f5f"
  },
  "radii": {
    "lg": 16,
    "md": 12,
    "sm": 8
  },
  "shadows": {
    "elevated": "0 12px 40px rgba(15,20,35,0.08)"
  },
  "spacing": {
    "xs": 4,
    "sm": 8,
    "md": 12,
    "lg": 20,
    "xl": 32
  },
  "typography": {
    "title": {
      "font": "Inter, system-ui",
      "size": 28,
      "weight": 700,
      "letterSpacing": -0.02
    },
    "subtitle": {
      "size": 16,
      "weight": 500
    },
    "body": {
      "size": 14,
      "weight": 400
    }
  }
}
```

## Layout
- Grid-based shell: 280px fixed sidebar, flexible main content.
- Header pinned with gradient background, containing brand, status indicators, and language toggle.
- Content cards use `var(--radius-lg)` and `var(--shadow-elevated)` for consistent depth.

## Components
- **Header**: includes animated tagline (typewriter) and branding `Created by dsold / Разработал dsold`.
- **Sidebar**: uses Radix ToggleGroup for filters, icons from inline SVG, and preset buttons styled as pills.
- **Tables**: virtualization via `react-window`, high-density layout with 10 columns for flows.
- **Graph**: force-inspired radial placement rendered as SVG with gradient strokes.
- **Notifications**: stacked toast cards with fade-in animation.

## Accessibility
- Keyboard navigation: `/` focus flows, `A` alerts, `G` graph, `S` settings.
- All actionable elements have visible focus states and `aria-label`s.
- Reduced motion: respects `prefers-reduced-motion` and exposes toggle in Settings.

## Animation Guidelines
- Typewriter effect limited to greeting line; transitions between tabs use CSS transitions defined in `app.css`.
- Alert notifications slide/fade in under 300ms and auto-dismiss after 5s.

## Iconography
- Inline SVG sprites bundled in `src/assets/icons.svg` (no network fetch).
- Icons sized 16px inside buttons, tinted using `currentColor`.

## Export Paths
- PCAP and HTML exports saved under `~/NetMonExports` (configurable server-side).

## Testing Matrix
- Run `npm run check:locales` to ensure translations are synchronized.
- `npm run test` executes Vitest suite covering hooks and header component.

## Packaging
- Use `npm run tauri:build` for desktop bundles; offline dependencies must be vendored via `cargo vendor` and Node lockfiles.
