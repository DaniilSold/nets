# Nets Desktop UI

Offline-ready Tauri + React shell for the local network monitoring toolkit.

## Getting Started (Offline)

1. Install dependencies from local cache:
   ```bash
   npm install --prefer-offline
   ```
2. Run the UI in standalone mode with mocked data:
   ```bash
   npm run dev
   ```
3. Launch the Tauri shell (requires Rust + Cargo):
   ```bash
   npm run tauri:dev
   ```

All commands avoid external network calls when the npm cache is pre-populated.

## Testing

```bash
npm run check:locales
npm run test
```

The locale script validates that English and Russian resources contain identical key sets.

## Building Offline Packages

1. Vendor Rust dependencies:
   ```bash
   cargo vendor --locked --manifest-path src-tauri/Cargo.toml
   ```
2. Package the desktop app:
   ```bash
   npm run tauri:build
   ```

Artifacts are emitted under `src-tauri/target/release/bundle` and can be copied to offline hosts.

## Directory Layout

- `src/` – React + TypeScript UI.
- `src-tauri/` – Rust backend emitting flow, alert, and status events.
- `public/` – Inline SVG icons and static assets (no remote fonts).
- `scripts/` – Utility tooling including locale linting.
- `STYLEGUIDE.md` – tokens, typography, and animation guidance.

## Accessibility & Shortcuts

- `/` focus search, `F` flows tab, `A` alerts, `G` graph, `S` settings.
- Respects `prefers-reduced-motion` and can disable animations in Settings.

## Branding

The header always displays **“Created by dsold” / “Разработал dsold”** according to the selected locale.
