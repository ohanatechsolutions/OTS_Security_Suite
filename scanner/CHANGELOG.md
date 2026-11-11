## 2.5.0 — Branding fixes
- Correctly serve `/ohana-logo.png` as PNG; v2.4 mistakenly served CSS.
- Serve PWA manifest and 192/512 px app icons for Chrome-hosted window.
- Bust browser cache for logo/favicon.
- Version the installed shortcut icon path to avoid stale Windows icon cache.
- Add HTTP integration tests for visual branding asset routes.
- Keep all scanner detection logic unchanged.
- Note Chromium app-mode taskbar-icon limitation.

## 2.4.0 — Official Ohana Tech Solutions branding

- Replaced OTS text mark with the original Ohana Tech Solutions logo, converted to white on transparent background.
- Applied the supplied shield-bug icon to shortcut, Windows app resources, installer, Chrome extension, and favicon.
- Updated Windows product version and extension metadata.
- No changes to scanning engine or detection rules.

# Changelog

## 2.3.0 — Compact UI and window lifecycle
- Removed the promotional hero, description, detection matrix and scan-card title.
- Kept scan modes, target input, primary scan button and engine statistics.
- Updated primary accent to neon green `#2CFF05`.
- Added authenticated UI heartbeats. The desktop engine exits about 6 seconds after the last heartbeat when its window closes, with a 30-second launch grace period. Page reloads are tolerated.
- Unchanged detection engine, risk scoring, scan history and extension.
