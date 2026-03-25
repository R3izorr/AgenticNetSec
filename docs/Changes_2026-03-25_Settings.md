# Settings Implementation on 2026-03-25

Date: 2026-03-25

## Overview

Today's work added a minimal `/settings` route to the AgenticNetSec frontend.

The goal of this implementation was to provide browser-local runtime preferences without changing backend contracts or introducing server-side settings storage.

This pass intentionally scoped settings to three concrete behaviors already present in the application:

- backend API base URL override
- global polling interval override
- theme preference

`demo mode` and `mock mode` were intentionally deferred for a later pass.

## What Was Added

A new frontend route was added:

- `/settings`

The page allows the user to:

- override the backend API base URL used by frontend requests
- choose a global polling interval used by async job polling and artifact retry polling
- select a theme preference: `dark`, `light`, or `system`
- reset individual settings back to defaults
- reset all browser-local settings at once

The page also explicitly states that preferences are stored locally in the current browser only.

## Settings Architecture

A small client-side settings layer was added to centralize runtime preferences.

### Store and Types

A shared settings module now defines:

- the `AppSettings` type
- default values
- localStorage persistence helpers
- sanitization and fallback behavior
- a tiny subscription-backed store for browser-side settings updates

This implementation stores settings under a single localStorage key and safely falls back to defaults if stored values are missing or invalid.

### Provider

A frontend settings provider now wraps the app and exposes:

- current settings
- resolved polling interval
- update action
- reset action

The provider also applies the current theme preference to the document root.

## Functional Wiring

The new settings are not cosmetic only; they are connected to live frontend behavior.

### API Base URL

The frontend API client now resolves its base URL in this order:

1. browser-local settings override
2. `NEXT_PUBLIC_API_BASE_URL`
3. `http://localhost:8000`

This preserves the existing environment-variable behavior while allowing local browser overrides from the UI.

### Polling Interval

The shared polling preference now drives:

- job status polling
- artifact `409 not ready` retry polling

This keeps the polling cadence consistent across the analysis detail, report, and raw artifact flows.

### Theme Preference

Theme selection now controls the frontend theme at the app root.

Supported values:

- `dark`
- `light`
- `system`

The toast/toaster styling was also updated so it follows the selected theme instead of remaining hardcoded to dark mode.

## UI Changes

The `/settings` page was implemented using the existing shadcn-based component stack already present in the repo.

Main UI sections:

- `Settings` summary and reset-all actions
- `Connectivity`
- `Polling`
- `Appearance`

Each section includes:

- a short explanation of the setting
- the current resolved/default-backed value where useful
- reset controls
- validation or guidance text where needed

The main navigation was also updated to include:

- `Settings`

## Public Interfaces and Contract Impact

This implementation did not change any backend endpoints or backend schemas.

No API request or response contracts were modified.

Public frontend addition:

- new route: `/settings`

Internal frontend additions:

- `AppSettings` type
- localStorage-backed settings store
- settings provider and hook

## Files Touched

Main implementation areas:

- `frontend/app/settings/page.tsx`
- `frontend/components/providers/app-settings-provider.tsx`
- `frontend/lib/settings.ts`
- `frontend/lib/api/client.ts`
- `frontend/hooks/use-job-status.ts`
- `frontend/hooks/use-artifact.ts`
- `frontend/app/layout.tsx`
- `frontend/components/ui/sonner.tsx`
- `frontend/components/layout/app-shell.tsx`

## Validation and Guardrails

The settings page includes validation for:

- malformed API base URLs
- unsupported polling interval values

Stored settings are sanitized when loaded, so invalid or corrupted localStorage values fall back safely instead of breaking the app.

## Verification Run Today

Frontend verification was run with:

```powershell
npm run lint
npm run build
```

Result:

- `npm run build` passed
- `npm run lint` completed with one existing warning only

Existing warning:

- TanStack Table / React Compiler compatibility warning in `frontend/app/analysis/history/data-table.tsx`

Verified outcomes for the settings implementation:

- `/settings` is available as a route
- the page renders in production build output
- theme changes are wired through the app provider and toaster
- polling hooks compile successfully against the shared settings provider
- API client compiles successfully with browser-local base URL resolution

## Notes

- This implementation is frontend-only by design.
- Settings are local to one browser profile and are not shared across devices.
- `demo mode` and `mock mode` remain deferred even though they were mentioned in `docs/FrontendPLAN.md`.
- This markdown is intended as an audit/change record for the `/settings` implementation pass.
