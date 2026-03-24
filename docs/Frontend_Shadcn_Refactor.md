# Frontend shadcn/ui Standardization

## Summary

This document summarizes the incremental shadcn/ui standardization pass applied to the AgenticNetSec frontend.

The goal of the refactor was to make the UI system more consistent and maintainable without rewriting app logic, routes, API integration, or domain-specific forensic presentation.

## Outcome

The frontend now uses shadcn/ui much more consistently for shared primitives, state surfaces, forms, tabs, cards, badges, alerts, and toast notifications.

The refactor preserved:

- existing routes
- existing API behavior
- existing polling and async job logic
- existing report and raw artifact data flow
- the current dark analyst-dashboard visual direction

## Pre-Refactor Audit

Before this implementation, the frontend already had a shadcn foundation, but it was narrow.

Existing shadcn usage:

- `button`
- `select`
- `table`
- Tailwind token-based theme setup in `globals.css`

Main inconsistency sources:

- raw `button` and `input` elements in app-level UI
- custom state UIs for loading, empty, and error states
- a homegrown toast renderer
- repeated bordered artifact panels and inset content boxes
- manual tab and segmented-control styling
- repeated status and progress styling outside shared primitives

## shadcn Components Added

The following shadcn/ui components were added to `frontend/components/ui`:

- `alert`
- `badge`
- `card`
- `checkbox`
- `input`
- `label`
- `progress`
- `separator`
- `skeleton`
- `sonner`
- `tabs`
- `toggle`
- `toggle-group`

Dependency added:

- `sonner`

## Shared Foundation Changes

The shared component layer was updated first so page-level changes could stay small and low-risk.

### Updated shared components

- `SectionCard`
  - now composes shadcn `Card`
  - keeps the same external role as the app's primary section wrapper

- `StatusBadge`
  - now renders via shadcn `Badge`
  - keeps centralized status-to-style mapping

- `ProgressBar`
  - now wraps shadcn `Progress`

- `LoadingState`, `ErrorState`, `EmptyState`
  - now use shadcn `Card`, `Alert`, `Skeleton`, and `Button`
  - preserve existing usage patterns while making state UI consistent

- `CopyButton`
  - now uses shadcn `Button`

### New shared wrappers

- `InlineNotice`
  - shared inline info/warning/error surface built on shadcn `Alert`

- `ArtifactPanel`
  - shared wrapper for copyable JSON/markdown/raw artifact panels

### Toast system

The previous custom toast renderer was replaced with a `sonner`-backed bridge.

Important detail:

- `useToast().pushToast({ title, description, variant })` was preserved
- page logic did not need to change to adopt the new toast system

## Page-Level Refactor Summary

### App shell

`frontend/components/layout/app-shell.tsx`

- navigation now uses shadcn button variants more consistently
- jump-to-job input now uses shadcn `Input`

### Home page

`frontend/app/page.tsx`

- hero remained custom to preserve branding
- surrounding layout now aligns with the updated shared card system

### New Analysis page

`frontend/app/analysis/new/page.tsx`

- input-mode selector now uses shadcn `ToggleGroup`
- form fields now use shadcn `Input` and `Label`
- boolean options now use shadcn `Checkbox`
- form errors now use `InlineNotice`
- submission logic and validation behavior were preserved

### History page

`frontend/app/analysis/history/page.tsx`

- bespoke loading, empty, and error presentation replaced with shared state components
- table behavior remains unchanged

`frontend/app/analysis/history/data-table.tsx`

- pagination layout cleaned up
- unused `SelectGroup` import removed
- spacing moved toward shared gap-based layout conventions

### Job detail page

`frontend/app/analysis/[jobId]/page.tsx`

- progress display now uses the shared progress primitive
- notices now use `InlineNotice`
- status and timeline presentation is more consistent
- polling, refresh, and job-state logic were preserved

### Raw artifacts page

`frontend/app/analysis/[jobId]/raw/page.tsx`

- manual tab switcher replaced with shadcn `Tabs`
- repeated raw artifact surfaces moved onto `ArtifactPanel`
- metrics and audit sections now use a more consistent shared presentation layer

### Report page

`frontend/app/analysis/[jobId]/report/page.tsx`

- anchor navigation now uses shadcn button styling
- repeated inset surfaces now use shadcn-aligned cards
- forensic report structure and content mapping were preserved

## Components Intentionally Kept Custom

Some components remain custom by design because there is no exact shadcn replacement or because the UI is domain-specific.

Remaining non-shadcn components include:

- `KeyValueGrid`
  - semantic definition-list output is still the best fit

- `BulletList`
  - forensic evidence lists are domain-specific and lightweight

- `AppShell`
  - application-specific layout, now composed with shadcn primitives

- home page hero section
  - branding-specific, not a reusable registry component

- report-specific evidence and inset compositions
  - still custom, but now built on shadcn cards/buttons/badges rather than ad hoc surfaces

## Verification

Checks run after implementation:

```bash
npm run lint
npm run build
```

Current verification result:

- `npm run build` passes
- `npm run lint` passes with one existing warning from TanStack Table / React Compiler compatibility in `app/analysis/history/data-table.tsx`

The warning is:

- `react-hooks/incompatible-library` for `useReactTable()`

This is a warning, not a failing build or runtime error.

## Net Effect

This refactor improved:

- UI consistency
- shared component reuse
- maintainability of state and feedback surfaces
- alignment with shadcn/ui conventions
- clarity of page-level composition

without introducing a broad rewrite of unrelated application logic.
