# Frontend: friendly and plain

Good GUI first; friendly to the people who use it.

## 1. Stack

React 19 + TypeScript (strict) + Vite + Tailwind v4 + shadcn/ui (Radix) + TanStack Query v5/Table v8 + React Router + react-i18next (English only) + Zod (API schemas) + MSW (mock API for M0/M1) + vitest + Testing Library + Playwright (E2E) + axe-core (a11y in tests). pnpm. No Next.js, no SSR: a SPA embedded in the Go binary.

## 2. Who uses it, and when

P2 opens it for 2 minutes every morning and when there is an alert; P1 only reads Zalo and occasionally opens a report; P3 looks at the overview table. So: **dense, calm information in plain language**, no "wow", and chat is not the centre. The AI appears **in context** (an "Explain" button on a finding), with a source label and tokens, with no floating chat box.

## 3. Design direction (decisions, not suggestions)

- **Visual standard (colour, type, spacing, corner radius, shadow, app frame, menu, components, motion, contrast)**: `docs/UI.md`, the only place that records the visual rules (#842). When this document and UI.md differ, UI.md wins. Kept here: four status colours with a fixed meaning that always come with text, no gradient/glass/purple/sparkle, one green accent colour.
- **Page frame (S-UI-1; the shape is in `docs/UI.md` §3-4)**: every page in the main menu follows one order: `PageHeader` (a ~20 px heading and a short description on one line) → an optional `KpiStrip` (at most 4 cells: number, label, link; only when the number is the answer) → `PageTabs` when the page has more than one part (a horizontal tab row, the open tab in `?tab=<id>`, changing tab replaces the history entry, a tab with work waiting for the user carries a red number plus a phrase for screen readers; on a phone the tab row scrolls inside itself). All three are in `web/src/components/common/{PageHeader,PageFrame}.tsx`; a module does not build its own tabs or number cards, and does not store the tab in `#hash`. A long page with many independent sections (≥ 4) is split into tabs. When `PageTabs` is used: a tab that the role may not see is **left out** of `tabs` (not drawn and then hidden); a lazy panel (`lazy`) gets its own `Suspense` each; a red number only for work that needs the user at once; a parameter that belongs to one tab (for example `?run=` of Scans) **is kept** when the tab changes (`PageTabs` only sets `tab`), so other tabs must ignore a parameter that is not theirs. When moving an old page into the frame: old links (`#hash`, old paths) must redirect to the right `?tab=`, keep the other parameters, and catch only the old names (another hash such as `#main` of the "Skip to content" link is left alone). Settings keeps its vertical menu (many short forms; like Grafana, GitLab admin); a Settings section or admin page with ≥ 4 separately saved areas gets a `PageTabs` row inside it (Box network, My account, `/devices/setup`), and a page that answers one question stays one page (Updates); old `#hash` links go through `OldHashToTab` (`PageFrame.tsx`). Below `lg` the Settings menu is a horizontal row in the same style as the tab row.
- **One style for the whole app**: a page's status frame is `Notice` (`PageHeader.tsx`, `tone` danger/warn/accent/off with the colour meanings above); do not draw `rounded-md border border-danger/40 …` in a module; the tab row goes only through `PageTabs` (a test in `PageFrame.test.tsx` blocks importing `components/ui/tabs` from `features/`).
- **Language**: clear verbs ("Send test", "Apply", "Mark as handled"); an error says what is wrong and how to fix it; an empty screen is guidance for an action ("No devices yet. Turn on passive inventory or declare one by hand."); no "Oops", no emoji in the UI, no all-caps labels, no eyebrow labels, no "→" at the end of a button.
- **Information hierarchy**: every page answers one persona question on its first line ("Today: 2 new findings, 1 confirmed"). A big number only when it is the answer, never decoration.
- **Visible confidence**: all data has a "source" and an "updated at"; "confirmed" / "suspected" are two chips of different shape (not only different colour); AI data has a dotted border + the label "AI generated".

## 4. Avoid a generic template look: review checklist

A screen fails review if it has: a cream background + serif + terracotta orange; black + one neon colour; identical cards in a grid with grey shadows; an ALL-CAPS eyebrow on every heading; "A · B · C" strings; "WORD — fragment" headings; mono type for labels; "→" at the end of a link; a hero with a big number + gradient; fade-slide-up on every section; emoji used as icons; a floating chat box; the words "AI-powered" or "smart" in copy. Every frontend PR lists the result of this checklist in its description.

## 5. Tooling

| Tool | Use |
|---|---|
| TypeScript strict + Zod | typed UI, API schemas shared between UI, mocks and OpenAPI |
| vitest + Testing Library | component and behaviour tests |
| axe-core (in vitest and Playwright) | accessibility checks, including colour contrast in the real browser |
| Playwright | E2E on the real build, screenshots for visual review |

Each screen goes through: plan → build → critique (with a screenshot, against the checklist in §4 and the accessibility checks) → fix.

## 6. a11y, i18n, responsive

- WCAG 2.2 AA: contrast ≥4.5:1, visible focus, full keyboard navigation, tables with headers, status with text. axe runs in vitest for every page.
- i18n: every string goes through `t()`; English only, simple, concrete wording, sentence case; numbers/dates in en-GB; no string concatenation.
- Responsive: desktop is the main target; tablet is readable; mobile: the home page + findings + alerts are readable, with no required actions.

## 7. Structure of `web/`

```
web/src/
  app/            router, layout, providers
  features/<module>/   pages, components, hooks, api (1 folder per module; module off = route not mounted)
  components/ui/  shadcn
  components/common/  StatusChip, SourceBadge, AiBadge, EmptyState, ErrorState, DataTable
  lib/            api client (OpenAPI → types), i18n, format
  mocks/          MSW handlers + fixtures (M0/M1)
  test/
```

Each `features/<module>` has a `README.md` naming the story IDs it serves.
