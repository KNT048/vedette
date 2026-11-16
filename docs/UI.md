# UI standard (web app)

The one standard for every screen of `web/` (#842). Order of work: this page → one independent review → shared components
built once in `web/src/components/` → Devices as the reference page (light, dark, phone screenshots to kien) → other pages
in groups → dashboard (#825). A page never styles itself; it composes the components named here. `docs/FRONTEND.md` keeps
the stack, voice and anti-"AI look" checklist; on visuals this page wins. **exists** = use as is, **fix** = change named
here, **build** = new, name given.

## 1. Tokens (`web/src/index.css`)

**Colour.** The #827 brand adds no colour: the palette is the theme tokens. One accent (Vedette green), four status tones with
fixed meaning, always with words. Use the Tailwind names (`bg-surface`, `text-muted`…), never a value.

| Token | Light | Dark | Use |
|---|---|---|---|
| `paper` | `#f8f9f7` | `#11181b` | page background |
| `surface` | `#ffffff` | `#172125` | sidebar, cards, tables, dialogs, popovers |
| `sunken` | `#f1f3f0` | `#0d1416` | table header, hover row, code |
| `ink` / `muted` | `#18211d` / `#56615c` | `#e3eae7` / `#9aa7a2` | text / secondary text |
| `rule` | `#dfe3df` | `#263338` | dividers and card edges (decoration only) |
| `control` **build** | `#848e89` | `#64716c` | edge of inputs, selects, checkboxes, switches off |
| `accent` (+`-ink`, `-soft`) | `#1d5a45` | `#6bbe9c` | primary button, active nav and tab, links, illustrations |
| `danger` / `warn` / `ok` / `off` (+`-soft`) | `#b42318` `#9a5b06` `#3b6b1e` `#5a635f` | `#f2857a` `#e7a748` `#97c977` `#8e9893` | confirmed or urgent / needs a look / fine or handled / off or unknown |
| `focus` | `#1d5a45` | `#6bbe9c` | focus ring |

The signal amber `#e7a748` is the logo dot only (`SIGNAL` in `components/brand/Logo.tsx`). `control` is new because `rule`
on `surface` is 1.3:1, below the 3:1 that WCAG 1.4.11 asks of a field's edge; Vercel Geist splits its scale the same way
(backgrounds, borders, text: [Geist colors](https://vercel.com/geist/colors)).

**Contrast**, computed with the WCAG formula (AA: text 4.5:1, UI edges and focus 3:1). `app/toastContrast.test.ts` checks two
pairs from the CSS; **fix**: extend it to every pair below.

| Pair | Light | Dark | Pair | Light | Dark |
|---|---|---|---|---|---|
| ink on paper / surface / sunken | 15.6 / 16.5 / 14.8 | 14.7 / 13.4 / 15.2 | muted on paper / surface / sunken | 6.1 / 6.4 / 5.8 | 7.2 / 6.6 / 7.5 |
| accent on surface / paper | 8.1 / 7.7 | 7.4 / 8.1 | accent-ink on accent (primary button) | 8.1 | 8.3 |
| ink on accent-soft (active nav) | 13.9 | 11.5 | muted on any `-soft` (Notice line) | ≥ 5.4 | ≥ 5.5 |
| danger on surface / danger-soft | 6.6 / 5.7 | 6.6 / 6.1 | white / paper on danger (solid chip, counter) | 6.6 | 7.2 |
| warn on surface / warn-soft | 5.4 / 4.8 | 7.8 / 6.6 | ok on surface / ok-soft | 6.4 / 5.6 | 8.5 / 7.3 |
| off on surface / off-soft | 6.2 / 5.4 | 5.5 / 4.9 | focus on paper / surface / accent-soft | 7.7 / 8.1 / 6.8 | 8.1 / 7.4 / 6.3 |
| control on surface / paper / sunken | 3.4 / 3.2 / 3.0 | 3.2 / 3.5 / 3.7 | rule on surface (not for controls) | 1.3 | 1.3 |

**Type.** Be Vietnam Pro 400/500/600; JetBrains Mono only in `CodeBlock`, logs and the CVSS vector. Six named sizes, added to
`@theme` (**build**) so `text-[13px]` (853 arbitrary sizes in `features/`) becomes a name; Geist names its text styles the same way
([Geist typography](https://vercel.com/geist/typography)), and Primer keeps 12 px as the floor ([Primer typography](https://primer.style/product/getting-started/foundations/typography/)).

| Class | Size / line | Use |
|---|---|---|
| `text-caption` | 12 / 16 | chips, counters, table header, nav group label |
| `text-meta` | 13 / 20 | the header line, hints, secondary cell text, InfoTip text, CVSS line |
| `text-sm` | 14 / 20 | body, table cells, buttons, nav |
| `text-base` | 16 / 24 | section and dialog title; inputs on phones (no iOS zoom) |
| `text-lg` | 18 / 28 | KPI number |
| `text-xl` | 20 / 28 | page title (`h1`), 600, tracking -0.01em; 11, 11.5, 12.5 and 15 px go (codemod to the nearest) |

**Spacing**: the Tailwind 4 px scale only (layout uses 2, 3, 4, 5, 6, 8, 10; half steps inside components), no arbitrary
values, numbers `tabular-nums` ([Primer spacing](https://primer.style/product/primitives/spacing/)). **Radius**, three levels by role, not one for
everything: `rounded-sm` 4 px chips; `rounded-md` 6 px buttons, inputs, cards, tables, Notice; `rounded-lg` 8 px dialogs,
popovers, menus (**fix** `dialog.tsx`, `InfoTip`, `dropdown-menu.tsx`); `rounded-full` counters and the ⓘ. **Shadow**: none on
anything in the page (edges are `rule` borders); `shadow-md` popovers and menus, `shadow-lg` dialogs. In dark, overlays keep
the border because shadows barely show ([Material elevation](https://m3.material.io/styles/elevation/overview)).
**Motion**: 150 ms ease-out, only in answer to an action (open, expand); none on load; `prefers-reduced-motion` is honoured globally.

## 2. App shell (`app/Layout.tsx` frame; **build** `components/shell/Sidebar.tsx` with `NavGroup` and `useNavState`)

Decisions from #842. Patterns: collapsible sections ([Atlassian navigation](https://atlassian.design/components/navigation-system)),
groups ([Primer NavList](https://primer.style/product/components/nav-list/)), icon rail and drawer ([Material rail](https://m3.material.io/components/navigation-rail/overview),
[drawer](https://m3.material.io/components/navigation-drawer/overview)), a quiet dense sidebar ([Linear redesign](https://linear.app/now/how-we-redesigned-the-linear-ui)).

- **Order**: logo and org; **Home**, **Findings** always visible, never in a group; then the groups **Assets** (Devices, External
  exposure, Vulnerability scans), **Intrusion detection** (Internal traps, Logs, Incidents), **Assistant and reports** (AI
  assistant, Reports, Lookup); at the bottom **Settings**, the user menu and the running version. Where the Monitor items go: question 1.
- **Groups**: the header is a button (`aria-expanded`, chevron); a click opens or closes it. The group holding the current page
  opens by itself without overwriting the saved state. Open groups and the rail choice are saved per user in `localStorage`
  (`vedette.nav.<userId>`, reads and writes in try/catch; on failure all groups closed but the current one).
- **Badges stay visible**: a `NavItem` gets an optional `useBadge()` hook (**build** in `app/feature.ts`) returning
  `{ count, label }`, e.g. Devices "To review 15". A closed group shows the sum on its header; in the rail it is a counter on
  the icon. Red only for work that waits for the user (same rule as tabs); the screen reader hears "Devices, 15 to review".
- **Rail**: from `lg`, "Collapse menu" (`aria-pressed`) at the foot shrinks 240 px to 56 px; groups flatten into icons split
  by a rule, each with a `Tooltip` (**build** `components/ui/tooltip.tsx`, Radix, in `radix-ui`); the logo becomes the mark.
- **Below `lg`**: a 56 px top bar (menu button, logo) and the same `Sidebar` in a left drawer, 288 px wide, max 85 vw, closed on
  navigation and Esc, focus trapped (**build** `DrawerContent` in `components/ui/dialog.tsx`; replaces the class override in Layout).
- Active item: `bg-accent-soft`, `font-medium`, icon in `accent`; 36 px tall, 40 px on phones; Preview keeps `ScopeBadge`.

## 3. Page frame (`PageHeader`, `KpiStrip`, `PageTabs`: exist; **build** `components/common/Breadcrumbs.tsx`)

- Content: max 1280 px, gutter 16 / 24 / 40 px (base / `sm` / `lg`), top 24 / 32 px (exists in Layout). Order (D-464):
  breadcrumbs → `PageHeader` → at most one page `Notice` → `KpiStrip` (≤ 4) → `PageTabs` → content; 20 px under each, 24 px
  between sections.
- `PageHeader`: `h1` + one short line (`meta`) + ⓘ (`info`) on the left, actions on the right (one primary at most), wraps under
  on phones ([Primer PageHeader](https://primer.style/product/components/page-header/)).
- Breadcrumbs on every detail page, above the title, parents only ("Devices ›"), `text-meta` muted, `nav aria-label="Breadcrumb"`;
  the `h1` names the current page ([Atlassian page header](https://atlassian.design/components/page-header)).

## 4. Tabs (`PageTabs` exists; `components/ui/tabs.tsx` is private to it, guard in `PageFrame.test.tsx`)

Underline style, 2 px `accent` under the open tab, label `text-sm`, open tab `font-medium ink`. Counts as a `Counter`. Tab in
`?tab=`, replace history, arrows/Home/End ([APG tabs](https://www.w3.org/WAI/ARIA/apg/patterns/tabs/)). Narrow screens: the
row scrolls sideways inside itself and the open tab scrolls into view; it never wraps and never becomes a select (Material's
scrollable tabs: [tabs](https://m3.material.io/components/tabs/guidelines)). At most 6 tabs, one or two words each.
`Segmented` (exists) is for filters, never for sections.

## 5. Card and table

- **Card** = `Panel` (exists in `PageHeader.tsx`; **fix**: add `p-4` default and an optional `title`/`actions` row,
  `text-base` 600): `rule` border, `rounded-md`, `surface`, no shadow. No card in a card. Lists of things are tables, not a
  grid of identical cards. `Section` (exists) is a titled block without a box.
- **Table** = `DataTable` (exists): header 36 px, `text-caption` muted on `sunken`, sticky; rows 40 px, `rule` between,
  hover `sunken` only when the row opens something; the row's first cell holds a real link (keyboard), the row click is a
  pointer shortcut; risk bar 3 px inset left (danger, warn); numbers right-aligned; 50 rows a page with `Pager` (exists).
  Phones: `mobileRow` list (required over 3 columns); anatomy as [Primer DataTable](https://primer.style/product/components/data-table/).

## 6. Empty state (`EmptyState` exists; **fix**: `art` prop; **build** `components/common/Illustration.tsx`)

- Nothing exists yet (first run, no devices, no findings): centred, illustration 180×120 (120×80 on phones) in `text-accent`,
  title, one line, one action ([Primer empty states](https://primer.style/product/ui-patterns/empty-states/),
  [Blankslate](https://primer.style/product/components/blankslate/)).
- A filter or search finds nothing: text only, inside the table ("No devices match. Clear filters").
- Illustrations (`web/src/assets/illustrations/`, #827): `no-devices` Devices, `no-findings` Findings and Plan (good news),
  `no-alerts` Incidents, `scanning` a running first scan, `welcome` and `setup-done` first-run setup; inline via `?raw`, `aria-hidden`, never `<img>`.

## 7. Chip, counter, badge; risk with its CVSS line

- `Chip` (exists, `StatusChip.tsx`; **fix**: a `shape` of `solid`, `soft`, `dashed`): 24 px, `rounded-sm`, `text-caption` 500.
  Meaning is the tone plus the shape, always with words: **solid** danger = confirmed and Critical; **dashed** warn =
  suspected; **soft** for the rest (High danger, Medium warn, handled ok, Low/Info/off off). Today Critical and High look the
  same and Medium borrows the "suspected" dash; the fix separates them.
- `Counter` (**build** `components/common/Counter.tsx`, taken out of `PageTabs`): pill, `text-caption` 600, "99+" cap, `danger`
  when work waits for the user, `off` for a plain count, words for screen readers inside; used by tabs, nav, KPI ([Primer CounterLabel](https://primer.style/product/components/counter-label/)).
- **Risk + CVSS**: Vedette's risk chip (`RiskChip` → `SeverityChip`) first; under it, in a list cell, or after it on the
  finding page, the line **CVSS 9.8 Critical ⓘ** (`text-meta`; score 600 tabular; band word in danger/warn/muted). The ⓘ holds
  version, vector, source and the FIRST credit. No score → "No score ⓘ", never 0. CVSS never replaces the risk chip: Tenable
  shows its own VPR as the companion of CVSS the same way ([Tenable CVSS vs VPR](https://docs.tenable.com/vulnerability-management/Content/Explore/Findings/RiskMetrics.htm));
  bands from [FIRST CVSS](https://www.first.org/cvss/v3.1/specification-document). Component: `CvssScore`
  (`features/findings/Cvss.tsx` on the CVSS branch; **fix**: move to `components/common/Cvss.tsx` when it merges, since
  Devices and Exposure show CVEs too).

## 8. Notice, form, dialog

- `Notice` (exists): page or section state; tones danger, warn, accent, off; title + one line + ⓘ + actions. `ScopeBadge`
  (exists): Preview / not in v1.
- **Field** (`Field`, `Input`, `Select`, `Textarea`, `Checkbox`, `RadioGroup`, `Switch`: exist in `components/ui/`; **fix**:
  edges use `control`): label above (`text-sm` 500), control 40 px phone / 36 px desktop, hint one line `text-meta` muted,
  error under the control in `danger` linked by `aria-describedby`, `aria-invalid`. Explanations go behind the label's ⓘ
  (Material keeps helper text to one line: [text fields](https://m3.material.io/components/text-fields/guidelines)). One
  column, max 576 px; two short fields side by side from `md` only. Mark the fewer: "(optional)" when most fields are required.
  Primary action at the end of the form, left-aligned with the fields ([Primer forms](https://primer.style/product/ui-patterns/forms/)).
- **Button** (exists): one `primary` per region; `secondary` default; `ghost` in toolbars; `danger` for destructive verbs;
  icon-only buttons have `aria-label` and a `Tooltip`. Labels are verbs ("Remove device"), no trailing arrows.
- **Dialog** (`DialogContent`, `DialogFooter`: exist): 512 px, `wide` 768 px, full width minus 32 px on phones; title
  `text-base` 600, one-line description, ⓘ; footer right-aligned, primary last; Esc and the 40/32 px close; focus returns to
  the opener. A form of more than about 6 fields, or one the user may leave half done, is a page, not a dialog
  ([Primer Dialog](https://primer.style/product/components/dialog/)). Destructive confirms name object and verb, never "Are you sure?".

## 9. Guidance behind ⓘ (`InfoTip` exists, #824)

Every section, dialog, field and empty state shows a title and at most one short line (about 12 words). How it works, why,
examples, edge cases and legal detail go behind an ⓘ next to the title or label: click, Enter or Space opens it, Esc or a click
outside closes it, the text is the button's description. Always visible (one line, detail behind ⓘ): warnings that prevent
harm, errors, status, legal text the TERMS require on screen, the "AI-generated" label. Pass it through `info` on `PageHeader`,
`Section`, `Notice`, `DialogContent`, `Field`, `EmptyState`; no page writes its own help paragraph. `Tooltip` is for the name of
an icon, `InfoTip` for an explanation; never both on one control ([WCAG 1.4.13](https://www.w3.org/WAI/WCAG22/Understanding/content-on-hover-or-focus.html)).

## 10. Long jobs (`JobProgress` exists, `components/progress/`, #834)

Any job the box reports progress for (scan, public-IP scan; later feed sync, backup, update) shows `JobProgress` inline where
it was started (the row or the card), never in a modal or a toast: the step in words, a determinate bar with percent or a
sliding one, "3 of 8 checks", elapsed, "about 4 min left in this step", the pass note, a neutral "Last report 45 s ago ⓘ"
when quiet. `Loading` (`States.tsx`) only for waits under about 5 s with nothing to report.

## 11. Breakpoints, phone, keyboard

Below 640 px (base): top bar + drawer, tables as `mobileRow`, buttons 40 px, inputs 16 px text. 640–1023 (`sm`, `md`): top
bar + drawer, tables scroll inside their card. From 1024 (`lg`): sidebar 240 px or rail 56 px. Check at 360, 390, 768, 1024 and 1440 px, light and dark: no sideways scroll of the page, ever
([Tailwind breakpoints](https://tailwindcss.com/docs/responsive-design)). Keyboard: "Skip to content" first (exists); every
action reachable by Tab in visual order; focus ring 2 px `focus`, offset 2 (contrast above); groups are disclosure buttons
([APG disclosure](https://www.w3.org/WAI/ARIA/apg/patterns/disclosure/)); dialogs and the drawer trap focus and give it back;
targets 24 px minimum on desktop, 40 px on phones ([WCAG 2.5.8](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html)).
Status is never colour alone (words, shape). axe runs in the component tests (exists).

## 12. Keeping it standard: the style guard (**build** `web/src/test/styleGuard.test.ts`, not yet)

A vitest guard, like the `ui/tabs` import guard in `PageFrame.test.tsx`: it reads every `src/features/**/*.{ts,tsx}` (not
tests) and fails on (1) colour literals: `#rgb`, `#rrggbb`, `rgb(`, `hsl(`, `oklch(`; (2) Tailwind palette colours
(`bg-red-500`, `text-white`, `border-black`…); (3) arbitrary values in colour, spacing, font size, radius or shadow utilities
(`text-[13px]`, `p-[7px]`, `rounded-[4px]`, `shadow-[…]`, `bg-[…]`); (4) `style={{…}}` setting colour, background, margin,
padding or font size. Allowed: layout values (`grid-cols-[minmax(0,1fr)…]`, `max-w-[…]`), `components/`, `index.css`. Not
oxlint: it has no Tailwind class rule, and an ESLint Tailwind plugin is a second linter; the guard needs no dependency and
runs in PR CI with the web tests. Migration: a per-file baseline that may only go down. Today `features/` has 0 colour
literals, 0 palette colours, 853 arbitrary font sizes, 5 other arbitrary values. (Wiz and Falcon docs are behind sign-in, so
no choice here cites them.)

## 13. Open questions for kien

1. #842 keeps Home and Findings always visible but does not place **Updates to plan**, **Incidents**, **Lookup** (now "Monitor").
   Proposed: Updates to plan always visible under Findings (J5's answer); Incidents in Intrusion detection; Lookup in
   Assistant and reports. OK?
2. **Settings** as a collapsing group would repeat the Settings page's own menu (D-519). Proposed, as Linear and GitHub do: one
   Settings entry at the foot of the sidebar, its sections in its own menu. OK?
3. Severity: Critical solid red, High soft red, Medium soft amber, no fifth colour (the word carries the level). OK, or two
   colours for Critical and High, as [Tenable](https://docs.tenable.com/vulnerability-management/Content/getting-started/VulnerabilitySeverityIndicators.htm) and Wiz do?
