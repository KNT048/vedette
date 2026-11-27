# UI standard (web app)

The one standard for every screen of `web/` (#842). Order of work: this page → one independent review → shared
components built once in `web/src/components/` and `web/src/app/` → Devices as the reference page (light, dark, phone
screenshots) → other pages in groups → dashboard (#825). Done for each step = before/after screenshots of every
top-level page in the PR, checked on a real box. A page never styles itself; it composes the components named here.
`docs/FRONTEND.md` keeps the stack, voice and generic-look checklist; every visual rule lives here.
**exists** = use as is, **fix** = change named here, **build** = new, name given.

## 0. Customer ease first: every page follows these (on the #849 drafts)

Convenience is the first rule of the UI: in 2026 no product sends its customer somewhere else, unguided, to do a second task
before the first one can go on.

1. **Do it where you are.** When a step needs something that does not exist yet (an SNMP credential, a scope or LAN range, an
   alert channel, an agent or enrol token, an API key, a user…), the customer creates it right there: the select's last option
   "+ New …" opens a small dialog, saves, and the new item is selected (`CreatableSelect`, §8). The same item stays editable on
   its own page. Never "go to Settings first", never a dead end without a link. As Atlassian's creatable select
   ([Select](https://atlassian.design/components/select/examples#creatable-select)), Linear's label picker that creates the
   label you type ([Labels](https://linear.app/docs/labels)) and Vercel's project import that takes the environment variables
   in the same form ([Environment variables](https://vercel.com/docs/projects/environment-variables)).
2. **Need → place → action is obvious.** Each customer need has one clear place to start. Every dependency that cannot be
   created inline links straight to the exact tab and field (`DependencyLink`: one short reason + a link to
   `/settings/<section>?tab=<tab>#<field-id>`, the field gets focus on arrival), never "see Settings". As GOV.UK's error
   summary links each problem to its field ([Error summary](https://design-system.service.gov.uk/components/error-summary/)).
3. **No action with nothing behind it** (the box offered "Fix by updating the operating system" with no
   update to install). A link, button, banner, dialog or count is shown only when there is something to act on: "Install N
   updates" only at N > 0, "Fix by updating" only when an update fixes an open finding, no "Select all 0", no link a role cannot
   open, no action on a closed item. When work remains but nothing fixes it yet, one honest line says so ("No update fixes these
   yet: see each finding") instead of a dead link. A KPI of 0 is plain text (`KpiStrip`). Findings closed as not relevant are
   hidden wherever findings are listed, with one toggle "Show not relevant (N)" (`NotRelevantToggle`, `?notrelevant=show` on the
   Findings list); counts next to them leave them out. Guard: `web/src/test/emptyActionGuard.test.ts` fails on a `<Link>` or
   `<Button>` whose label states a count that nothing near it checks (named exceptions: `empty-guard:` and `ALLOWED`).
4. **Review check for every page** (§13): list each dependency the page needs; each one is created inline or deep-linked.

## 1. Tokens (`web/src/index.css`)

**Colour.** The #827 brand adds no colour: the palette is the theme tokens. One accent (Vedette green), four status tones with
fixed meaning, always with words. Use the Tailwind names (`bg-surface`, `text-muted`…), never a value.

| Token | Light | Dark | Use |
|---|---|---|---|
| `paper` | `#f8f9f7` | `#11181b` | page background |
| `surface` | `#ffffff` | `#172125` | sidebar, cards, tables, dialogs, popovers, switch thumb |
| `sunken` | `#f1f3f0` | `#0d1416` | table header, hover row, code |
| `ink` / `muted` | `#18211d` / `#56615c` | `#e3eae7` / `#9aa7a2` | text / secondary text; `muted` also edges checkboxes and radios |
| `rule` | `#dfe3df` | `#263338` | dividers and card edges (decoration only) |
| `control` **build** | `#848e89` | `#64716c` | edge of inputs, selects, textareas; switch track when off |
| `accent` (+`-ink`, `-soft`) | `#1d5a45` | `#6bbe9c` | primary button, active nav bar and tab, links, illustrations |
| `danger` / `warn` / `ok` / `off` (+`-soft`) | `#b42318` `#9a5b06` `#3b6b1e` `#5a635f` | `#f2857a` `#e7a748` `#97c977` `#8e9893` | confirmed or urgent / needs a look / fine or handled / off or unknown |
| `focus` | `#1d5a45` | `#6bbe9c` | focus ring |

The signal amber `#e7a748` is the logo dot only (`SIGNAL` in `components/brand/Logo.tsx`). `control` is new because `rule`
on `surface` is 1.3:1, below the 3:1 that WCAG 1.4.11 asks of a field's edge; Vercel Geist splits its scale the same way
(backgrounds, borders, text: [Geist colors](https://vercel.com/geist/colors)). Each token is set in all three blocks of
`index.css` (light, `[data-theme=dark]`, dark by system).

**Contrast**, computed with the WCAG formula (AA: text 4.5:1, UI edges, indicators and focus 3:1). **Build**
`app/tokenContrast.test.ts`: it reads the three blocks and checks every pair below (it replaces the two pairs of `toastContrast.test.ts`).

| Pair | Light | Dark | Pair | Light | Dark |
|---|---|---|---|---|---|
| ink on paper / surface / sunken | 15.6 / 16.5 / 14.8 | 14.7 / 13.4 / 15.2 | muted on paper / surface / sunken | 6.1 / 6.4 / 5.8 | 7.2 / 6.6 / 7.5 |
| accent on surface / paper | 8.1 / 7.7 | 7.4 / 8.1 | accent-ink on accent (primary button) | 8.1 | 8.3 |
| ink on accent-soft (active nav) | 13.9 | 11.5 | accent on accent-soft (Preview chip, active icon) | 6.8 | 6.3 |
| muted on any `-soft` (Notice line) | ≥ 5.4 | ≥ 5.5 | warn on warn-soft at 60 % (dashed chip) | 5.1 | 7.2 |
| danger on surface / danger-soft | 6.6 / 5.7 | 6.6 / 6.1 | white (light) / paper on danger (solid chip, counter) | 6.6 / 6.2 | 7.2 |
| warn on surface / warn-soft | 5.4 / 4.8 | 7.8 / 6.6 | ok on surface / ok-soft | 6.4 / 5.6 | 8.5 / 7.3 |
| off on surface / off-soft | 6.2 / 5.4 | 5.5 / 4.9 | focus on paper / surface / accent-soft | 7.7 / 8.1 / 6.8 | 8.1 / 7.4 / 6.3 |
| control on surface / paper / sunken | 3.4 / 3.2 / 3.0 | 3.2 / 3.5 / 3.7 | switch thumb (surface) on accent / control | 8.1 / 3.4 | 7.4 / 3.2 |
| active nav bar, selected segment edge (accent on surface) | 8.1 | 7.4 | not allowed: rule on surface 1.3, accent-soft on surface 1.2, white thumb on dark accent 2.2 | | |

A fill of `accent-soft` alone (1.2:1) never marks a state: the active nav item adds a 3 px `accent` leading bar, a selected
segment an `accent` edge (Primer NavList marks the current item the same way: [NavList](https://primer.style/product/components/nav-list/)).

**Type.** Be Vietnam Pro 400/500/600; JetBrains Mono only in `CodeBlock`, logs and the CVSS vector. Six named sizes. The
tokens PR adds `text-caption` and `text-meta` to `@theme` and teaches tailwind-merge their names in `lib/utils.ts`
(`extendTailwindMerge({ extend: { theme: { text: ['caption', 'meta'] } } })`, unit test `lib/utils.test.ts`), or `cn()`
reads them as colours and drops them. The codemod PR (§12) then resets the namespace (`--text-*: initial`) and redefines
exactly these six, so `text-2xl` and the rest stop existing. Names as in [Geist typography](https://vercel.com/geist/typography);
12 px is the floor as in [Primer typography](https://primer.style/product/getting-started/foundations/typography/).

| Class | Size / line | Use |
|---|---|---|
| `text-caption` | 12 / 16 | chips, counters, table header, nav group label |
| `text-meta` | 13 / 20 | the header line, hints, errors, secondary cell text, InfoTip text, CVSS line |
| `text-sm` | 14 / 20 | body, table cells, buttons, nav |
| `text-base` | 16 / 24 | section, card and dialog title; inputs on phones (no iOS zoom) |
| `text-lg` | 18 / 28 | KPI number |
| `text-xl` | 20 / 28 | page title, only through the `page-title` utility (**build**, `@utility` in index.css: xl, 600, -0.01em) |

**Spacing**: the Tailwind 4 px scale only (layout uses 2, 3, 4, 5, 6, 8, 10; half steps inside components), no arbitrary
values, numbers `tabular-nums` ([Primer spacing](https://primer.style/product/primitives/spacing/)). **Radius**, three levels
by role: `rounded-sm` 4 px chips, checkboxes, segments; `rounded-md` 6 px buttons, inputs, cards, tables, Notice;
`rounded-lg` 8 px dialogs, popovers, menus, tooltips (**fix** `dialog.tsx`, `InfoTip`, `dropdown-menu.tsx`); `rounded-full`
counters, switches and the ⓘ. **Shadow**: none on anything in the page (edges are `rule` borders); `shadow-md` popovers,
menus, tooltips, `shadow-lg` dialogs and the drawer. In dark, overlays keep the border because shadows barely show
([Material elevation](https://m3.material.io/styles/elevation/overview)). **Motion**: 150 ms ease-out, only in answer to an
action (open, expand); none on load; progress fills may ease over 700 ms (`JobProgress`); `prefers-reduced-motion` honoured globally.

## 2. App shell (`app/Layout.tsx`; **build** `app/Sidebar.tsx`, `app/nav.ts`; one caller, so in `app/`, not `components/`)

Decisions from #842. Patterns: collapsible sections ([Atlassian navigation](https://atlassian.design/components/navigation-system)),
groups ([Primer NavList](https://primer.style/product/components/nav-list/)), icon rail and drawer ([Material rail](https://m3.material.io/components/navigation-rail/overview),
[drawer](https://m3.material.io/components/navigation-drawer/overview)), a quiet dense sidebar ([Linear redesign](https://linear.app/now/how-we-redesigned-the-linear-ui)).

- **Order**: logo and org; the always-visible block **Home**, **Findings**, **Recommended updates** (was "Updates to plan"), **Incidents** (decided
  2026-11-16: "the alert arrives" is a core user journey, and Wiz and CrowdStrike keep Issues and Detections top-level); then the
  groups **Assets** (Devices, External exposure, Vulnerability scans), **Intrusion detection** (Internal traps, Logs),
  **Assistant and reports** (AI assistant, Reports, Lookup); at the foot the `shell.status` slot, **Settings** (one entry,
  decided 2026-11-16: its sections stay in its own menu, as Linear and GitHub do), the user menu (with the running
  version) and "Collapse menu". The placement is one table in `app/nav.ts`.
- **Groups**: a group with one visible item renders as that plain item (no header, no chevron); a group with none is not
  drawn ([Primer NavList](https://primer.style/product/components/nav-list/) groups related items, never one link). On a
  default v1 box (Preview modules off) Lookup is therefore a plain item and Intrusion detection is not drawn. A real group's header is a disclosure
  button (`aria-expanded`, chevron); the group holding the current page stays open (closing it would hide where you are), so its header is `aria-disabled` and
  says "holds this page". Groups are drawn only once `/modules` has answered (no header that turns into an item). First visit: every group closed except the one holding the current page, which opens by
  itself without overwriting the saved state. Open groups and the rail choice are saved per user in `localStorage`
  (`vedette.nav.<userId>`, reads and writes in try/catch; on failure the first-visit default).
- **Badges** come from one cheap read, `GET /findings/overview` (cached on the box, shared with Home through the same
  query key `['findings','model','overview']`, 60 s refresh, paused in a hidden tab). A plain selector table in `app/nav.ts` maps it to
  items: Findings ← the open findings of the four urgent statuses (`open.by_status`: under attack, exploited, public exploit,
  critical on an edge device), Incidents ← `incidents.urgent` ("high or critical open"); all urgent (red), as work waits for the
  user. An error stops the polling. No per-item hook and no list fetch in the shell. A closed group shows only the **urgent** total
  of its items; its accessible name starts with the visible text and then lists the parts ("Assets 15 waiting: Devices 15 to review"; no
  `aria-label` that would hide the visible label, WCAG 2.5.3). No summary (findings off, error): no badges.
- **Rail**: from `lg`, "Collapse menu" at the foot shrinks 240 px to 56 px (then "Expand menu"; the name always equals the tooltip); groups flatten into icons,
  each group a `role=group` with its own `aria-label` (not a `ul`: page tests query their page's one list), split by a rule. Every nav icon is unique (Internal traps moves from
  `ShieldAlert` to `Radar`). Each icon has a `Tooltip` (**build** `components/ui/tooltip.tsx`, Radix, in `radix-ui`) with the
  label, the badge words and "Preview" when it is one; the link keeps its label as `sr-only` text and the tooltip
  (`describe={false}`) is not its description, so nothing is read twice. One `TooltipProvider` in `App.tsx`. Focus rings of nav
  entries are drawn inside the entry (`-outline-offset-2`), so a group's clipping never cuts them. A badge is a counter on the icon's corner. The logo becomes the mark; the org name hides; the user
  menu is an icon button with a tooltip; the version lives inside the user menu. The column paints its background and rule the
  full page height at 56 px too (UI-4).
- **Below `lg`** (tablets included, a choice: no persistent nav under 1024 px): a 56 px top bar (menu button, logo, the
  `shell.status` slot on the right) and the same `Sidebar`, expanded, in a left drawer, 288 px, max 85 vw, focus trapped
  (**build** `DrawerContent` in `components/ui/dialog.tsx`; the menu button is its `DialogTrigger`). A header row holds the brand,
  the org and the ✕. A link click (user-menu entries too) closes it and focus goes to `#main` (as on every page change); Esc
  and ✕ return focus to the menu button.
- Active item: `aria-current`, `bg-accent-soft`, `font-medium`, 3 px `accent` leading bar, icon in `accent`; items 36 px tall,
  40 px in the drawer. Preview entries keep `ScopeBadge` (expanded) or "Preview" in the tooltip (rail).
- **`shell.status` slot**: a feature registers `slots: { 'shell.status': Component }` (existing `Slot`), rendered in the
  phone top bar and in the sidebar foot, with prop `compact` (rail, phone). #850's `ScansRunningIndicator` goes here. Both
  copies are mounted at every width (one hidden by CSS), so a slot component stays pure: query state only, no toasts or effects.
  Its icon must not be one the nav uses (`Radar` is Internal traps), and its compact form is named by `Tooltip`, not `title`.

## 3. Page frame (`PageHeader`, `KpiStrip`, `PageTabs`: exist; **build** `components/common/Breadcrumbs.tsx`)

- Content: max 1280 px, gutter 16 / 24 / 40 px (base / `sm` / `lg`), top 24 / 32 px (exists in Layout). Order:
  breadcrumbs → `PageHeader` (20 px under) → at most one page `Notice` (20 px) → `KpiStrip` (20 px) → `PageTabs` (panel 16 px
  under the row) → content; `Section`s 32 px apart. These are the values in the code today; none changes.
- `PageHeader`: `h1` (`page-title`) + one short line (`meta`) + ⓘ (`info`) on the left, actions on the right (one primary at
  most), wraps under on phones ([Primer PageHeader](https://primer.style/product/components/page-header/)). New prop
  `breadcrumbs` renders `Breadcrumbs` above the title.
- Breadcrumbs on every detail page, parents only ("Devices ›"), `text-meta` muted, `nav aria-label="Breadcrumb"` with an `<ol>`
  (correct semantics; page tests then scope their list queries, e.g. `within(main)`); the `h1`
  names the current page ([Atlassian page header](https://atlassian.design/components/page-header)).
- **Standalone pages** (sign-in, first-run setup, change password, SSO return, not found) sit outside the shell: **build**
  `components/common/StandalonePage.tsx`: centred column (`size` sm/md/lg), stacked logo, `h1` in `page-title` (sign-in: the logo is the h1), one `Card`,
  optional footer links; first-run steps may show the `welcome` / `setup-done` illustrations (GitHub and Vercel sign-in work
  this way). Sign-in adopts it with the shell; the setup pages move with the core page group.

## 4. Tabs and link rows (`PageTabs` exists; **build** `components/common/UnderlineNav.tsx`)

Two components, one look, as Primer splits UnderlineNav and UnderlinePanels ([UnderlineNav](https://primer.style/product/components/underline-nav/)):
`PageTabs` for panels of one page (`role=tablist`, `?tab=`, replace history, arrows/Home/End: [APG tabs](https://www.w3.org/WAI/ARIA/apg/patterns/tabs/));
`UnderlineNav` for links between pages (`aria-current="page"`; Settings: a row below `lg`, the vertical menu from `lg`).
`components/ui/tabs.tsx` stays private to `PageTabs` (guard in `PageFrame.test.tsx`). Underline 2 px `accent`
under the open item (the only mark of the open tab: a tab clicked with a pointer draws no focus ring, the keyboard still does), label `text-sm`, open item `font-medium ink`, counts as a `Counter`. Narrow screens: the row scrolls
sideways inside itself and the open item scrolls into view; it never wraps and never becomes a select (Material's scrollable
tabs: [tabs](https://m3.material.io/components/tabs/guidelines)). At most 6 tabs, one or two words each. `Segmented` (exists;
**fix**: selected = `accent-soft` + `accent` edge) is for filters, never for sections.

## 5. Card and table

- **Card** (**build** `components/common/Card.tsx`: `title`, `info`, `actions`, `flush`, `level`): `rule` border, `rounded-md`,
  `surface`, no shadow, `p-4` (`flush`: no padding, for a divided list of rows; its title row is `px-4 py-3` over a rule),
  title row `text-base` 600 with actions on the right; `level={3}` inside a `Section` (h2). **A DataTable is its own card:
  never inside a Card**; title it with a `Section` or its `caption`. `Panel` (exists, no padding) stays as is until its pages migrate, then goes. No card in a card. Lists of things are
  tables, not a grid of identical cards. `Section` (exists) is a titled block without a box.
- **Table** = `DataTable` (exists; **fix**): header 36 px, `text-caption` muted on `sunken`, not sticky (the scroll box of a
  wide table would make "sticky" a lie); rows 40 px, `rule` between, hover `sunken` only when the row opens something; the
  row's first cell holds a real link (keyboard), the row click is a pointer shortcut; risk bar 3 px inset left (danger, warn);
  numbers right-aligned; 50 rows a page with `Pager` (exists). Below `md` (768 px, as the code) a `mobileRow` list (required
  over 3 columns). `empty` is "nothing yet"; when filters hide every row (its own text filter, or the page's: `filtered`) it shows
  `emptyFiltered`, by default "No rows match these filters." with "Clear filters" (`onClearFilters` clears the page's). Anatomy as
  [Primer DataTable](https://primer.style/product/components/data-table/).
- **List anatomy** (`components/common/ListParts.tsx`), the same on every page and tab, top to bottom:
  1. `ListToolbar` (DataTable draws it; a page that keeps the search above a server-paged list uses it directly): search
     first, then the filters (`Segmented`, an unlabelled `Select` whose first option names "every …", toggles), then the list's
     actions at the right end (Export, Add …; the primary one last). The add action of a list lives here, not in the page header.
  2. `ListSummary` (DataTable `summary`): one `text-meta` muted line, "<count> <rows>" with an optional qualifier after a comma
     ("7 devices, 16 open findings", "9 fixes, 16 open findings", "3 handled findings"); what the list is and how it is ordered
     goes behind its ⓘ; buttons that act on the whole list as shown (Add all, Export CSV) sit at its right end.
  3. The table. A DataTable of one column is a list of cards: its header is for screen readers only, as a `list` has none.
     A card row is a `ListRow`: lead (`ExpandToggle`, a rank) | title line (the name, a link when it has a page, then its
     badges) and short muted meta lines | actions on the right; the opened part is indented under the title.
  A tab whose panel is one list has no heading repeating the tab's name. `ExpandToggle` is the one disclosure: a chevron
  pointing right when closed and down when open, as an icon before a row's title or as a small text button ("Settings").
  `src/test/layoutGuard.test.ts` fails on a tab row, list search, count line, disclosure chevron or "Back to …" link built by hand.

## 6. Empty state (`EmptyState` exists; **fix**: `art` prop; **build** `components/common/Illustration.tsx`)

- Nothing exists yet (first run, no devices, no findings): centred, illustration 180×120 (120×80 on phones) in `text-accent`,
  title, one line, one action ([Primer empty states](https://primer.style/product/ui-patterns/empty-states/),
  [Blankslate](https://primer.style/product/components/blankslate/)). `art` is typed as the six names, not a node.
- A filter or search finds nothing: text only, inside the table (`filtered` + `onClearFilters`, or `emptyFiltered`: "No devices
  match. Clear filters"), never the "nothing yet" art.
- Illustrations (`web/src/assets/illustrations/`, #827): `no-devices` Devices, `no-findings` Findings and Plan (good news),
  `no-alerts` Incidents, `scanning` a running first scan, `welcome` and `setup-done` first-run setup. `Illustration` inlines the
  static build-time SVG (`?raw`); it is the only `dangerouslySetInnerHTML` in `src`, never fed with data; `aria-hidden`.

## 7. Chip, counter, badge; the status model

- `Chip` (`StatusChip.tsx`): 24 px, `rounded-sm`, `text-caption` 500, always words, soft in four tones for generic states
  (on/off, linked, sent). It never shows a finding's status, a severity, how a match is verified or how a finding was handled:
  those have one component each in `components/common/status`, and `web/src/test/statusGuard.test.ts` fails on any other chip
  of them (a named exception says why it stays).
- **Status** (`StatusBadge`): one badge per finding status and device badge, most urgent first: Under attack here (the only
  filled one, `danger`), Exploited in the wild (`danger` soft), Public exploit available (`warn` with a full border), Critical on
  an edge device (`warn` outline), Update recommended (`warn` soft), Patched (`ok` soft), Mitigated (`ok` outline), Risk accepted
  until a day, Not relevant, False positive (`off`), Needs your input (`accent`). Each has its own icon, so colour is never
  alone; its meaning is the hover text. With a count it is a device's badge ("2 exploited") and a link to that device's findings.
- **Reasons** (`ReasonsLine`): under the badge, every urgency layer that applies with its sources, date and link
  ("Exploited in the wild: Rapid7 (19 Nov); not yet in CISA KEV · Public exploit available: GitHub, 244 stars (18 Nov)").
- **Verification** (`VerificationLine`): a second line, never a second chip: "Confirmed by a safe check", "Confirmed: the
  device reports this version", "Confirmed by <user>", "Not confirmed yet: based on a scan banner".
- **Handling** (`HandledLine`): who and how, from stored fields: "Patched by Vedette: version moved 6.24 → 7.23 (18 Nov)".
- **Severity** (`SeverityBadge`): the CVE's CVSS band and score, "Critical 9.8", soft in the four tones (Critical and High
  `danger`, Medium `warn`, Low, None and Info `off`) with a `SeverityMeter` of four bars (4 Critical … 0 None), as Tenable gives
  each severity its own icon ([Tenable severity indicators](https://docs.tenable.com/vulnerability-management/Content/getting-started/VulnerabilitySeverityIndicators.htm)).
  Separate from the status and never instead of it. No score: "Not scored yet", never 0. Version and vector on hover; on the
  finding page behind an ⓘ with FIRST's credit; bands from [FIRST CVSS](https://www.first.org/cvss/v3.1/specification-document)
  (NVD's three bands for CVSS 2.0).
- **CVE lists** (`CveList`): every list of CVEs, most severe first, each with its severity and a link, a count line
  ("2 Critical · 18 High · 5 Medium"), Critical and High shown and the rest behind one click ("+12 Medium/Low"). No joined
  string of CVE ids and no hand-built run of links elsewhere (the status guard counts them).
- `Counter` (**build** `components/common/Counter.tsx`, taken out of `PageTabs`): pill, `text-caption` 600, "99+" cap, `danger`
  solid when work waits for the user, `off` soft for a plain count, words for screen readers inside; used by tabs, nav, KPI
  ([Primer CounterLabel](https://primer.style/product/components/counter-label/)). `ScopeBadge` (exists): Preview / not in v1.
## 8. Notice, form, dialog

- `Notice` (exists): page or section state; tones danger, warn, accent, off; title + one line + ⓘ + actions.
- **CreatableSelect** (**build** `components/common/CreatableSelect.tsx`, §0): a `Select` whose last option is "+ New …";
  the caller supplies the small create dialog and its save call (`renderCreate`); on save the item is selected, focus is back on
  the select and a status line says "… added and selected". **DependencyLink** (**build** `components/common/DependencyLink.tsx`):
  one short reason + a link to the exact tab and `#field`; `useDeepLinkTarget` in Layout focuses that field on arrival.
- **Field** (`Field`, `Input`, `Select`, `Textarea`: exist; **fix**: `Field` gives the control whose `id` equals `htmlFor`
  `aria-describedby` (error, else hint) and `aria-invalid` when there is an error, through context, unless the call site sets
  them; edges use `control`; `Checkbox`, `RadioGroup` keep `muted` edges, `Switch` off-track `control`, thumb `surface`): label
  above (`text-sm` 500), control 40 px phone / 36 px desktop, hint one line `text-meta` muted, error under the control in
  `danger`. Explanations go behind the label's ⓘ (Material keeps helper text to one line: [text fields](https://m3.material.io/components/text-fields/guidelines)).
  One column, max 576 px; two short fields side by side from `md` only. Mark the fewer: "(optional)" when most fields are
  required. Primary action at the end of the form, left-aligned with the fields ([Primer forms](https://primer.style/product/ui-patterns/forms/)).
- **Button** (exists): one `primary` per region; `secondary` default; `ghost` in toolbars; `danger` for destructive verbs;
  icon-only buttons have `aria-label` and a `Tooltip`. Labels are verbs ("Remove device"), no trailing arrows.
- **Busy state** (2026-11-17: "Ask my AI" went grey for 20 s with no sign of work): a button whose action waits on the
  server takes `busy={x.isPending}` and `busyLabel` ("Saving…", "Asking…": `common:busy.*` or the feature's). The Button then
  disables itself, sets `aria-busy="true"`, keeps its full colour, and shows a spinner with the busy label in place of its icon
  and label; its width never changes (label, busy content and busy label share one grid cell). Only the button whose own action
  runs is busy; Cancel and its siblings are only disabled. A wait that is usually longer than about 3 s (AI calls, scans or checks
  started from a button, report generation, connection tests, test messages) also says what is happening next to or under the
  button with `BusyNote` ("Asking your AI… this can take up to a minute · 12 s"), a polite status line; jobs with progress use
  `JobProgress` (§10). As Atlassian's loading button and Polaris's `loading` keep the button's size and show a spinner
  ([Atlassian button](https://atlassian.design/components/button/examples#loading-button),
  [Polaris button](https://polaris-react.shopify.com/components/actions/button)). Guard: `web/src/test/busyGuard.test.ts`
  fails on a `<Button>` without `busy` whose `disabled` reads a pending state or whose `onClick`/`onSelect` calls a mutation or a
  download (itself or through a function of the file), a form's submit button whose `onSubmit` does, a label or spinner swapped
  by hand, `busy` without a `busyLabel` (only an icon-only button may rely on its `aria-label`), and a raw `<button>` or a menu
  item that waits; a named exception needs a `busy-guard:` comment and an `ALLOWED` entry. Downloads use `DownloadButton`
  ("Downloading…"). With an `aria-label`, the busy name starts with the busy label (WCAG 2.5.3). A wait the person did not start
  (a timer's poll, a background refetch) shows no busy state.
- **Dialog** (`DialogContent`, `DialogFooter`: exist): 512 px, `wide` 768 px, full width minus 32 px on phones; title
  `text-base` 600, one-line description, ⓘ; footer right-aligned, primary last; Esc and the 40/32 px close; focus returns to
  the opener. A form of more than about 6 fields, or one the user may leave half done, is a page, not a dialog
  ([Primer Dialog](https://primer.style/product/components/dialog/)). Destructive confirms name object and verb, never "Are you sure?".

## 9. Guidance behind ⓘ (`InfoTip` exists, #824)

Every section, tab, dialog, form, field, empty state and first-run wizard step shows a title and at most one short line (about
12 words). How it works, why, examples, edge cases and legal detail go behind an ⓘ next to the title or label: click, Enter or
Space opens it, Esc or a click outside closes it, the text is the button's description. Always visible (one line, detail
behind ⓘ): warnings that prevent harm, errors, status, legal text the TERMS require on screen, the "AI-generated" label. Pass
it through `info` on `PageHeader`, `Section`, `Card`, `Notice`, `DialogContent`, `Field`, `EmptyState`; no page writes its
own help paragraph. `Tooltip` names an icon, `InfoTip` explains; never both on one control ([WCAG 1.4.13](https://www.w3.org/WAI/WCAG22/Understanding/content-on-hover-or-focus.html)).

## 10. Long jobs (`JobProgress` exists, `components/progress/`, #834)

Any job the box reports progress for (scan, public-IP scan; later feed sync, backup, update) shows `JobProgress` inline where
it was started (the row or the card), never in a modal or a toast: the step in words, a determinate bar with percent or a
sliding one, "3 of 8 checks", elapsed, "about 4 min left in this step", the pass note, a neutral "Last report 45 s ago ⓘ"
when quiet. `Loading` (`States.tsx`) only for waits under about 5 s with nothing to report.

## 11. Breakpoints, phone, keyboard

Below 768 px (`md`): top bar + drawer, tables as `mobileRow`. 768–1023: top bar + drawer, tables scroll inside their card.
From 1024 (`lg`): sidebar 240 px or rail 56 px. Check at 360, 390, 768, 1024 and 1440 px, light and dark: no sideways
scroll of the page, ever ([Tailwind breakpoints](https://tailwindcss.com/docs/responsive-design)). Inputs 16 px text on
phones. Targets: 40 px for buttons and the ⓘ on phones, at least 36 px for small buttons, checkboxes and the table filter,
never under 24 px ([WCAG 2.5.8](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html)). Keyboard: "Skip to
content" first (exists); every action reachable by Tab in visual order; focus ring 2 px `focus`, offset 2; groups are
disclosure buttons ([APG disclosure](https://www.w3.org/WAI/ARIA/apg/patterns/disclosure/)); dialogs and the drawer trap
focus. Status is never colour alone (words, shape). axe runs in the component tests (exists).

## 12. Keeping it standard: codemod, then the style guard

1. **Codemod PR** (one, mechanical, after the Devices #849 and Scanning #850 pages merge, so their branches don't conflict):
   `text-[13px]` → `text-meta`, `text-[12px]` → `text-caption` (819 exact renames in `features/`, plus the ones in
   `components/` and `app/`); the 34 others (12.5, 11.5, 11, 15 px) and `text-2xl` ×4 by hand to the nearest name; the five
   other arbitrary values by hand; `--text-*: initial`; QR renderers (`core/QrCode.tsx`, `notify/ZaloPersonal.tsx`) merged into
   `components/common/QrCode.tsx` (black on white in both themes); the print CSS of `reports/PrintPage.tsx` into `index.css`
   `@media print`. The guard lands in the same PR and starts at zero: no baseline file.
2. **Guard** (**build** `web/src/test/styleGuard.test.ts`, vitest, like the `ui/tabs` guard in `PageFrame.test.tsx`): reads every
   non-test `.ts`/`.tsx` under `features/`, `components/` and `app/` and fails on: colour literals in value positions only
   (inside `-[…]`, JSX `fill|stroke|color|stopColor="#…"`, `color|background|border…: #…` in style objects or CSS strings), so
   `#824` in a comment and `#bad` anchors never match; Tailwind palette colours (`bg-red-500`, `text-white`, `border-black`;
   allowed keywords `transparent`, `current`, `inherit`); arbitrary values in colour, spacing, font size, radius or shadow
   utilities; sizes outside the six (`text-xs`, `text-2xl`…); `style={{…}}` setting colour, background, margin, padding or font
   size. Named exceptions, each with a `// ui-guard: <reason>` on the line: `components/common/QrCode.tsx`, `components/brand/Logo.tsx`
   (`SIGNAL`), hit areas `after:-inset-*`, `translate-x-[…]` of the switch thumb, the inset rule `shadow-[inset…]` of
   `PageTabs`/`UnderlineNav`/`DataTable`, `max-h-[min(…)]` of popovers, layout values (`grid-cols-[minmax(0,1fr)…]`,
   `grid-rows-[0fr|1fr]` and `transition-[grid-template-rows]` of the nav groups, `max-w-[…]`). The current-entry bar is the
   `nav-current` utility, not an arbitrary shadow. Not oxlint: it has no Tailwind class rule, and an ESLint Tailwind plugin is a second linter; the guard needs
   no dependency and runs in PR CI with the web tests. Review-only (not guarded): opacity-modified tokens such as
   `border-danger/40` and hand-drawn `rounded-md border border-rule bg-surface` boxes, which move to `Notice` and `Card` as
   pages migrate. (Wiz and Falcon docs are behind sign-in, so no choice here cites them.)

## 13. Review

**Checklist for every page and dialog**: (1) list every dependency the page needs (credential, scope,
channel, token, key, user, module on…); (2) each is created inline (`CreatableSelect` with its small dialog, new item selected)
or deep-linked to the exact tab and field (`DependencyLink`); (3) no text says "go to Settings" without that link; (4) the same
item is still editable on its own page. A dependency that fails (2) is a defect, not a follow-up.

Spacing: the doc states the code's values. Targets follow the code (§11). Checkboxes keep `muted`. The guard names its
keywords; opacity-modified tokens and hand-drawn boxes are review-only, as said in §12. The shell keeps the `<ol>` (note in
§3).

## 14. Decisions

1. **Incidents always visible** in the pinned block (§2).
2. **Settings is one entry at the foot** of the sidebar; its sections keep their own menu.
3. **Severity: a level meter inside the existing four tones** (§7); only "Under attack here" is filled.

No open questions remain for this standard; new ones go to the issue of the page that raises them.
