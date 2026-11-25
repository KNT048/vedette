// The sidebar of docs/UI.md §2 (#842): an always-visible block, collapsible groups that remember their state per user, an icon rail
// from lg, the same list in the phone drawer, badges from the one overview read. Lives in app/ (one caller: Layout).
import { useState, type ComponentProps, type ReactNode } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { Bug, ChevronDown, CircleHelp, LogOut, PanelLeftClose, PanelLeftOpen, Settings, UserCog, UserRound } from 'lucide-react'
import { BugReportDialog } from '@/features/core/BugReportDialog'
import { RunningVersion } from '@/features/core/UpdateSignals'
import { useUpdatesBanner } from '@/features/core/api'
import { navItems, type NavItem } from './feature'
import { GROUPS, badgeOf, navItemOf, placeOf, useNavSummary, type NavBadge, type NavState, type NavSummary, type ShellGroup } from './nav'
import { useModules } from '@/lib/modules'
import { scopeOf, type Scope } from '@/lib/v1'
import { ScopeBadge } from '@/components/common/V1Scope'
import { Counter } from '@/components/common/Counter'
import { Slot } from '@/components/common/Slot'
import { useMe } from '@/lib/session'
import { api } from '@/lib/api'
import { setTheme, useTheme, type ThemePref } from '@/lib/theme'
import { Button } from '@/components/ui/button'
import { Logo } from '@/components/brand/Logo'
import { Tooltip } from '@/components/ui/tooltip'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { cn } from '@/lib/utils'

type Entry = { item: NavItem; scope: Scope; badge: NavBadge | null }

function useEntries(): { pinned: Entry[]; groups: { id: ShellGroup; entries: Entry[] }[]; ready: boolean } {
  const { data } = useModules()
  const enabled = new Set(data?.modules.filter((m) => m.enabled).map((m) => m.id))
  const summary: NavSummary | undefined = useNavSummary(!!data && enabled.has('findings'))
  // A module left out of v1 has no entry unless this box has it on (#819); while loading, it is not shown either.
  const scope = (n: NavItem) => scopeOf(n.module, data ? enabled.has(n.module) : undefined)
  const all = navItems.filter((n) => (!data || enabled.has(n.module)) && scope(n) !== 'hidden').map((item) => ({ item, scope: scope(item), badge: badgeOf(item.to, summary) }))
  const pinned = all.filter((e) => placeOf(e.item) === 'pinned')
  return { pinned, ready: !!data, groups: GROUPS.map((id) => ({ id, entries: all.filter((e) => placeOf(e.item) === id) })) }
}

const itemClass = (rail: boolean, drawer: boolean) => ({ isActive }: { isActive: boolean }) => cn(
  // -outline-offset-2: the ring is drawn inside, so a group's overflow (its open/close animation) never clips it (as PageTabs).
  'relative flex items-center rounded-md text-meta text-muted hover:bg-sunken hover:text-ink focus-visible:-outline-offset-2 [&_svg]:size-4 [&_svg]:shrink-0',
  rail ? 'size-10 justify-center' : cn('gap-2.5 px-2.5 py-1.5', drawer ? 'min-h-10' : 'min-h-9'),
  // UI.md §1: the fill alone is 1.2:1, so the current entry also has a 3 px accent bar (8:1) and aria-current (NavLink).
  isActive && 'nav-current bg-accent-soft font-medium text-ink [&_svg]:text-accent',
)

/** A rail link under a Tooltip trigger. Radix's Slot joins a child's className as a string, and NavLink's className is a function, so
 *  the trigger wraps this component (string-free props) and the function stays inside. */
function RailLink({ to, end, children, ...rest }: Omit<ComponentProps<typeof NavLink>, 'className' | 'children'> & { children: ReactNode }) {
  return <NavLink to={to} end={end} {...rest} className={itemClass(true, false)}>{children}</NavLink>
}

function EntryLink({ e, rail, drawer, onNavigate }: { e: Entry; rail: boolean; drawer: boolean; onNavigate?: () => void }) {
  const { t } = useTranslation()
  const label = t(e.item.label)
  const words = e.badge ? t(e.badge.key) : null
  const preview = e.scope === 'leaving' ? t(`scope.${e.scope}`) : null
  const counter = e.badge ? <Counter count={e.badge.count} label={words ?? undefined} tone={e.badge.urgent ? 'danger' : 'off'} className={rail ? 'absolute -right-1 -top-1 h-4 min-w-4 px-1' : 'ml-auto'} /> : null
  if (rail) {
    return (
      <Tooltip describe={false} content={[label, e.badge ? `${e.badge.count} ${words}` : null, preview].filter(Boolean).join(', ')}>
        <RailLink to={e.item.to} end={e.item.end} onClick={onNavigate}>
          <e.item.icon aria-hidden /><span className="sr-only">{label}{preview ? ` ${preview}` : ''}</span>{counter ? <>{' '}{counter}</> : null}
        </RailLink>
      </Tooltip>
    )
  }
  return (
    <NavLink to={e.item.to} end={e.item.end} onClick={onNavigate} className={itemClass(false, drawer)}>
      <e.item.icon aria-hidden /><span className="min-w-0">{label}</span>{' '}
      {counter ?? <ScopeBadge scope={e.scope === 'preview' ? 'v1' : e.scope} className="-mr-1 ml-auto h-5 shrink-0 px-1.5 text-caption" />}
      {counter && preview ? <ScopeBadge scope={e.scope === 'preview' ? 'v1' : e.scope} className="-mr-1 h-5 shrink-0 px-1.5 text-caption" /> : null}
    </NavLink>
  )
}

function Group({ id, entries, nav, current, drawer, onNavigate }: { id: ShellGroup; entries: Entry[]; nav: NavState; current: boolean; drawer: boolean; onNavigate?: () => void }) {
  const { t } = useTranslation()
  const name = t(`layout.group.${id}`)
  const open = current || nav.isOpen(id)
  const urgent = entries.filter((e) => e.badge?.urgent)
  const total = urgent.reduce((n, e) => n + e.badge!.count, 0)
  const parts = urgent.map((e) => `${t(e.item.label)} ${e.badge!.count} ${t(e.badge!.key)}`).join(', ')
  const region = `nav-group-${id}${drawer ? '-drawer' : ''}`
  const [moved, setMoved] = useState(false)
  return (
    <div className="grid grid-cols-[minmax(0,1fr)]">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={region}
        // The group holding the current page stays open (closing it would hide where you are), so its header says so and does nothing.
        aria-disabled={current || undefined}
        onClick={() => { if (!current) { setMoved(true); nav.toggle(id, !open) } }}
        className={cn('flex h-8 items-center gap-1.5 rounded-md px-2.5 text-left text-caption font-medium text-muted hover:text-ink', current && 'cursor-default hover:text-muted')}
      >
        <span className="min-w-0 flex-1 truncate">{name}{current ? <span className="sr-only">, {t('layout.groupHere')}</span> : null}</span>
        {/* No aria-label: the name is the visible text (WCAG 2.5.3) plus sr-only words after it: "Assets 2 waiting: Devices 2 to review". */}
        {!open && total ? <>{' '}<Counter count={total} tone="danger" label={t('layout.groupWaiting', { parts })} /></> : null}
        <ChevronDown aria-hidden className={cn('size-3.5 shrink-0 transition-transform duration-150', open ? 'rotate-0' : '-rotate-90')} />
      </button>
      {/* Closed: `hidden` (display none), so its links leave the tab order, the accessibility tree and every role query; inert alone
          left them listed as present but unclickable. Height eases over 150 ms both ways once the header was pressed: `starting:` gives
          the opening its 0fr start, `transition-discrete` keeps display on until the closing ends. Before a press nothing animates,
          so a group open on load or in a freshly opened drawer is simply there. */}
      <div
        id={region}
        hidden={!open}
        className={cn('grid ease-out', moved && 'transition-[grid-template-rows,display] transition-discrete duration-150', open ? cn('grid-rows-[1fr]', moved && 'starting:grid-rows-[0fr]') : 'grid-rows-[0fr]')}
      >
        {/* div, not ul: many page tests query the one list or listitem of their page (getByRole('list')). */}
        <div role="group" aria-label={name} className="grid min-h-0 grid-cols-[minmax(0,1fr)] gap-0.5 overflow-hidden">
          {entries.map((e) => <EntryLink key={e.item.to} e={e} rail={false} drawer={drawer} onNavigate={onNavigate} />)}
        </div>
      </div>
    </div>
  )
}

/** The list: pinned entries, then each group (one visible entry: a plain item; none: nothing), then Settings. */
export function NavList({ nav, rail = false, drawer = false, onNavigate }: { nav: NavState; rail?: boolean; drawer?: boolean; onNavigate?: () => void }) {
  const { t } = useTranslation()
  const { pathname } = useLocation()
  const { pinned, groups, ready } = useEntries()
  const here = navItemOf(pathname)
  const hereGroup = here ? placeOf(here) : null
  const list = (entries: Entry[], label?: string) => (
    <div role={label ? 'group' : undefined} aria-label={label} className={cn('grid gap-0.5', rail ? 'justify-items-center' : 'grid-cols-[minmax(0,1fr)]')}>
      {entries.map((e) => <EntryLink key={e.item.to} e={e} rail={rail} drawer={drawer} onNavigate={onNavigate} />)}
    </div>
  )
  return (
    <nav aria-label={t('layout.nav')} className={cn('grid gap-3', !rail && 'grid-cols-[minmax(0,1fr)]')}>
      {list(pinned)}
      {/* The groups wait for /modules: before it, every entry would show and a one-entry group would flip from header to item. */}
      {(ready ? groups : []).filter((g) => g.entries.length).map((g) => (
        <div key={g.id} className={cn(rail && 'border-t border-rule pt-3')}>
          {rail || g.entries.length === 1
            ? list(g.entries, rail ? t(`layout.group.${g.id}`) : undefined)
            : <Group id={g.id} entries={g.entries} nav={nav} current={hereGroup === g.id} drawer={drawer} onNavigate={onNavigate} />}
        </div>
      ))}
      <div className={cn('grid gap-0.5 border-t border-rule pt-3', rail && 'justify-items-center')}>
        {rail ? (
          <>
            <Tooltip describe={false} content={t('layout.settings')}>
              <RailLink to="/settings" onClick={onNavigate}><Settings aria-hidden /><span className="sr-only">{t('layout.settings')}</span></RailLink>
            </Tooltip>
            {/* Help: the user cookbook (docs/cookbook), bundled in the build so it works offline. */}
            <Tooltip describe={false} content={t('layout.help')}>
              <RailLink to="/help" onClick={onNavigate}><CircleHelp aria-hidden /><span className="sr-only">{t('layout.help')}</span></RailLink>
            </Tooltip>
          </>
        ) : (
          <>
            <NavLink to="/settings" onClick={onNavigate} className={itemClass(false, drawer)}><Settings aria-hidden />{t('layout.settings')}</NavLink>
            <NavLink to="/help" onClick={onNavigate} className={itemClass(false, drawer)}><CircleHelp aria-hidden />{t('layout.help')}</NavLink>
          </>
        )}
      </div>
    </nav>
  )
}

/** `onNavigate`: the drawer closes when an entry leaves the page. */
export function UserMenu({ rail = false, onNavigate }: { rail?: boolean; onNavigate?: () => void }) {
  const { t } = useTranslation()
  const { data: me } = useMe()
  const theme = useTheme()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const version = useUpdatesBanner().data?.components.find((c) => c.id === 'software')?.version
  const [bug, setBug] = useState(false)
  async function logout() {
    await api.post('/auth/logout')
    qc.clear()
    navigate('/login')
  }
  const trigger = rail ? (
    <Button variant="ghost" size="icon" aria-label={`${t('layout.account')}: ${me?.name ?? ''}`}><UserRound className="text-muted" aria-hidden /></Button>
  ) : (
    <Button variant="ghost" className="h-auto w-full justify-start gap-2.5 px-2.5 py-2 text-left">
      <UserRound className="text-muted" aria-hidden />
      <span className="sr-only">{t('layout.account')}:</span>{' '}
      <span className="grid min-w-0">
        <span className="truncate text-sm">{me?.name}</span>
        <span className="truncate text-caption text-muted">{me ? t(`role.${me.role}`) : ''}</span>
      </span>
    </Button>
  )
  return (
    <>
      <BugReportDialog open={bug} onOpenChange={setBug} />
      <DropdownMenu>
        {rail ? <Tooltip describe={false} content={me?.name ?? t('layout.account')}><DropdownMenuTrigger asChild>{trigger}</DropdownMenuTrigger></Tooltip> : <DropdownMenuTrigger asChild>{trigger}</DropdownMenuTrigger>}
        <DropdownMenuContent align="start" side={rail ? 'right' : undefined} className="w-60">
          <DropdownMenuLabel>{me?.email}</DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuLabel>{t('layout.theme')}</DropdownMenuLabel>
          <DropdownMenuRadioGroup value={theme} onValueChange={(v) => setTheme(v as ThemePref)}>
            <DropdownMenuRadioItem value="system">{t('layout.themeSystem')}</DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="light">{t('layout.themeLight')}</DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="dark">{t('layout.themeDark')}</DropdownMenuRadioItem>
          </DropdownMenuRadioGroup>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => { onNavigate?.(); navigate('/settings/account') }}><UserCog />{t('layout.myAccount')}</DropdownMenuItem>
          {/* Not onNavigate: the bug dialog lives in this menu, so closing the drawer would close it too; it opens over the drawer. */}
          <DropdownMenuItem onSelect={() => setBug(true)}><Bug />{t('layout.reportProblem')}</DropdownMenuItem>
          <DropdownMenuItem onSelect={() => { onNavigate?.(); void logout() }}><LogOut />{t('layout.logout')}</DropdownMenuItem>
          {/* In the rail the version has no footer line of its own (UI.md §2): it is the last entry here. */}
          {rail && version ? <><DropdownMenuSeparator /><DropdownMenuItem onSelect={() => { onNavigate?.(); navigate('/settings/updates') }}>{t('core:updates.footerVersion', { version })}</DropdownMenuItem></> : null}
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  )
}

export function Brand({ rail = false }: { rail?: boolean }) {
  const { data: me } = useMe()
  if (rail) return <div className="grid justify-items-center"><Logo variant="mark" className="h-6" /></div>
  return (
    <div className="grid gap-2 px-2.5">
      <Logo className="h-6" />
      <span className="truncate text-caption text-muted">{me?.org}</span>
    </div>
  )
}

/** The desktop column (from lg): brand, list, status slot, user menu, version, "Collapse menu". */
export function Sidebar({ nav }: { nav: NavState }) {
  const { t } = useTranslation()
  const rail = nav.rail
  // The name says what a press does ("Collapse menu" / "Expand menu") and equals the rail tooltip (WCAG 2.5.3).
  const collapse = (
    <Button variant="ghost" size={rail ? 'icon' : 'sm'} aria-label={rail ? t('layout.expand') : t('layout.collapse')} onClick={() => nav.setRail(!rail)} className={cn('text-muted', !rail && 'justify-start gap-2.5 px-2.5')}>
      {rail ? <PanelLeftOpen aria-hidden /> : <PanelLeftClose aria-hidden />}{rail ? null : <span>{t('layout.collapse')}</span>}
    </Button>
  )
  return (
    <div className={cn('sticky top-0 flex h-dvh flex-col gap-6 overflow-y-auto py-5', rail ? 'items-center px-2' : 'px-3')}>
      <Brand rail={rail} />
      <div className="flex-1"><NavList nav={nav} rail={rail} /></div>
      <div className={cn('grid gap-1', rail && 'justify-items-center')}>
        <Slot name="shell.status" props={{ compact: rail }} />
        <UserMenu rail={rail} />
        {rail ? null : <RunningVersion />}
        {rail ? <Tooltip describe={false} content={t('layout.expand')}>{collapse}</Tooltip> : collapse}
      </div>
    </div>
  )
}
