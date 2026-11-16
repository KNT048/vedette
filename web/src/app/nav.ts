// The placement of the nav entries and their badges (docs/UI.md §2, #842). One table, so kien's answer to UI.md question 1 (Incidents
// always visible?) is a one-line change here. Features declare their entries (feature.ts); the shell decides where they sit.
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { useMe } from '@/lib/session'
import { navItems, type NavGroup, type NavItem } from './feature'

/** Always visible, in this order, never in a group. */
export const PINNED = ['/', '/findings', '/plan'] as const

/** The collapsible groups, in order. `monitor` holds no group of its own any more: what it held is pinned or moved below. */
export type ShellGroup = Exclude<NavGroup, 'monitor'>
export const GROUPS: ShellGroup[] = ['assets', 'detect', 'assist']

/** Entries whose feature still says `monitor` but that sit in a group (UI.md question 1). */
const MOVED: Record<string, ShellGroup> = { '/incidents': 'detect', '/lookup': 'assist' }

export function placeOf(n: NavItem): 'pinned' | ShellGroup {
  if ((PINNED as readonly string[]).includes(n.to)) return 'pinned'
  return MOVED[n.to] ?? (n.group === 'monitor' ? 'assist' : n.group)
}

/** The part of GET /findings/summary (#825) the nav reads. Optional fields: an older box, or one whose summary lacks a count, shows no badge. */
export type NavSummary = { open?: { confirmed?: number }; devices?: { pending?: number } }

/** The badge of one entry: count and the words read after it. `urgent`: work waits for the user (red, and summed on a closed group). */
export type NavBadge = { count: number; key: string; urgent: boolean }

const BADGES: Record<string, (s: NavSummary) => NavBadge | null> = {
  '/findings': (s) => (s.open?.confirmed ? { count: s.open.confirmed, key: 'layout.badge.findings', urgent: true } : null),
  '/devices': (s) => (s.devices?.pending ? { count: s.devices.pending, key: 'layout.badge.devices', urgent: true } : null),
}

export function badgeOf(to: string, s: NavSummary | undefined): NavBadge | null {
  return s ? (BADGES[to]?.(s) ?? null) : null
}

/** One cheap read for every badge: the cached summary Home reads too (same query key, so one request serves both). Only while the
 *  findings module is on; a failure shows no badges and is not retried in a loop. */
export function useNavSummary(enabled: boolean) {
  return useQuery({
    queryKey: ['findings', 'summary'],
    queryFn: () => api.get<NavSummary>('/findings/summary'),
    enabled,
    staleTime: 60_000,
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    retry: false,
  }).data
}

type Saved = { rail: boolean; open: ShellGroup[] }
const EMPTY: Saved = { rail: false, open: [] }

function read(key: string): Saved {
  try {
    const v = JSON.parse(localStorage.getItem(key) ?? 'null') as Partial<Saved> | null
    return { rail: v?.rail === true, open: Array.isArray(v?.open) ? v.open.filter((g): g is ShellGroup => (GROUPS as string[]).includes(g)) : [] }
  } catch {
    return EMPTY
  }
}

/** The rail choice and the open groups, saved per user in localStorage (try/catch: a blocked storage gives the first-visit default). */
export function useNavState() {
  const { data: me } = useMe()
  const key = `vedette.nav.${me?.id ?? 'anon'}`
  // Keyed by user: when the session loads (anon → id) the saved state of that user is read during render, not in an effect.
  const [held, setHeld] = useState<{ key: string; v: Saved }>(() => ({ key, v: read(key) }))
  const state = held.key === key ? held.v : read(key)
  if (held.key !== key) setHeld({ key, v: state })
  const save = (next: Saved) => {
    setHeld({ key, v: next })
    try { localStorage.setItem(key, JSON.stringify(next)) } catch { /* private window or blocked storage: keep it for this visit */ }
  }
  return {
    rail: state.rail,
    setRail: (rail: boolean) => save({ ...state, rail }),
    isOpen: (g: ShellGroup) => state.open.includes(g),
    toggle: (g: ShellGroup, now: boolean) => save({ ...state, open: now ? [...state.open.filter((x) => x !== g), g] : state.open.filter((x) => x !== g) }),
  }
}
export type NavState = ReturnType<typeof useNavState>

/** The nav entry a path belongs to (the longest match), none under /settings. */
const byLength = [...navItems].sort((a, b) => b.to.length - a.to.length)
export function navItemOf(p: string) {
  return p.startsWith('/settings') ? undefined : byLength.find((n) => (n.to === '/' ? p === '/' : p === n.to || p.startsWith(`${n.to}/`)))
}

