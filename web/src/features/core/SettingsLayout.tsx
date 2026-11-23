import { Link, Navigate, Outlet, useLocation, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { settingsSections, type SettingsSection } from '@/app/feature'
import { EmptyState, Loading, ModuleOff } from '@/components/common/States'
import { useModules } from '@/lib/modules'
import { PageModule, scopeOf } from '@/lib/v1'
import { useMe, type Role } from '@/lib/session'
import { UnderlineNav } from '@/components/common/UnderlineNav'

const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 }

/** The module a section belongs to for the v1 scope: the one whose switch it holds (switchOf), else its own. */
const ownerOf = (s: SettingsSection) => s.switchOf ?? s.module

/** The settings sections this person may see: the role is enough, the section's module is on, and it does not belong to a module this release does not offer. */
function useAllowed() {
  const me = useMe()
  const mods = useModules()
  if (!me.data || !mods.data) return { ready: false as const, list: [] }
  const on = new Set(mods.data.modules.filter((m) => m.enabled).map((m) => m.id))
  const hidden = (s: SettingsSection) => scopeOf(ownerOf(s), on.has(ownerOf(s))) === 'hidden'
  return { ready: true as const, role: me.data.role, list: settingsSections.filter((s) => RANK[me.data!.role] >= RANK[s.minRole] && on.has(s.module) && !hidden(s)), on, hidden }
}

export function SettingsLayout() {
  const { t } = useTranslation('core')
  const a = useAllowed()
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[200px_minmax(0,1fr)] lg:gap-6">
      <aside className="grid min-w-0 content-start gap-3">
        {/* docs/UI.md §4: a row like the tab row below lg, the vertical menu from lg (Settings keeps its menu). */}
        <UnderlineNav label={t('settings.nav')} verticalFrom="lg" items={a.list.map((s) => ({ to: `/settings/${s.id}`, label: t(s.label) }))} />
      </aside>
      <div className="min-w-0"><Outlet /></div>
    </div>
  )
}

export function SettingsIndex() {
  const a = useAllowed()
  if (!a.ready) return <Loading />
  const first = a.list[0]
  return first ? <Navigate to={`/settings/${first.id}`} replace /> : <SettingsNotFound />
}

function SettingsNotFound() {
  const { t } = useTranslation('core')
  const a = useAllowed()
  const first = a.list[0]
  return (
    <EmptyState title={t('settings.notFound.title')} action={first ? <Link className="text-accent underline-offset-4 hover:underline" to={`/settings/${first.id}`}>{t('settings.notFound.back', { name: t(first.label) })}</Link> : undefined}>
      {t('settings.notFound.body')}
    </EmptyState>
  )
}

export function SettingsRoute() {
  const { t } = useTranslation('core')
  const { section } = useParams()
  const a = useAllowed()
  if (!a.ready) return <Loading />
  const s = settingsSections.find((x) => x.id === section)
  if (!s) return <SettingsNotFound />
  if (RANK[a.role] < RANK[s.minRole]) {
    return <EmptyState title={t('settings.needRole.title', { name: t(s.label) })}>{t('settings.needRole.body', { role: t(`common:role.${s.minRole}`) })}</EmptyState>
  }
  if (!a.on.has(s.module)) return <ModuleOff module={s.module} page />
  if (a.hidden(s)) return <ModuleOff module={ownerOf(s)} page />
  return <PageModule.Provider value={ownerOf(s)}>{s.element}</PageModule.Provider>
}

/** My account is a Settings section; the old /account (links, bookmarks, SSO `next`) lands there with its ?query and #anchor. */
export function AccountMoved() {
  const l = useLocation()
  return <Navigate to={{ pathname: '/settings/account', search: l.search, hash: l.hash }} replace />
}
