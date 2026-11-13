import { Link, Navigate, NavLink, Outlet, useLocation, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { settingsSections } from '@/app/feature'
import { EmptyState, Loading, ModuleOff } from '@/components/common/States'
import { useModules } from '@/lib/modules'
import { useMe, type Role } from '@/lib/session'
import { cn } from '@/lib/utils'

const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 }

/** Mục cài đặt người này được xem: đủ vai và module của mục đang bật. */
function useAllowed() {
  const me = useMe()
  const mods = useModules()
  if (!me.data || !mods.data) return { ready: false as const, list: [] }
  const on = new Set(mods.data.modules.filter((m) => m.enabled).map((m) => m.id))
  return { ready: true as const, role: me.data.role, list: settingsSections.filter((s) => RANK[me.data!.role] >= RANK[s.minRole] && on.has(s.module)), on }
}

export function SettingsLayout() {
  const { t } = useTranslation('core')
  const a = useAllowed()
  const link = ({ isActive }: { isActive: boolean }) => cn('flex h-9 items-center whitespace-nowrap rounded-md px-3 text-sm text-muted hover:bg-sunken hover:text-ink', isActive && 'bg-accent-soft font-medium text-ink')
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-6 lg:grid-cols-[200px_minmax(0,1fr)]">
      <aside className="grid min-w-0 content-start gap-3">
        <nav aria-label={t('settings.nav')} className="flex flex-wrap gap-1 lg:grid lg:gap-0.5">
          {a.list.map((s) => <NavLink key={s.id} to={`/settings/${s.id}`} className={link}>{t(s.label)}</NavLink>)}
        </nav>
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
  if (!a.on.has(s.module)) return <ModuleOff module={s.module} />
  return <>{s.element}</>
}

/** W1-26, D-540: My account is a Settings section; the old /account (links, bookmarks, SSO `next`) lands there with its ?query and #anchor. */
export function AccountMoved() {
  const l = useLocation()
  return <Navigate to={{ pathname: '/settings/account', search: l.search, hash: l.hash }} replace />
}
