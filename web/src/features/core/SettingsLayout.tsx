import { useEffect, useRef } from 'react'
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
  const { pathname } = useLocation()
  const nav = useRef<HTMLElement>(null)
  // D-543: dưới lg menu là một hàng ngang cùng kiểu với hàng tab (PageTabs), cuộn trong chính nó; mục đang mở được cuộn vào tầm nhìn.
  useEffect(() => {
    const row = nav.current
    const el = row?.querySelector<HTMLElement>('[aria-current="page"]')
    if (!row || !el || row.scrollWidth <= row.clientWidth) return
    const r = row.getBoundingClientRect()
    const e = el.getBoundingClientRect()
    if (e.left < r.left || e.right > r.right) row.scrollLeft += e.left - r.left - 16
  }, [pathname, a.list.length])
  // Điện thoại/cửa sổ hẹp: gạch chân như tab; từ lg: menu dọc (D-464: Cài đặt giữ menu dọc, như Grafana, GitLab admin).
  const link = ({ isActive }: { isActive: boolean }) => cn(
    'flex h-10 shrink-0 items-center whitespace-nowrap border-b-2 border-transparent px-3 text-sm text-muted hover:text-ink focus-visible:-outline-offset-2',
    'lg:h-9 lg:rounded-md lg:border-b-0 lg:hover:bg-sunken',
    isActive && 'border-accent font-medium text-ink lg:bg-accent-soft',
  )
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[200px_minmax(0,1fr)] lg:gap-6">
      <aside className="grid min-w-0 content-start gap-3">
        <nav ref={nav} aria-label={t('settings.nav')} className="flex flex-nowrap overflow-x-auto overscroll-x-contain shadow-[inset_0_-1px_0_var(--color-rule)] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden lg:grid lg:gap-0.5 lg:overflow-visible lg:shadow-none">
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
