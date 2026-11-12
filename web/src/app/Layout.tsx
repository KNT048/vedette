import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, ScrollRestoration, useLocation, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { Bug, LogOut, Menu, Settings, UserCog, UserRound } from 'lucide-react'
import { BugReportDialog } from '@/features/core/BugReportDialog'
import { RevokedBanner } from '@/features/core/UpdateSignals'
import { navItems, type NavGroup } from './feature'
import { useModules } from '@/lib/modules'
import { useMe } from '@/lib/session'
import { api } from '@/lib/api'
import { setTheme, useTheme, type ThemePref } from '@/lib/theme'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { cn } from '@/lib/utils'

const GROUPS: NavGroup[] = ['monitor', 'assets', 'detect', 'assist']

function Nav({ onNavigate }: { onNavigate?: () => void }) {
  const { t } = useTranslation()
  const { data } = useModules()
  const enabled = new Set(data?.modules.filter((m) => m.enabled).map((m) => m.id))
  const items = navItems.filter((n) => !data || enabled.has(n.module))
  const link = (isActive: boolean) => cn('flex h-9 items-center gap-2.5 rounded-md px-2.5 text-sm text-muted hover:bg-sunken hover:text-ink [&_svg]:size-4', isActive && 'bg-accent-soft font-medium text-ink [&_svg]:text-accent')
  return (
    <nav aria-label={t('layout.nav')} className="grid gap-5">
      {GROUPS.map((g) => {
        const list = items.filter((n) => n.group === g)
        if (!list.length) return null
        return (
          <div key={g} className="grid gap-0.5">
            <p className="px-2.5 pb-1 text-[12px] text-muted">{t(`layout.group.${g}`)}</p>
            {list.map((n) => (
              <NavLink key={n.to} to={n.to} end={n.end} onClick={onNavigate} className={({ isActive }) => link(isActive)}>
                <n.icon aria-hidden />{t(n.label)}
              </NavLink>
            ))}
          </div>
        )
      })}
      <div className="grid gap-0.5 border-t border-rule pt-3">
        <NavLink to="/settings" onClick={onNavigate} className={({ isActive }) => link(isActive)}><Settings aria-hidden />{t('layout.settings')}</NavLink>
      </div>
    </nav>
  )
}

function UserMenu() {
  const { t } = useTranslation()
  const { data: me } = useMe()
  const theme = useTheme()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [bug, setBug] = useState(false)
  async function logout() {
    await api.post('/auth/logout')
    qc.clear()
    navigate('/login')
  }
  return (
    <>
    <BugReportDialog open={bug} onOpenChange={setBug} />
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="h-auto w-full justify-start gap-2.5 px-2.5 py-2 text-left">
          <UserRound className="text-muted" aria-hidden />
          <span className="sr-only">{t('layout.account')}:</span>{' '}
          <span className="grid min-w-0">
            <span className="truncate text-sm">{me?.name}</span>
            <span className="truncate text-[12px] text-muted">{me ? t(`role.${me.role}`) : ''}</span>
          </span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-60">
        <DropdownMenuLabel>{me?.email}</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuLabel>{t('layout.theme')}</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={theme} onValueChange={(v) => setTheme(v as ThemePref)}>
          <DropdownMenuRadioItem value="system">{t('layout.themeSystem')}</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="light">{t('layout.themeLight')}</DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="dark">{t('layout.themeDark')}</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => navigate('/account')}><UserCog />{t('layout.myAccount')}</DropdownMenuItem>
        <DropdownMenuItem onSelect={() => setBug(true)}><Bug />{t('layout.reportProblem')}</DropdownMenuItem>
        <DropdownMenuItem onSelect={() => void logout()}><LogOut />{t('layout.logout')}</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
    </>
  )
}

function Brand() {
  const { data: me } = useMe()
  return (
    <div className="grid px-2.5">
      <span className="text-[17px] font-semibold tracking-[-0.01em]">Vedette</span>
      <span className="truncate text-[12px] text-muted">{me?.org}</span>
    </div>
  )
}

/** Tiêu đề tab trình duyệt theo trang (WCAG 2.4.2) và focus vào nội dung khi đổi trang (trình đọc màn hình đọc trang mới). */
function usePageChrome() {
  const { t, i18n } = useTranslation()
  const loc = useLocation()
  const first = useRef(true)
  useEffect(() => {
    const p = loc.pathname
    const item = p.startsWith('/settings') || p.startsWith('/account') ? null : [...navItems].sort((a, b) => b.to.length - a.to.length).find((n) => (n.to === '/' ? p === '/' : p === n.to || p.startsWith(`${n.to}/`)))
    const label = item ? t(item.label) : p.startsWith('/account') ? t('layout.myAccount') : p.startsWith('/settings') ? t('layout.settings') : null
    document.title = label ? `${label} | Vedette` : 'Vedette'
    if (first.current) { first.current = false; return }
    document.getElementById('main')?.focus({ preventScroll: true })
  }, [loc.pathname, t, i18n.language])
}

export function Layout() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const loc = useLocation()
  usePageChrome()
  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[240px_1fr]">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-surface focus:px-3 focus:py-2">{t('layout.skip')}</a>
      <div className="sticky top-0 hidden h-dvh flex-col gap-6 overflow-y-auto border-r border-rule bg-surface px-3 py-5 lg:flex">
        <Brand />
        <div className="flex-1"><Nav /></div>
        <UserMenu />
      </div>
      <div className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-rule bg-surface px-4 lg:hidden">
        <Button variant="ghost" size="icon" onClick={() => setOpen(true)} aria-label={t('layout.openMenu')}><Menu /></Button>
        <span className="text-[17px] font-semibold">Vedette</span>
        <span className="w-9" />
      </div>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent title={t('layout.nav')} className="left-0 top-0 h-dvh max-h-dvh w-72 max-w-72 translate-x-0 translate-y-0 rounded-none">
          <Nav onNavigate={() => setOpen(false)} />
          <UserMenu />
        </DialogContent>
      </Dialog>
      <div className="min-w-0">
        <RevokedBanner />
        <main id="main" tabIndex={-1} key={loc.pathname} className="mx-auto w-full max-w-[1280px] px-4 py-6 outline-none sm:px-6 lg:px-10 lg:py-8">
          <Outlet />
        </main>
      </div>
      <ScrollRestoration />
    </div>
  )
}
