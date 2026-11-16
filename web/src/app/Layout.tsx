import { useEffect, useRef, useState } from 'react'
import { Outlet, ScrollRestoration, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Menu } from 'lucide-react'
import { RevokedBanner, RunningVersion } from '@/features/core/UpdateSignals'
import { PageModule } from '@/lib/v1'
import { Button } from '@/components/ui/button'
import { Logo } from '@/components/brand/Logo'
import { Slot } from '@/components/common/Slot'
import { DrawerContent, Dialog } from '@/components/ui/dialog'
import { NavList, Sidebar, UserMenu } from './Sidebar'
import { navItemOf, useNavState } from './nav'
import { cn } from '@/lib/utils'

/** Tiêu đề tab trình duyệt theo trang (WCAG 2.4.2) và focus vào nội dung khi đổi trang (trình đọc màn hình đọc trang mới). */
function usePageChrome() {
  const { t, i18n } = useTranslation()
  const loc = useLocation()
  const first = useRef(true)
  useEffect(() => {
    const p = loc.pathname
    const item = navItemOf(p)
    const label = item ? t(item.label) : p.startsWith('/settings/account') ? t('layout.myAccount') : p.startsWith('/settings') ? t('layout.settings') : null
    document.title = label ? `${label} | Vedette` : 'Vedette'
    if (first.current) { first.current = false; return }
    document.getElementById('main')?.focus({ preventScroll: true })
  }, [loc.pathname, t, i18n.language])
}

export function Layout() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  // A link in the drawer closes it and the page change moves focus to #main; Esc or the close button return it to "Open menu".
  const byLink = useRef(false)
  const nav = useNavState()
  const loc = useLocation()
  usePageChrome()
  const closeByLink = () => { byLink.current = true; setOpen(false) }
  return (
    <div className={cn('min-h-dvh lg:grid', nav.rail ? 'lg:grid-cols-[56px_1fr]' : 'lg:grid-cols-[240px_1fr]')}>
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-surface focus:px-3 focus:py-2">{t('layout.skip')}</a>
      {/* UI-4: the column paints the background and the rule down the whole page (it stretches with the grid row); only its content
          is sticky. With the background on the sticky h-dvh box, everything below the first screen height showed the page grey. */}
      <div className="hidden border-r border-rule bg-surface lg:block">
        <Sidebar nav={nav} />
      </div>
      <div className="sticky top-0 z-30 flex h-14 items-center justify-between gap-2 border-b border-rule bg-surface px-4 lg:hidden">
        <Button variant="ghost" size="icon" onClick={() => { byLink.current = false; setOpen(true) }} aria-label={t('layout.openMenu')}><Menu /></Button>
        <Logo className="h-[22px]" />
        {/* docs/UI.md §2: the shell.status slot (#850 "1 scan running"); the empty box keeps the logo centred. */}
        <div className="flex min-w-9 justify-end"><Slot name="shell.status" props={{ compact: true }} /></div>
      </div>
      <Dialog open={open} onOpenChange={setOpen}>
        <DrawerContent title={t('layout.nav')} returnFocus={() => !byLink.current}>
          <NavList nav={nav} drawer onNavigate={closeByLink} />
          <div className="grid gap-1 border-t border-rule pt-3">
            <UserMenu />
            <RunningVersion onNavigate={closeByLink} />
          </div>
        </DrawerContent>
      </Dialog>
      <div className="min-w-0">
        <RevokedBanner />
        <main id="main" tabIndex={-1} key={loc.pathname} className="mx-auto w-full max-w-[1280px] px-4 py-6 outline-none sm:px-6 lg:px-10 lg:py-8">
          <PageModule.Provider value={navItemOf(loc.pathname)?.module ?? null}><Outlet /></PageModule.Provider>
        </main>
      </div>
      <ScrollRestoration />
    </div>
  )
}
