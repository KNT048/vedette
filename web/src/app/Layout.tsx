import { Suspense, useEffect, useRef, useState } from 'react'
import { Outlet, ScrollRestoration, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Menu } from 'lucide-react'
import { RevokedBanner, RunningVersion } from '@/features/core/UpdateSignals'
import { PageModule } from '@/lib/v1'
import { Button } from '@/components/ui/button'
import { Logo } from '@/components/brand/Logo'
import { Loading } from '@/components/common/States'
import { Slot } from '@/components/common/Slot'
import { useDeepLinkTarget } from '@/components/common/DependencyLink'
import { Dialog, DialogTrigger, DrawerContent } from '@/components/ui/dialog'
import { shellNamespaces } from './feature'
import { Brand, NavList, Sidebar, UserMenu } from './Sidebar'
import { navItemOf, useNavState } from './nav'
import { cn } from '@/lib/utils'

/** Tiêu đề tab trình duyệt theo trang (WCAG 2.4.2) và focus vào nội dung khi đổi trang (trình đọc màn hình đọc trang mới). */
function usePageChrome() {
  const { t, i18n } = useTranslation(['common', ...shellNamespaces])
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
  const { t } = useTranslation(['common', ...shellNamespaces])
  const [open, setOpen] = useState(false)
  // A link in the drawer closes it and the page change moves focus to #main; Esc or the close button return it to "Open menu".
  const byLink = useRef(false)
  const nav = useNavState()
  const loc = useLocation()
  usePageChrome()
  useDeepLinkTarget() // docs/UI.md §0: a deep link's #field is focused once its page has drawn it
  const closeByLink = () => { byLink.current = true; setOpen(false) }
  return (
    <div className={cn('min-h-dvh lg:grid', nav.rail ? 'lg:grid-cols-[56px_1fr]' : 'lg:grid-cols-[240px_1fr]')}>
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-surface focus:px-3 focus:py-2">{t('layout.skip')}</a>
      {/* UI-4: the column paints the background and the rule down the whole page (it stretches with the grid row); only its content
          is sticky. With the background on the sticky h-dvh box, everything below the first screen height showed the page grey. */}
      <div className="hidden border-r border-rule bg-surface lg:block">
        <Sidebar nav={nav} />
      </div>
      {/* The menu button is the Dialog's trigger, so Esc and ✕ give focus back to it (WCAG 2.4.3); a link gives it to #main. */}
      <Dialog open={open} onOpenChange={(v) => { if (v) byLink.current = false; setOpen(v) }}>
        <div className="sticky top-0 z-30 flex h-14 items-center justify-between gap-2 border-b border-rule bg-surface px-4 lg:hidden">
          <DialogTrigger asChild><Button variant="ghost" size="icon" aria-label={t('layout.openMenu')}><Menu /></Button></DialogTrigger>
          <Logo className="h-5.5" />
          {/* docs/UI.md §2: the shell.status slot (#850 "1 scan running"); the empty box keeps the logo centred. */}
          <div className="flex min-w-9 justify-end"><Slot name="shell.status" props={{ compact: true }} /></div>
        </div>
        <DrawerContent title={t('layout.nav')} returnFocus={() => !byLink.current}>
          {/* Header row: brand and org, the ✕ on its right, so the ✕ never sits over an entry. */}
          <div className="flex min-h-10 items-center pr-10"><Brand /></div>
          <NavList nav={nav} drawer onNavigate={closeByLink} />
          <div className="grid gap-1 border-t border-rule pt-3">
            <UserMenu onNavigate={closeByLink} />
            <RunningVersion onNavigate={closeByLink} />
          </div>
        </DrawerContent>
      </Dialog>
      <div className="min-w-0">
        <RevokedBanner />
        <main id="main" tabIndex={-1} key={loc.pathname} className="mx-auto w-full max-w-[1280px] px-4 py-6 outline-none sm:px-6 lg:px-10 lg:py-8">
          <PageModule.Provider value={navItemOf(loc.pathname)?.module ?? null}><Suspense fallback={<Loading />}><Outlet /></Suspense></PageModule.Provider>
        </main>
      </div>
      <ScrollRestoration />
    </div>
  )
}
