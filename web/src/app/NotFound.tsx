import { useEffect, useState } from 'react'
import { Link, useRouteError } from 'react-router'
import { useTranslation } from 'react-i18next'
import { BugReportDialog } from '@/features/core/BugReportDialog'
import { Button } from '@/components/ui/button'
import { Logo } from '@/components/brand/Logo'
import { recordClientError } from '@/lib/clientErrors'

export function NotFound() {
  const { t } = useTranslation()
  return (
    <div className="max-w-xl">
      <h1 className="text-xl font-semibold">{t('notFound.title')}</h1>
      <p className="mt-2 text-sm text-muted">{t('notFound.body')}</p>
      <Link to="/" className="mt-4 inline-block text-accent underline-offset-4 hover:underline">{t('notFound.home')}</Link>
    </div>
  )
}

export function RouteError() {
  const { t } = useTranslation()
  const err = useRouteError()
  const msg = err instanceof Error ? err.message : String(err)
  const [bug, setBug] = useState(false)
  useEffect(() => { recordClientError(err) }, [err])
  // Shown in place of the whole layout (no sidebar), so the page carries the logo itself, outside the alert.
  return (
    <div className="mx-auto max-w-xl p-8">
      <Logo className="mb-8 h-6" />
      <div role="alert">
        <h1 className="text-xl font-semibold">{t('routeError.title')}</h1>
        <p className="mt-2 text-sm text-muted">{t('routeError.body')}</p>
        <pre className="mt-3 overflow-x-auto rounded-md bg-sunken p-3 font-mono text-caption">{msg}</pre>
        <div className="mt-4 flex flex-wrap items-center gap-4">
          <a href="/" className="text-accent underline-offset-4 hover:underline">{t('notFound.home')}</a>
          <Button onClick={() => setBug(true)}>{t('routeError.report')}</Button>
        </div>
      </div>
      <BugReportDialog open={bug} onOpenChange={setBug} />
    </div>
  )
}
