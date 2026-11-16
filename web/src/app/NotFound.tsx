import { useEffect, useState } from 'react'
import { Link, useRouteError } from 'react-router'
import { useTranslation } from 'react-i18next'
import { BugReportDialog } from '@/features/core/BugReportDialog'
import { Button } from '@/components/ui/button'
import { StandalonePage } from '@/components/common/StandalonePage'
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
  // Shown in place of the whole layout (no sidebar): a standalone page (docs/UI.md §3), the error inside an alert.
  return (
    <StandalonePage title={t('routeError.title')} size="md">
      <div role="alert" className="grid gap-3">
        <p className="text-sm text-muted">{t('routeError.body')}</p>
        <pre className="overflow-x-auto rounded-md bg-sunken p-3 font-mono text-[12px]">{msg}</pre>
        <div className="flex flex-wrap items-center gap-4">
          <a href="/" className="text-accent underline-offset-4 hover:underline">{t('notFound.home')}</a>
          <Button onClick={() => setBug(true)}>{t('routeError.report')}</Button>
        </div>
      </div>
      <BugReportDialog open={bug} onOpenChange={setBug} />
    </StandalonePage>
  )
}
