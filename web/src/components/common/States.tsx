import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { Button } from '@/components/ui/button'
import { useModuleEnabled, useModules, type ModuleId } from '@/lib/modules'
import { notOffered } from '@/lib/v1'
import { ApiError } from '@/lib/api'
import { InfoTip } from './InfoTip'
import { PageHeader } from './PageHeader'
import { Illustration, type IllustrationName } from './Illustration'

/** An empty screen is guidance for an action (FRONTEND §3). `children` is one short line; a long explanation goes into `info` (ⓘ next to the heading, #824). */
/*  `art` (docs/UI.md §6): only when nothing exists yet (first run, no devices…): the #827 drawing, centred. A filter that matches
    nothing stays text only (DataTable `emptyFiltered`). */
export function EmptyState({ title, children, info, action, art }: { title: string; children?: ReactNode; info?: ReactNode; action?: ReactNode; art?: IllustrationName }) {
  if (art) {
    return (
      <div className="grid justify-items-center gap-1 rounded-md border border-rule bg-surface px-6 py-10 text-center">
        <Illustration name={art} className="mb-3" />
        <div className="flex items-center gap-1">
          <p className="font-medium">{title}</p>
          {info ? <InfoTip topic={title}>{info}</InfoTip> : null}
        </div>
        {children ? <div className="max-w-md text-sm text-muted">{children}</div> : null}
        {action ? <div className="mt-3">{action}</div> : null}
      </div>
    )
  }
  return (
    <div className="rounded-md border border-dashed border-rule bg-surface px-6 py-8">
      <div className="flex items-center gap-1">
        <p className="font-medium">{title}</p>
        {info ? <InfoTip topic={title}>{info}</InfoTip> : null}
      </div>
      {children ? <div className="mt-1 max-w-2xl text-sm text-muted">{children}</div> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  )
}

/** An error says what is wrong and how to fix it; it does not apologise. */
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const { t } = useTranslation()
  const msg = error instanceof ApiError ? error.message : error instanceof Error ? error.message : String(error)
  const status = error instanceof ApiError ? error.status : 0
  // 4xx and 501: retrying does not help: say the kind of error, no retry button. Other 5xx/network loss: allow a retry.
  const kind = error instanceof ApiError && status === 409 ? (error.code === 'not_appliance' ? 'notOnInstall' : 'unavailable') : status === 404 ? 'notFound' : status === 403 ? 'forbidden' : status === 401 ? 'unauthenticated' : status >= 400 && status < 500 ? 'invalid' : 'loadFailed'
  const retry = kind === 'loadFailed' && status !== 501 && onRetry
  return (
    <div role="alert" className={kind === 'loadFailed' ? 'rounded-md border border-danger/40 bg-danger-soft px-4 py-3 text-sm' : 'rounded-md border border-rule bg-surface px-4 py-3 text-sm'}>
      <p className={kind === 'loadFailed' ? 'font-medium text-danger' : 'font-medium'}>{t(`error.${kind}`)}</p>
      <p className="mt-1 text-ink">{msg}</p>
      {retry ? <Button className="mt-3" size="sm" onClick={onRetry}>{t('retry')}</Button> : null}
      {/* 501: the backend does not have this part yet; old sample data is irrelevant, so do not offer to restore it. */}
      {status === 501 ? <p className="mt-3 text-meta text-muted">{t('error.notImplemented')}</p> : null}
      {/* Preview build: another 5xx is usually sample data saved by an older version of the UI */}
      {status >= 500 && status !== 501 && import.meta.env.VITE_API_MOCK !== 'off' ? <p className="mt-3 text-meta text-muted">{t('error.previewStale')} <Link to="/settings/data" className="text-accent underline underline-offset-4">{t('error.previewStaleLink')}</Link></p> : null}
    </div>
  )
}

export function Loading({ label }: { label?: string }) {
  const { t } = useTranslation()
  return (
    <div role="status" aria-live="polite" className="grid gap-2 py-6">
      <span className="sr-only">{label ?? t('loading')}</span>
      <div className="h-4 w-1/3 rounded bg-sunken" />
      <div className="h-4 w-2/3 rounded bg-sunken" />
      <div className="h-4 w-1/2 rounded bg-sunken" />
    </div>
  )
}

/** Bundles the 3 states of a query: loading / error / has data. */
export function QueryState<T>({ query, children }: { query: { data: T | undefined; error: unknown; isPending: boolean; refetch: () => unknown }; children: (data: T) => ReactNode }) {
  // Read all three properties now: TanStack Query only re-renders for the properties that were read (tracked props).
  const { data, error, isPending } = query
  if (error) return <ErrorState error={error} onRetry={() => void query.refetch()} />
  if (isPending || data === undefined) return <Loading />
  return <>{children(data)}</>
}

/** S-CORE-1: when a module is off, say why data is missing and where to turn it on. `page`: it stands in for a whole page, so it carries the page's
 *  h1 (the module's name), as every page has one (docs/UI.md §3; /settings/mcp and the module-off pages had none). */
export function ModuleOff({ module, children, page }: { module: ModuleId; children?: ReactNode; page?: boolean }) {
  const { t } = useTranslation()
  const box = <ModuleOffBox module={module}>{children}</ModuleOffBox>
  return page ? <><PageHeader title={t(`modules.${module}.name`)} />{box}</> : box
}

function ModuleOffBox({ module, children }: { module: ModuleId; children?: ReactNode }) {
  const { t } = useTranslation()
  // A module this install cannot run (available false: needs vedette-host on a container-only install) cannot be
  // turned on, so the box says so instead of inviting the user to switch it on (S-CORE-9).
  const notHere = useModules().data?.modules.find((m) => m.id === module)?.available === false
  if (notHere) {
    return (
      <div className="rounded-md border border-rule bg-off-soft px-4 py-3 text-sm">
        <div className="flex items-center gap-1">
          <p className="font-medium">{t('moduleOff.notHereTitle', { name: t(`modules.${module}.name`) })}</p>
          <InfoTip topic={t(`modules.${module}.name`)}>{t('moduleOff.notHereInfo')}</InfoTip>
        </div>
        <p className="mt-1 text-muted">{t('moduleOff.notHereBody')}</p>
      </div>
    )
  }
  // A module this build does not offer cannot be turned on from Settings → Modules, so no link there.
  if (notOffered(module)) {
    return (
      <div className="rounded-md border border-rule bg-off-soft px-4 py-3 text-sm">
        <p className="font-medium">{t('moduleOff.notOfferedTitle', { name: t(`modules.${module}.name`) })}</p>
        <p className="mt-1 text-muted">{t('moduleOff.notOfferedBody')}</p>
      </div>
    )
  }
  return (
    <div className="rounded-md border border-rule bg-off-soft px-4 py-3 text-sm">
      <p className="font-medium">{t('moduleOff.title', { name: t(`modules.${module}.name`) })}</p>
      <p className="mt-1 text-muted">{children ?? t('moduleOff.body')}</p>
      <Link to={`/settings/modules#module-${module}`} className="mt-2 inline-block text-accent underline-offset-4 hover:underline">{t('moduleOff.enable')}</Link>
    </div>
  )
}

/** Wraps content that depends on a module: off → ModuleOff; loading → shows nothing. */
export function RequireModule({ module, children, fallback, page }: { module: ModuleId; children: ReactNode; fallback?: ReactNode; page?: boolean }) {
  const on = useModuleEnabled(module)
  if (on === undefined) return null
  if (!on) return <>{fallback ?? <ModuleOff module={module} page={page} />}</>
  return <>{children}</>
}

