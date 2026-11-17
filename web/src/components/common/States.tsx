import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { Button } from '@/components/ui/button'
import { useModuleEnabled, useModules, type ModuleId } from '@/lib/modules'
import { notOffered } from '@/lib/v1'
import { ApiError, api } from '@/lib/api'
import { InfoTip } from './InfoTip'
import { PageHeader } from './PageHeader'
import { useQuery } from '@tanstack/react-query'
import { Illustration, type IllustrationName } from './Illustration'

/** Màn trống là hướng dẫn hành động (FRONTEND §3). `children` một dòng ngắn; giải thích dài vào `info` (ⓘ cạnh tiêu đề, #824). */
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

/** Lỗi nói cái gì sai và sửa thế nào; không xin lỗi. */
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const { t } = useTranslation()
  const msg = error instanceof ApiError ? error.message : error instanceof Error ? error.message : String(error)
  const status = error instanceof ApiError ? error.status : 0
  // 4xx và 501: thử lại không giúp gì → nói rõ loại lỗi, không có nút thử lại. 5xx khác/mất mạng: cho thử lại.
  const kind = error instanceof ApiError && status === 409 ? (error.code === 'not_appliance' ? 'notOnInstall' : 'unavailable') : status === 404 ? 'notFound' : status === 403 ? 'forbidden' : status === 401 ? 'unauthenticated' : status >= 400 && status < 500 ? 'invalid' : 'loadFailed'
  const retry = kind === 'loadFailed' && status !== 501 && onRetry
  return (
    <div role="alert" className={kind === 'loadFailed' ? 'rounded-md border border-danger/40 bg-danger-soft px-4 py-3 text-sm' : 'rounded-md border border-rule bg-surface px-4 py-3 text-sm'}>
      <p className={kind === 'loadFailed' ? 'font-medium text-danger' : 'font-medium'}>{t(`error.${kind}`)}</p>
      <p className="mt-1 text-ink">{msg}</p>
      {retry ? <Button className="mt-3" size="sm" onClick={onRetry}>{t('retry')}</Button> : null}
      {/* 501: backend chưa có phần này; dữ liệu mẫu cũ không liên quan nên không mời khôi phục. */}
      {status === 501 ? <p className="mt-3 text-meta text-muted">{t('error.notImplemented')}</p> : null}
      {/* Bản xem thử: lỗi 5xx khác thường do dữ liệu mẫu lưu từ phiên bản cũ của giao diện */}
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

/** Gói 3 trạng thái của một query: đang tải / lỗi / có dữ liệu. */
export function QueryState<T>({ query, children }: { query: { data: T | undefined; error: unknown; isPending: boolean; refetch: () => unknown }; children: (data: T) => ReactNode }) {
  // Đọc cả ba thuộc tính ngay: TanStack Query chỉ render lại theo thuộc tính đã đọc (tracked props).
  const { data, error, isPending } = query
  if (error) return <ErrorState error={error} onRetry={() => void query.refetch()} />
  if (isPending || data === undefined) return <Loading />
  return <>{children(data)}</>
}

/** S-CORE-1: module tắt thì nói rõ vì sao thiếu dữ liệu và chỗ bật. `page`: it stands in for a whole page, so it carries the page's
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

/** Bọc nội dung phụ thuộc một module: tắt → ModuleOff; đang tải → không hiện gì. */
export function RequireModule({ module, children, fallback, page }: { module: ModuleId; children: ReactNode; fallback?: ReactNode; page?: boolean }) {
  const on = useModuleEnabled(module)
  if (on === undefined) return null
  if (!on) return <>{fallback ?? <ModuleOff module={module} page={page} />}</>
  return <>{children}</>
}

/** Nhãn "Dữ liệu mẫu" khi chạy trên mock API (rủi ro: người test tin dữ liệu giả, ROADMAP). */
export function SampleDataNote() {
  const { t } = useTranslation()
  // Cùng queryKey với useSetup (src/app/RequireSession.tsx). Cài sạch → không có dữ liệu mẫu nào để ghi nhãn.
  const setup = useQuery({ queryKey: ['setup'], queryFn: () => api.get<{ complete: boolean; org: string; data_mode?: 'sample' | 'clean' }>('/setup'), staleTime: 60_000 })
  if (import.meta.env.VITE_API_MOCK === 'off' || setup.data?.data_mode !== 'sample') return null
  return <span className="inline-flex h-6 items-center rounded-sm border border-rule bg-sunken px-2 text-caption text-muted">{t('sampleData')}</span>
}
