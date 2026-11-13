// /link/zalo?c=… (S-RESP-2, D-447): the confirm link the box's Zalo account sends to an approver. Whoever opens it must be signed in as the
// Vedette user it names; only the Confirm button (a POST with the CSRF token) links, opening the page never does. The proof and the
// token belong to module response (POST /response/me/identities/zalo-personal/confirm), which refuses another signed-in person without
// spending the link.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useSearchParams } from 'react-router'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CircleCheck } from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { api, ApiError } from '@/lib/api'
import { useMe } from '@/lib/session'
import type { Identity, IdentityList } from '@/features/response/types'

export default function ZaloLinkPage() {
  const { t } = useTranslation('notify')
  const [params] = useSearchParams()
  const token = params.get('c') ?? ''
  const me = useMe()
  const qc = useQueryClient()
  const ids = useQuery({ queryKey: ['response', 'me', 'identities'], queryFn: () => api.get<IdentityList>('/response/me/identities'), retry: false })
  const confirm = useMutation({ mutationFn: () => api.post<Identity>('/response/me/identities/zalo-personal/confirm', { code: token }),
    onSettled: () => { void qc.invalidateQueries({ queryKey: ['response'] }) } })
  const [done, setDone] = useState<Identity | null>(null)
  const row = ids.data?.items.find((r) => r.channel === 'zalo-personal')
  // The Zalo ID first and plain: the name is free text an administrator typed, the ID is what Vedette will trust.
  const zalo = row ? t('zl.account', { id: row.address }) : t('zl.thisAccount')
  const err = confirm.error instanceof ApiError ? confirm.error.message : confirm.error ? String(confirm.error) : null
  return (
    <div className="max-w-xl">
      <PageHeader title={t('zl.title')} stories={['S-RESP-2']} />
      <div className="grid gap-4 rounded-md border border-rule bg-surface p-4">
        {!token ? <p role="alert" className="text-sm">{t('zl.noToken')}</p>
          : done ? (
            <p role="status" className="flex items-start gap-2 text-sm"><CircleCheck className="mt-0.5 size-4 shrink-0 text-ok" aria-hidden />{t('zl.linked', { zalo })}</p>
          ) : row?.linked ? <p role="status" className="text-sm">{t('zl.already', { zalo })}</p> : (
            <>
              <p className="text-sm font-medium">{t('zl.question', { who: me.data ? `${me.data.name} (${me.data.email})` : '' })}</p>
              {row ? (
                <div className="grid gap-1 rounded-md border border-rule bg-sunken px-3 py-2">
                  <p className="text-sm">{t('zl.idLabel')} <span className="font-mono text-lg font-semibold tracking-wide">{row.address}</span></p>
                  {row.name ? <p className="text-[13px] text-muted">{t('zl.namedBy', { name: row.name })}</p> : null}
                </div>
              ) : null}
              <p className="text-[13px] text-muted">{t('zl.explain')}</p>
              {err ? <p role="alert" className="text-sm text-danger">{err}</p> : null}
              <div><Button variant="primary" disabled={confirm.isPending} onClick={() => confirm.mutate(undefined, { onSuccess: setDone })}>{t('zl.confirm')}</Button></div>
            </>
          )}
        <p className="text-[13px]"><Link className="underline" to="/account">{t('zl.toAccount')}</Link></p>
      </div>
    </div>
  )
}
