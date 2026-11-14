// /link/telegram?c=… and /link/zalo?c=… (S-RESP-2, D-414, D-447): the confirm link the box sends to an approver's chat account. Whoever
// opens it must be signed in as the Vedette user it names; only the Confirm button (a POST with the CSRF token) links, opening the page
// never does. The token and the proof belong to this module (POST /response/me/identities/{channel}/confirm), which refuses another
// signed-in person without spending the link. One page for every confirm-link channel: the channel is the last part of the path.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useLocation, useSearchParams } from 'react-router'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CircleCheck } from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { api, ApiError } from '@/lib/api'
import { useMe } from '@/lib/session'
import type { Identity, IdentityList } from './types'

/** The path's last part → the approval channel whose link it is. */
const CHANNEL = { telegram: 'telegram', zalo: 'zalo-personal' } as const
type Kind = keyof typeof CHANNEL

export default function ChatLinkPage() {
  const { t } = useTranslation('response')
  const kind: Kind = useLocation().pathname.endsWith('/telegram') ? 'telegram' : 'zalo'
  const channel = CHANNEL[kind]
  const [params] = useSearchParams()
  const token = params.get('c') ?? ''
  const me = useMe()
  const qc = useQueryClient()
  const ids = useQuery({ queryKey: ['response', 'me', 'identities'], queryFn: () => api.get<IdentityList>('/response/me/identities'), retry: false })
  const confirm = useMutation({ mutationFn: () => api.post<Identity>(`/response/me/identities/${channel}/confirm`, { code: token }),
    onSettled: () => { void qc.invalidateQueries({ queryKey: ['response'] }) } })
  const [done, setDone] = useState<Identity | null>(null)
  const row = ids.data?.items.find((r) => r.channel === channel)
  const name = t(`chatLink.name.${kind}`)
  // The ID first and plain: a name is free text an administrator typed, the ID is what Vedette will trust.
  const account = row ? t(`chatLink.account.${kind}`, { id: row.address }) : t('chatLink.thisAccount', { name })
  const who = me.data ? `${me.data.name} (${me.data.email})` : ''
  const err = confirm.error instanceof ApiError ? confirm.error.message : confirm.error ? String(confirm.error) : null
  return (
    <div className="max-w-xl">
      <PageHeader title={t('chatLink.title', { name })} stories={['S-RESP-2']} />
      <div className="grid gap-4 rounded-md border border-rule bg-surface p-4">
        {!token ? <p role="alert" className="text-sm">{t('chatLink.noToken', { name })}</p>
          : done ? (
            <p role="status" className="flex items-start gap-2 text-sm"><CircleCheck className="mt-0.5 size-4 shrink-0 text-ok" aria-hidden />{t(`chatLink.linked.${kind}`, { account })}</p>
          ) : row?.linked ? <p role="status" className="text-sm">{t('chatLink.already', { account })}</p> : (
            <>
              <p className="text-sm font-medium">{row ? t('chatLink.question', { name, id: row.address, who }) : t('chatLink.questionNoId', { name, who })}</p>
              {row ? (
                <div className="grid gap-1 rounded-md border border-rule bg-sunken px-3 py-2">
                  <p className="text-sm">{t(`chatLink.idLabel.${kind}`)} <span className="font-mono text-lg font-semibold tracking-wide">{row.address}</span></p>
                  {row.name ? <p className="text-[13px] text-muted">{t('chatLink.namedBy', { name: row.name })}</p> : null}
                </div>
              ) : null}
              <p className="text-[13px] text-muted">{t(`chatLink.explain.${kind}`)}</p>
              {err ? <p role="alert" className="text-sm text-danger">{err}</p> : null}
              <div><Button variant="primary" disabled={confirm.isPending} onClick={() => confirm.mutate(undefined, { onSuccess: setDone })}>{t('chatLink.confirm')}</Button></div>
            </>
          )}
        <p className="text-[13px]"><Link className="underline" to="/settings/account?tab=approvers">{t('chatLink.toAccount')}</Link></p>
      </div>
    </div>
  )
}
