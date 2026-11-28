// A finding the customer's AI opened (the AI read the vendor's statement for the release line and its quote is in the page): in every list
// of findings it says so with one chip ("Found by your AI", plus "inferred" when the answer comes from a product that shares code), a link
// to the page it rests on and "Not right?", which rejects the reading in one click (the finding closes on every device of the line and
// the CVE is possible again). A finding that is not the AI's shows nothing.
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Bot, ExternalLink } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { useRejectProposal, useView } from './api'
import { errMsg } from './errors'
import { Chip } from './Possible'
import { evidenceUrl, isInferred } from './research'
import type { PossibleCheck } from './types'

/** The chips, the evidence link and "Not right?" of one AI check. */
export function FoundByAi({ check, cve }: { check: PossibleCheck; cve: string }) {
  const { t } = useTranslation('findings')
  const operator = useCan('operator')
  const reject = useRejectProposal()
  const url = evidenceUrl(check)
  return (
    <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1" data-testid="found-by-ai">
      <Chip tone="accent" icon={Bot} title={check.model ? t('possible.chip.model', { model: check.model }) : undefined}>{t('foundByAi.chip')}</Chip>
      {isInferred(check) ? <Chip tone="off" title={t('review.inferredTitle')}>{t('review.inferred')}</Chip> : null}
      {url ? (
        <a href={url} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()}
          className="inline-flex items-center gap-1 text-meta text-accent underline-offset-4 hover:underline">{t('review.source')}<ExternalLink aria-hidden className="size-3" /></a>
      ) : null}
      <Button size="sm" variant="ghost" className="h-7" disabled={!operator || reject.isPending} title={operator ? t('foundByAi.notRightHow') : t('common:needRole', { role: t('common:role.operator') })}
        aria-label={t('foundByAi.notRightOf', { cve })}
        onClick={(e) => { e.stopPropagation(); reject.mutate({ key: check.key }, { onSuccess: () => toast.success(t('possible.aiReadRejected')), onError: (er) => toast.error(errMsg(er)) }) }}>
        {t('foundByAi.notRight')}
      </Button>
    </span>
  )
}

/** The mark of one finding of a list: reads the finding's view (the lists carry no AI detail) and shows nothing unless the AI opened it. */
export function AiFoundMark({ id, cve }: { id: string; cve: string }) {
  const view = useView(id)
  const check = view.data?.ai_check
  if (!check?.reading || check.rejected) return null
  return <FoundByAi check={check} cve={cve} />
}
