import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Card } from '@/components/common/Card'
import { Notice, Section } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { Switch } from '@/components/ui/switch'
import { useCan } from '@/lib/session'
import { useAskConnections, useSetAskConnection } from './api'
import { ActionError } from './parts'

/** S-AI-5: a read tool of a connection gets the arguments the AI writes, and the AI reads text it did not write (device names, logs,
 *  pages). A connection inside the network is always usable in Ask; one outside it only after an administrator allows it here. */
export function AskConnectionsSection() {
  const { t } = useTranslation('ai')
  const admin = useCan('admin')
  const list = useAskConnections(admin)
  const set = useSetAskConnection()
  if (!admin) return null
  return (
    <QueryState query={list}>
      {(v) => v.items.length === 0 ? null : (
        <Section title={t('settings.askConn.title')} description={t('settings.askConn.intro')} info={<p>{t('settings.askConn.info')}</p>} stories={['S-AI-5']}>
          {v.notice ? <Notice tone="warn" role="status" title={t('settings.askConn.notice')} /> : null}
          <Card className="grid gap-4">
            {v.items.map((c) => (
              <div key={c.id} className="flex items-start gap-3">
                <Switch id={`ask-conn-${c.id}`} checked={c.allowed} disabled={set.isPending}
                  onCheckedChange={(allowed) => set.mutate({ id: c.id, allowed }, { onSuccess: () => toast.success(t('settings.saved')) })} />
                <div className="grid gap-0.5">
                  <label htmlFor={`ask-conn-${c.id}`} className="font-medium">{t('settings.askConn.switch', { name: c.name })}</label>
                  <p className="text-meta text-muted break-all">{c.address}</p>
                </div>
              </div>
            ))}
          </Card>
          {set.error ? <div className="mt-3"><ActionError error={set.error} /></div> : null}
        </Section>
      )}
    </QueryState>
  )
}
