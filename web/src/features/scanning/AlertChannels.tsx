import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Select } from '@/components/ui/input'
import { ChannelDialog } from '@/features/notify/ChannelsSettings'
import { useChannels } from '@/features/notify/api'
import type { Channel } from '@/features/notify/types'
import { useModuleEnabled } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { TurnOnModule } from './Fixes'

/**
 * #850 (docs/UI.md §0): where the vulnerability checks' matches go, on the Nuclei card. Matches alert through every channel that is on
 * (there is no per-engine routing), so the card names them and offers "+ New channel" right here: choose the kind, then the same
 * form as Settings › Alert channels (notify's ChannelDialog), saved and switched on there too. Alert channels are an administrator's
 * section: a viewer or operator is told who sets them up, with no link to a page they cannot open; an admin turns notify on here
 * (#877 r1 L7).
 */
export function AlertChannels() {
  const { t } = useTranslation(['scanning', 'notify'])
  const admin = useCan('admin')
  const on = useModuleEnabled('notify') === true
  const q = useChannels({ enabled: on && admin, retry: false })
  const [choosing, setChoosing] = useState(false)
  const [kind, setKind] = useState('')
  const [editing, setEditing] = useState<Channel | null>(null)
  if (!admin) return <p className="text-meta text-muted">{t('alerts.askAdmin')}</p>
  if (!on) return <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-meta"><span className="text-muted">{t('alerts.notifyOff')}</span><TurnOnModule module="notify" name={t('common:modules.notify.name')} /></div>
  const list = q.data?.channels ?? []
  const live = list.filter((c) => c.configured && c.enabled).map((c) => t(`notify:ch.${c.type}`))
  const free = list.filter((c) => !c.configured)
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-meta">
      <span className="text-muted">{live.length ? t('alerts.sentTo', { list: live.join(', ') }) : t('alerts.none')}</span>
      {free.length ? <Button size="sm" variant="ghost" onClick={() => { setKind(free[0]!.type); setChoosing(true) }}><Plus />{t('alerts.new')}</Button> : null}
      <Dialog open={choosing} onOpenChange={setChoosing}>
        <DialogContent title={t('alerts.chooseTitle')} description={t('alerts.chooseBody')}>
          <Field htmlFor="alert-kind" label={t('alerts.kind')}>
            <Select id="alert-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
              {free.map((c) => <option key={c.type} value={c.type}>{t(`notify:ch.${c.type}`)}</option>)}
            </Select>
          </Field>
          <DialogFooter>
            <Button onClick={() => setChoosing(false)}>{t('common:cancel')}</Button>
            <Button variant="primary" disabled={!kind} onClick={() => { setChoosing(false); setEditing(free.find((c) => c.type === kind) ?? null) }}>{t('alerts.continue')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {editing && q.data ? (
        <ChannelDialog key={editing.type} channel={editing} codeUsers={q.data.email_code_users}
          onClose={() => setEditing(null)} onSaved={() => { toast.success(t('alerts.added', { name: t(`notify:ch.${editing.type}`) })); setEditing(null) }} />
      ) : null}
    </div>
  )
}
