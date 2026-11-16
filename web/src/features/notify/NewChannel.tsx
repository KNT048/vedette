import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Select } from '@/components/ui/input'
import { useCan } from '@/lib/session'
import { ChannelDialog } from './ChannelsSettings'
import { useChannels, useTestChannel } from './api'
import type { Channel } from './types'

/**
 * Do it where you are (docs/UI.md §0): a page that needs an alert channel sets one up right there, with the same form as
 * Settings › Alert channels, where it stays editable. `type` opens that channel's form directly (the weekly report needs Email);
 * without it the person first chooses the kind among the channels not set up yet (one left: its form opens at once).
 * Only an administrator can read and save channels, so nobody else sees the button (the page says who can instead).
 */
export function NewChannelButton({ type, label, variant = 'primary' }: { type?: Channel['type']; label: string; variant?: 'primary' | 'secondary' }) {
  const { t } = useTranslation('notify')
  const admin = useCan('admin')
  const q = useChannels({ enabled: admin, retry: false })
  const test = useTestChannel()
  const [choosing, setChoosing] = useState(false)
  const [kind, setKind] = useState('')
  const [editing, setEditing] = useState<Channel | null>(null)
  if (!admin || !q.data) return null
  const list = q.data.channels
  const fixed = type ? list.find((c) => c.type === type) : undefined
  const free = list.filter((c) => !c.configured)
  if (type ? !fixed : free.length === 0) return null
  const start = () => {
    if (fixed) setEditing(fixed)
    else if (free.length === 1) setEditing(free[0]!)
    else { setKind(free[0]!.type); setChoosing(true) }
  }
  return (
    <>
      <Button size="sm" variant={variant} onClick={start}><Plus aria-hidden />{label}</Button>
      <Dialog open={choosing} onOpenChange={setChoosing}>
        <DialogContent title={t('newChannel.title')} description={t('newChannel.body')}>
          <Field htmlFor="new-channel-kind" label={t('newChannel.kind')}>
            <Select id="new-channel-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
              {free.map((c) => <option key={c.type} value={c.type}>{t(`ch.${c.type}`)}</option>)}
            </Select>
          </Field>
          <DialogFooter>
            <Button onClick={() => setChoosing(false)}>{t('common:cancel')}</Button>
            <Button variant="primary" disabled={!kind} onClick={() => { setChoosing(false); setEditing(free.find((c) => c.type === kind) ?? null) }}>{t('newChannel.continue')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {editing ? (
        <ChannelDialog key={editing.type} channel={editing} codeUsers={q.data.email_code_users} onClose={() => setEditing(null)}
          onSaved={(thenTest) => {
            const saved = editing.type
            setEditing(null)
            if (thenTest) test.mutate(saved, { onSuccess: (r) => (r.ok ? toast.success(r.detail) : toast.error(r.detail)), onError: (e) => toast.error(e instanceof Error ? e.message : String(e)) })
          }} />
      ) : null}
    </>
  )
}
