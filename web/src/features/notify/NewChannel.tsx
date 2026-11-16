import { useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Plus } from 'lucide-react'
import { Button, buttonVariants } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Select } from '@/components/ui/input'
import { useCan } from '@/lib/session'
import { ChannelDialog } from './ChannelsSettings'
import { useChannels, useTestChannel } from './api'
import type { Channel } from './types'

/**
 * Do it where you are (docs/UI.md §0): a page that needs an alert channel sets one up right there, with the same form as
 * Settings › Alert channels, where it stays editable. `type` opens that channel's form directly (the weekly report needs Email);
 * without it the person first chooses among the channels that are set up but off and those not set up yet (one: its form opens
 * at once). Only an administrator can read and save channels, so nobody else gets the button (the page says who can instead).
 *
 * The page calls the hook once and renders `dialogs` where it always stays mounted, and `button(label)` wherever the need shows.
 * The button goes away as soon as a channel is on; the dialogs must not (review r1 M1 of #879): a Zalo personal form stays open
 * after Save to show who is linked, and "Save and send a test" shows the test result after the save turned the channel on.
 */
export function useNewChannel(type?: Channel['type']): { button: (label: string, variant?: 'primary' | 'secondary') => ReactNode; dialogs: ReactNode } {
  const { t } = useTranslation('notify')
  const admin = useCan('admin')
  const q = useChannels({ enabled: admin, retry: false })
  const test = useTestChannel()
  const [choosing, setChoosing] = useState(false)
  const [kind, setKind] = useState('')
  const [editing, setEditing] = useState<Channel | null>(null)
  const opener = useRef<HTMLButtonElement>(null)
  const list = q.data?.channels ?? []
  // a channel set up but switched off is offered first: turning it on is what is missing, not a second channel
  const open = type ? list.filter((c) => c.type === type) : [...list.filter((c) => c.configured && !c.enabled), ...list.filter((c) => !c.configured)]
  // §8: focus returns to the opener when the form closes (the chooser that opened it is gone by then)
  const back = () => requestAnimationFrame(() => { if (opener.current?.isConnected) opener.current.focus() })
  const start = () => {
    if (open.length === 1) setEditing(open[0]!)
    else { setKind(open[0]!.type); setChoosing(true) }
  }
  const button = (label: string, variant: 'primary' | 'secondary' = 'primary'): ReactNode => {
    if (!admin || q.isPending) return null
    // the channels could not be read, or there is nothing to set up here: the exact place in Settings, never a dead end
    if (!q.data || open.length === 0) {
      return <Link to={type ? `/settings/channels#channel-${type}` : '/settings/channels#channels'} className={buttonVariants({ variant, size: 'sm' })}>{label}</Link>
    }
    return <Button ref={opener} size="sm" variant={variant} onClick={start}><Plus aria-hidden />{label}</Button>
  }
  const dialogs = q.data ? (
    <>
      <Dialog open={choosing} onOpenChange={setChoosing}>
        <DialogContent title={t('newChannel.title')} description={t('newChannel.body')}>
          <Field htmlFor="new-channel-kind" label={t('newChannel.kind')}>
            <Select id="new-channel-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
              {open.map((c) => <option key={c.type} value={c.type}>{c.configured ? t('newChannel.off', { name: t(`ch.${c.type}`) }) : t(`ch.${c.type}`)}</option>)}
            </Select>
          </Field>
          <DialogFooter>
            <Button onClick={() => setChoosing(false)}>{t('common:cancel')}</Button>
            <Button variant="primary" disabled={!kind} onClick={() => { setChoosing(false); setEditing(open.find((c) => c.type === kind) ?? null) }}>{t('newChannel.continue')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {editing ? (
        <ChannelDialog key={editing.type} channel={editing} codeUsers={q.data.email_code_users} onClose={() => { setEditing(null); back() }}
          onSaved={(thenTest) => {
            const saved = editing.type
            setEditing(null)
            back()
            if (thenTest) test.mutate(saved, { onSuccess: (r) => (r.ok ? toast.success(r.detail) : toast.error(r.detail)), onError: (e) => toast.error(e instanceof Error ? e.message : String(e)) })
          }} />
      ) : null}
    </>
  ) : null
  return { button, dialogs }
}
