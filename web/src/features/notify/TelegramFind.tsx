import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { BusyNote } from '@/components/common/BusyNote'
import { ApiError } from '@/lib/api'
import { useFindTelegramChats } from './api'
import type { TelegramChat } from './types'

/**
 * "Find my chat" under the Telegram Chat ID: after the token is typed and a message was sent to the bot, the box asks Telegram
 * which chats it saw; picking one fills the Chat ID. With no token typed it uses the saved one (it never leaves the box).
 */
export function TelegramFind({ token, hasSaved, chatId, onPick, onTokenError }: { token: string; hasSaved: boolean; chatId: string; onPick: (id: string) => void; onTokenError: (msg: string) => void }) {
  const { t } = useTranslation('notify')
  const find = useFindTelegramChats()
  const [chats, setChats] = useState<TelegramChat[] | null>(null)
  const [fresh, setFresh] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const ready = token.trim() !== '' || hasSaved
  const label = (c: TelegramChat) => `${c.name || c.id}${c.username ? ` (@${c.username})` : ''}`
  function run() {
    setError(null)
    setChats(null)
    find.mutate(token.trim(), {
      onSuccess: (r) => { setChats(r.items); setFresh(r.fresh) },
      onError: (e) => {
        const msg = e instanceof ApiError ? e.message : String(e)
        if (e instanceof ApiError && e.code === 'bad_token') onTokenError(msg) // under the token field, as Save does
        else setError(msg)
      },
    })
  }
  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <Button disabled={!ready} busy={find.isPending} busyLabel={t('tgFind.finding')} onClick={run}>
          {t('tgFind.button')}
        </Button>
        {!ready ? <span className="text-meta text-muted">{t('tgFind.needToken')}</span> : null}
      </div>
      {/* One getUpdates call to Telegram, 15 s at most */}
      <BusyNote busy={find.isPending}>{t('tgFind.waiting')}</BusyNote>
      {error ? <p role="alert" className="text-meta text-danger">{error}</p> : null}
      {chats && chats.length === 0 ? <p role="status" className="text-meta text-muted">{t(fresh ? 'tgFind.fresh' : 'tgFind.none')}</p> : null}
      {chats && chats.length > 0 ? (
        <fieldset className="grid gap-1 rounded-md border border-rule p-2">
          <legend className="px-1 text-meta font-medium">{t('tgFind.pick')}</legend>
          {chats.map((c) => (
            <Button key={c.id} aria-pressed={chatId === c.id} onClick={() => onPick(c.id)} className="justify-start">
              {t('tgFind.option', { name: label(c), kind: t(`tgFind.kind.${c.kind}`), id: c.id })}
            </Button>
          ))}
        </fieldset>
      ) : null}
    </div>
  )
}
