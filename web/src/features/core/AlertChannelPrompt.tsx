import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { useModuleEnabled } from '@/lib/modules'
import { useMe } from '@/lib/session'
import { useChannels } from '@/features/notify/api'

/**
 * S-NOT-1 criterion D-462: the setup wizard has no alert channel step, so Home tells an administrator that no alert channel
 * is set up and switched on, with a link to Settings → Alert channels, until one is. Only administrators (they alone read and
 * change channels) and only while the Notifications module is on (switched off, nobody wants alerts).
 */
export function AlertChannelPrompt() {
  const { t } = useTranslation('core')
  const { data: me } = useMe()
  const notifyOn = useModuleEnabled('notify')
  const ask = me?.role === 'admin' && notifyOn === true
  const ch = useChannels({ retry: false, enabled: ask })
  if (!ask || !ch.data || ch.data.channels.some((c) => c.configured && c.enabled)) return null
  return (
    <div role="status" className="mb-6 rounded-md border border-warn/50 bg-warn-soft/60 px-4 py-3 text-sm">
      <p className="font-medium">{t('alertChannelPrompt.title')}</p>
      <p className="mt-1 max-w-prose">{t('alertChannelPrompt.body')}</p>
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2">
        <Button asChild size="sm" variant="primary"><Link to="/settings/channels">{t('alertChannelPrompt.go')}</Link></Button>
        <p className="text-[13px] text-muted">{t('alertChannelPrompt.noAlerts')}</p>
      </div>
    </div>
  )
}
