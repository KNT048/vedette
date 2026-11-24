import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { nav } from './util'

/** The part of the shared waiting rule (useRestartWait) a page shows when Vedette stays unreachable: what to check, and a reload. */
export function RestartSlow({ wait }: { wait: { slow: boolean } }) {
  const { t } = useTranslation('core')
  if (!wait.slow) return null
  return (
    <div className="grid gap-2">
      <p role="alert" className="text-sm">{t('restartWait.slow')}</p>
      <div><Button onClick={() => nav.reload()}>{t('restartWait.reload')}</Button></div>
    </div>
  )
}
