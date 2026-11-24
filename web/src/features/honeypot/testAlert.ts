import type { TFunction } from 'i18next'
import { toast } from 'sonner'
import type { Hit } from './types'

/** The toast of a test (Test trap, Test scan, Test token): what was recorded, then what each alert channel did with the test alert,
 *  so the person sees the whole path from the trap to their phone. A channel that failed or no channel at all is a warning: a real
 *  touch would not reach anyone that way either. */
export function testAlertToast(t: TFunction, recorded: string, hit: Hit) {
  const sent = hit.test_alert
  if (!sent) { toast.success(recorded); return }
  if (sent.channels.length === 0) { toast.warning(`${recorded}. ${t('honeypot:testAlert.none')}`); return }
  const ok = sent.channels.filter((c) => c.ok).map((c) => c.name)
  const bad = sent.channels.filter((c) => !c.ok)
  const parts = [recorded + '.']
  if (ok.length) parts.push(t('honeypot:testAlert.sent', { channels: ok.join(', ') }))
  for (const c of bad) parts.push(t(c.skipped ? 'honeypot:testAlert.skipped' : 'honeypot:testAlert.failed', { channel: c.name, detail: c.detail }))
  if (bad.some((c) => !c.skipped)) toast.warning(parts.join(' '))
  else toast.success(parts.join(' '))
}
