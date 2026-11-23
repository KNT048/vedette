// Where each watcher's one action leads (need -> place): the page that shows it, or the exact spot that sets it up.
import type { Watcher } from './types'

/** `container`: a container-only install sets the mirror port on the sensor card, an appliance in Box network. */
export function actionTarget(w: Pick<Watcher, 'id' | 'action'>, container: boolean): string | null {
  if (!w.action) return null
  if (w.action === 'turn_on') return `/settings/modules#module-${w.id === 'traps' ? 'honeypot' : w.id === 'logs' ? 'logs' : w.id === 'mirror_port' ? 'sensor-passive' : 'ids'}`
  switch (w.id) {
    case 'traps': return w.action === 'set_up' ? '/honeypot?tab=trap-ips' : '/honeypot'
    case 'logs': return w.action === 'set_up' ? '/logs?tab=sources&add=source' : '/logs?tab=sources' // Add opens the add dialog there
    case 'mirror_port': return container ? '/devices/setup?tab=sensor' : '/settings/network#span'
    case 'ips_events': return w.action === 'view' ? '#alerts' : w.action === 'set_up' ? '/logs?tab=sources&add=source' : '/logs?tab=sources'
  }
}
