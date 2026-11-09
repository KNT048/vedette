import type { TFunction } from 'i18next'
import type { Hit } from './types'

/** Name of what was touched: the service on the classic ports, otherwise the label (token, scan, other decoy port). */
export const hitName = (t: TFunction<'honeypot'>, h: Hit) => (h.service ? t(`service.${h.service}`) : h.label)
