import { Link } from 'react-router'
import type { TFunction } from 'i18next'
import type { Alert, DeviceRef, Severity } from './types'

const link = 'text-accent underline-offset-4 hover:underline'

// Statuses and severities are plain words here; a shared status component replaces them when it is on main.
export const severityText = (t: TFunction, s: Severity) => t(`severity.${s}`, { ns: 'common' })

export function DeviceLink({ device, ip }: { device: DeviceRef | null; ip: string }) {
  return device ? <Link to={`/devices/${device.id}`} onClick={(e) => e.stopPropagation()} className={link}>{device.name}</Link> : <span>{ip}</span>
}

/** "source → destination:port", a device by name when the inventory has the address. `plain`: names only, no links (the page
 *  links each device on its own line already). */
export function AlertLine({ a, plain }: { a: Alert; plain?: boolean }) {
  const end = (device: Alert['src_device'], ip: string) => (plain ? <span>{device?.name ?? ip}</span> : <DeviceLink device={device} ip={ip} />)
  return (
    <span className="inline-flex flex-wrap items-baseline gap-x-1 text-meta">
      {end(a.src_device, a.src_ip)}
      <span aria-hidden>→</span>
      {end(a.dst_device, a.dst_ip)}
      {a.dst_port !== null ? <span className="text-muted">{`:${a.dst_port}${a.proto ? `/${a.proto}` : ''}`}</span> : a.proto ? <span className="text-muted">{`/${a.proto}`}</span> : null}
    </span>
  )
}
