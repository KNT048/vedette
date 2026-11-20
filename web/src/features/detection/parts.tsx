import { Link } from 'react-router'
import type { TFunction } from 'i18next'
import type { Alert, DeviceRef, Severity } from './types'

const link = 'text-accent underline-offset-4 hover:underline'

// Statuses and severities are plain words here; a shared status component replaces them when it is on main.
export const severityText = (t: TFunction, s: Severity) => t(`severity.${s}`, { ns: 'common' })

export function DeviceLink({ device, ip }: { device: DeviceRef | null; ip: string }) {
  return device ? <Link to={`/devices/${device.id}`} onClick={(e) => e.stopPropagation()} className={link}>{device.name}</Link> : <span>{ip}</span>
}

/** "source → destination:port", a device by name when the inventory has the address. */
export function AlertLine({ a }: { a: Alert }) {
  return (
    <span className="inline-flex flex-wrap items-baseline gap-x-1 text-meta">
      <DeviceLink device={a.src_device} ip={a.src_ip} />
      <span aria-hidden>→</span>
      <DeviceLink device={a.dst_device} ip={a.dst_ip} />
      {a.dst_port !== null ? <span className="text-muted">{`:${a.dst_port}${a.proto ? `/${a.proto}` : ''}`}</span> : a.proto ? <span className="text-muted">{`/${a.proto}`}</span> : null}
    </span>
  )
}
