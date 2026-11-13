// Shared by sensors.global.spec.ts (WP-30 slice 7): the devices the sensors make, and giving the box back.
// The passive sensor is the REAL `vedette-sensor passive` replaying modules/sensor-passive/testdata/lan-discovery.pcap; the active one is the REAL
// `vedette-sensor active` with a fake nmap (cmd/vedette/e2esensor_test.go). Both are started through the control endpoint (box.ts: sensorCtl).
import { expect, type APIRequestContext } from '@playwright/test'
import { api, sensorCtl } from './box'
export { as } from './findings-seed'

export interface Svc { port: number; proto?: string; name?: string; product?: string | null; version?: string | null; source: string; confidence: number }
export interface Obs { id: string; field: string; value: string; source: string; confidence: number; current: boolean }
export interface Dev {
  id: string; ip: string; mac: string | null; kind: string; hostname: string | null; approved: boolean; is_box: boolean; first_scan_at: string | null; origin: string
  vendor: { value: string; source: string; confidence: number } | null; model: { value: string; source: string; confidence: number } | null; os: { value: string; source: string; confidence: number } | null
  summary: { source: string; confidence: number } | null; services: Svc[]
  software: { display: string; source: string; confidence: number }[]
}
export interface DevList { items: Dev[]; counts: { all: number; pending: number }; notify_new: boolean }

/** What lan-discovery.pcap holds (read from a real run of the sensor; the sweep fixture adds 192.168.10.2 and .5). */
export const ROUTER = { ip: '192.168.10.1', mac: 'aa:bb:cc:00:00:13', model: 'FRITZ!Box 7590' }
export const PC = { ip: '192.168.10.21', mac: 'aa:bb:cc:00:00:11', hostname: 'PC-ACCOUNTING-01' }
/** Every MAC and every address a sensor of this slice can make a device of: they must not exist when a file starts, and they are removed when it ends. */
export const MACS = [ROUTER.mac, PC.mac, 'aa:bb:cc:00:00:02', 'aa:bb:cc:00:00:05']
const inRange = (ip: string) => ip.startsWith('192.168.10.')

export async function devices(c: APIRequestContext): Promise<DevList> {
  const r = await api<DevList>(c, 'GET', '/inventory/devices')
  expect(r.status, `GET /inventory/devices: ${JSON.stringify(r.body)}`).toBe(200)
  return r.body
}
export async function device(c: APIRequestContext, id: string) {
  const r = await api<{ asset: Dev; observations: Obs[] }>(c, 'GET', `/inventory/devices/${id}`)
  expect(r.status, `GET /inventory/devices/${id}`).toBe(200)
  return r.body
}
/** The devices a sensor of this slice made (any device in 192.168.10.0/24 or with one of the replayed MACs), never the box itself. */
export const made = (l: DevList) => l.items.filter((d) => !d.is_box && (inRange(d.ip) || (d.mac !== null && MACS.includes(d.mac.toLowerCase()))))

/** The box must not hold a device of these sensors when a file starts: a leftover would make the first wait pass at once. */
export async function expectNoSensorDevices(c: APIRequestContext) {
  expect(made(await devices(c)).map((d) => `${d.ip} ${d.mac}`), 'this file needs a box with no device from the replayed recording or the fake scan').toEqual([])
}
/** Stops both sensors, resolves the "unknown device" alerts of the devices they made, removes those devices, checking every status, then reads the list back. Safe to call twice. */
export async function giveBack(c: APIRequestContext) {
  for (const role of ['passive', 'active'] as const) await sensorCtl({ stop: role })
  const gone = made(await devices(c))
  const ids = new Set(gone.map((d) => d.id))
  const incidents = await api<{ incidents: { id: string; status: string; devices: { id: string }[] }[] }>(c, 'GET', '/notify/incidents')
  expect(incidents.status, 'GET /notify/incidents').toBe(200)
  for (const i of incidents.body.incidents.filter((x) => x.status !== 'resolved' && x.devices.some((d) => ids.has(d.id)))) {
    expect((await api(c, 'PATCH', `/notify/incidents/${i.id}`, { status: 'resolved', note: 'e2e: the device was removed again' })).status, `resolve incident ${i.id}`).toBe(200)
  }
  for (const d of gone) expect((await api(c, 'DELETE', `/inventory/devices/${d.id}`)).status, `cleanup of device ${d.ip}`).toBe(204)
  expect(made(await devices(c)).map((d) => d.ip), 'the devices of the sensors are gone').toEqual([])
}
