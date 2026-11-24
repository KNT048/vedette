import i18n from '@/lib/i18n'
import type { Asset } from '@/lib/types'

/** `software`: the device's lines (the device page); `product`: the one line the Devices list sends for a hand-added device (its first
 *  installed line by name), since the list carries no lines. */
type Named = Pick<Asset, 'hostname' | 'vendor' | 'model' | 'ip'> & { name?: Asset['name']; origin?: Asset['origin']; os?: Asset['os']; software?: { display: string; not_installed?: boolean }[]; product?: { display: string } | null }

/** The name a person gave the device in Vedette, trimmed; '' when none. */
const userName = (a: Named) => a.name?.trim() ?? ''

const hasIp = (a: Named) => !!a.ip && a.ip !== '—'

/** The maker a network scan or the passive sensor reports is the one of the device's network card (the MAC's IEEE prefix), as the
 *  backend's `inventory.CardVendor`: who made the card, not what the device is. */
const cardVendor = (o: Asset['vendor']) => !!o && !o.software_id && (o.source === 'nmap' || o.source === 'passive')

/** The product an OS or firmware text names, without its release (the backend's `inventory.OSProduct`): the words before the first
 *  one that starts with a digit or a bracket ("VMware ESXi 8.0 Update 3 (build 24022510)" is "VMware ESXi"). */
export function osProduct(os: string): string {
  const words: string[] = []
  for (const w of os.split(/\s+/).filter(Boolean)) {
    if (/^[0-9([-]/.test(w)) break
    words.push(w)
  }
  return words.join(' ')
}

/** The OS the naming rule may use (the backend's `inventory.NamingOS`): never a network scan's fingerprint guess, never a declared OS row. */
const namingOS = (o: Asset['os'] | undefined) => (o && o.basis !== 'guess' && !o.software_id && o.source !== 'declared' ? o.value.trim() : '')

/** One naming rule for every module, exactly like the backend's `inventory.DisplayName` (findings, scans, reports, their mocks):
 *  the name a person gave in Vedette (`name`) always wins when present; then the host name (the name typed at hand declaration is also the host name); a hand-declared device follows its first product, with no IP "<product> (no device)",
 *  never an empty row name; a discovered device gets vendor + model, unless the maker is only its network card's and no model is
 *  known; then the product of the OS or firmware it states ("VMware ESXi"); then "<card maker> device"; then the IP. '' when nothing is known. */
// Its words are in the bundled `common` namespace: other features (Runs, a finding's firewall list) call it outside any component that
// waits for `inventory`, and a lazy namespace would show the raw key there ("makerDevice").
export function displayName(a: Named): string {
  if (userName(a)) return userName(a)
  if (a.hostname) return a.hostname
  // The backend lists software by display name (ORDER BY display): the first of them, whatever order this array has.
  // what it runs: never a line a person said is not installed
  const product = a.origin !== 'manual' ? undefined : a.software ? a.software.filter((s) => !s.not_installed).map((s) => s.display.trim()).filter(Boolean).sort()[0] : a.product?.display.trim() || undefined
  if (product) return hasIp(a) ? product : i18n.t('common:device.noDevice', { product })
  // A maker or model read from a person's declared OS row (software_id) is not the observations' (inventory INV-45): the backend's
  // naming rule leaves it out, and so does this one, so a device has one name on every page.
  const vendor = a.vendor && !a.vendor.software_id ? a.vendor.value.trim() : ''
  const model = a.model && !a.model.software_id ? a.model.value.trim() : ''
  if (model || (vendor && !cardVendor(a.vendor))) return [vendor, model].filter(Boolean).join(' ')
  const os = osProduct(namingOS(a.os))
  if (os) return os
  if (vendor) return i18n.t('common:device.makerDevice', { maker: vendor })
  return hasIp(a) ? a.ip : ''
}

/** The name on the Devices page: like `displayName`, but a device known only by IP gets its type too ("Router 192.168.1.1"), and one known by nothing gets the type. */
export function nameOf(a: Named, fallback: string) {
  if (userName(a)) return userName(a) // a person's name is shown as typed, even when it is the IP
  const name = displayName(a)
  return name && name === a.ip ? `${fallback} ${a.ip}` : name || fallback
}

/** A product someone said they run, with no address and no name (the add form's software path, CSV, the weekly "I have this"):
 *  declared software, not a device; nothing scans it, it is matched against exploited CVEs by its product. */
export const declaredSoftwareOnly = (a: Named) => a.origin === 'manual' && !a.hostname && !hasIp(a)

/** A device a person added by hand that no sensor, scan or agent has reported since. The inventory writes last_seen = first_seen =
 *  the time it was added, and only a report moves last_seen (max of the report's time), never a person's edit; so last_seen is a
 *  sighting only once it is past first_seen. Such a device reads "Never seen on the network" and "Added by hand", never "Last seen". */
export const neverSeen = (a: Pick<Asset, 'origin' | 'first_seen' | 'last_seen'>) => a.origin === 'manual' && Date.parse(a.last_seen) <= Date.parse(a.first_seen)

/** Whether the device page shows this device's Sources card (where its network scan is switched on): not ignored, not declared
 *  software only. The box has it too: its rows say what applies to it (not scanned, no SNMP, its own agent with Check now). A pointer
 *  to Sources elsewhere on the page links there only when it is shown. */
export const hasSourcesCard = (a: Named & { is_box: boolean; ignored_at?: string | null }) => !a.ignored_at && !declaredSoftwareOnly(a)

/** Whether the device page shows this device's SNMP card: an admin, active discovery on, a real device (not the box, not ignored,
 *  not declared software only). Last checks reads it too, so its "Set it up in Sources" link never points at no card. */
export const hasSnmpCard = (a: Named & { is_box: boolean; ignored_at?: string | null }, admin: boolean, on: boolean) => admin && on && !a.is_box && !a.ignored_at && !declaredSoftwareOnly(a)

/** Characters a name in Vedette cannot hold (as the backend's userName, #929): < >, C0 and C1 controls, bidi marks,
 *  overrides and isolates, zero-width characters, the soft hyphen, word joiners and U+FEFF. They would show the name reversed or blank. */
const BAD_NAME = /[<>\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/
/** Whether a trimmed name in Vedette is refused: more than 64 characters or a character of BAD_NAME. '' (none) is fine. */
export const badUserName = (s: string) => [...s].length > 64 || BAD_NAME.test(s)
