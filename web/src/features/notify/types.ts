// Kiểu API module notify — suy ra từ hợp đồng Zod (contract.ts), không khai tay. Hằng số UI ở dưới.
import type { z } from 'zod'
import type * as C from './contract'

export type ChannelType = z.infer<typeof C.ChannelType>
export type RouteSeverity = z.infer<typeof C.RouteSeverity>
export type TestResult = z.infer<typeof C.TestResult>
export type Channel = z.infer<typeof C.Channel>
export type ChannelInput = z.infer<typeof C.ChannelInput>
export type Approver = z.infer<typeof C.Approver>
export type Quiet = z.infer<typeof C.Quiet>
export type Grouping = z.infer<typeof C.Grouping>
export type ChannelsResponse = z.infer<typeof C.ChannelsResponse>
export type IncidentKind = z.infer<typeof C.IncidentKind>
export type IncidentStatus = z.infer<typeof C.IncidentStatus>
export type SendRecord = z.infer<typeof C.SendRecord>
export type Incident = z.infer<typeof C.Incident>
export type Preview = z.infer<typeof C.Preview>
export type IncidentDetail = z.infer<typeof C.IncidentDetail>
export type IncidentsResponse = z.infer<typeof C.IncidentsResponse>
export type HistoryItem = z.infer<typeof C.HistoryItem>
export type HistoryResponse = z.infer<typeof C.HistoryResponse>
export type FindingNotices = z.infer<typeof C.FindingNotices>
export type EmailSignin = z.infer<typeof C.EmailSignin>
export type EmailSigninStart = z.infer<typeof C.EmailSigninStart>
export type ZaloLogin = z.infer<typeof C.ZaloLogin>
export type ZaloContact = z.infer<typeof C.ZaloContact>
export type ZaloContacts = z.infer<typeof C.ZaloContacts>
export type ZaloFound = z.infer<typeof C.ZaloFound>
export type ZaloApprover = z.infer<typeof C.ZaloApprover>
export type ZaloApprovers = z.infer<typeof C.ZaloApprovers>

export const CHANNEL_TYPES: ChannelType[] = ['telegram', 'slack', 'zalo', 'zalo-personal', 'email', 'webhook']
export const ROUTE_SEVERITIES: RouteSeverity[] = ['critical', 'high', 'medium', 'low']
export const INCIDENT_KINDS: IncidentKind[] = ['trap', 'bad_address', 'log_anomaly', 'unknown_device']

/** Trường không bí mật của từng kênh. Bí mật (token, mật khẩu) tách riêng: chỉ gửi lên, không bao giờ trả về (SYS-4). */
export const FIELDS: Record<ChannelType, string[]> = {
  telegram: ['chat_id'],
  slack: ['label'], // channel_id chỉ hiện khi bật duyệt trong chat
  zalo: ['oa_id', 'user_id', 'app_id'], // app_id: the refresh-token flow (D-483); secret key and refresh token are secrets
  'zalo-personal': ['user_id'],
  email: ['provider', 'host', 'port', 'security', 'username', 'tenant_id', 'client_id', 'from', 'to'], // provider: preset (D-449); tenant_id, client_id: Microsoft 365 only
  webhook: ['url'],
}

/** Kênh có thể nhận duyệt hành động (D-38, D-46). Zalo OA và webhook chỉ gửi tin kèm liên kết mở Vedette. */
export const APPROVAL_CHANNELS: ChannelType[] = ['slack', 'telegram', 'email', 'zalo-personal']

const v4Forbidden = (a: number, b: number, c: number, d: number) =>
  a === 127 || (a === 169 && b === 254) || (a >= 224 && a <= 239) || (a === 0 && b === 0 && c === 0 && d === 0) ||
  (a === 100 && b === 100 && c === 100 && d === 200) || (a === 192 && b === 0 && c === 0 && d === 192) // cloud metadata off link-local: Alibaba, Oracle

/** Names of the cloud metadata service (Google Cloud), refused by the box before any lookup (metadataName). */
const METADATA_NAMES = ['metadata', 'metadata.google.internal', 'metadata.goog']

/** The box's sentence for Vedette itself (modules/notify/channel OwnText, D-446): the same in feeds, notify, logs and ai. */
export const OWN_TEXT = "That address is Vedette itself: loopback, Vedette's own container, or one of its ports (8443, 8444, 8765, 514, 6514) on the machine that runs it. For another program on that machine, enter the machine's LAN address and that program's port."

/**
 * Vedette itself as the page can judge it (channel ownAddr, D-446): loopback and *.localhost, also inside an IPv4-mapped IPv6 address.
 * The machine's own addresses and the container's are the box's to judge (the page does not know them). forbiddenHost is true for
 * these too; ask this first for the sentence.
 */
export const ownHost = (host: string) => {
  const h = host.toLowerCase().replace(/\.$/, '')
  return h === 'localhost' || h.endsWith('.localhost') || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h) || h === '[::1]' || /^\[::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}\]$/.test(h)
}

/**
 * A webhook or SMTP host the box never connects to, judged as the box judges a literal IP (modules/notify/channel forbiddenAddr,
 * after Unmap): loopback and *.localhost, link-local (cloud metadata 169.254.169.254), the other cloud metadata services
 * (100.100.100.200, 192.0.0.192, fd00:ec2::254, fd20:ce::254, metadata.google.internal), multicast, unspecified, also inside an
 * IPv4-mapped IPv6 address. Other transition forms (NAT64, 6to4) are left to the box. Only real IP literals: a DNS name such as 224.alerts.example.com is judged by the box when it connects.
 */
export const forbiddenHost = (host: string) => {
  const h = host.toLowerCase().replace(/\.$/, '')
  if (h === 'localhost' || h.endsWith('.localhost') || METADATA_NAMES.includes(h)) return true
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h)
  if (v4) return v4Forbidden(Number(v4[1]), Number(v4[2]), Number(v4[3]), Number(v4[4]))
  const m = /^\[([0-9a-f:.]+)\]$/.exec(h)
  if (!m) return false
  const parts = m[1]!.split('::')
  if (parts.length > 2) return false
  const side = (x: string) => (x ? x.split(':').map((p) => (/^[0-9a-f]{1,4}$/.test(p) ? parseInt(p, 16) : NaN)) : [])
  const head = side(parts[0]!), tail = parts.length === 2 ? side(parts[1]!) : []
  const fill = 8 - head.length - tail.length
  if (head.concat(tail).some(Number.isNaN) || (parts.length === 1 ? fill !== 0 : fill < 1)) return false
  const x = [...head, ...Array<number>(Math.max(fill, 0)).fill(0), ...tail] // URL writes IPv6 compressed, an embedded IPv4 as hex
  if (x.slice(0, 5).every((v) => v === 0) && x[5] === 0xffff) return v4Forbidden(x[6]! >> 8, x[6]! & 255, x[7]! >> 8, x[7]! & 255) // IPv4-mapped
  const zero7 = x.slice(0, 7).every((v) => v === 0)
  const meta = x.slice(2, 7).every((v) => v === 0) && x[7] === 0x254 && ((x[0] === 0xfd00 && x[1] === 0xec2) || (x[0] === 0xfd20 && x[1] === 0xce)) // AWS, Google Cloud
  return meta || (zero7 && (x[7] === 0 || x[7] === 1)) || (x[0]! & 0xffc0) === 0xfe80 || x[0]! >> 8 === 0xff
}
