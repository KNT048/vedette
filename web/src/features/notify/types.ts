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

export const CHANNEL_TYPES: ChannelType[] = ['telegram', 'slack', 'zalo', 'zalo-personal', 'email', 'webhook']
export const ROUTE_SEVERITIES: RouteSeverity[] = ['critical', 'high', 'medium', 'low']
export const INCIDENT_KINDS: IncidentKind[] = ['trap', 'bad_address', 'log_anomaly', 'unknown_device']

/** Trường không bí mật của từng kênh. Bí mật (token, mật khẩu) tách riêng: chỉ gửi lên, không bao giờ trả về (SYS-4). */
export const FIELDS: Record<ChannelType, string[]> = {
  telegram: ['chat_id'],
  slack: ['label'], // channel_id chỉ hiện khi bật duyệt trong chat
  zalo: ['oa_id', 'user_id'],
  'zalo-personal': ['user_id'],
  email: ['host', 'port', 'security', 'username', 'from', 'to'],
  webhook: ['url'],
}

/** Kênh có thể nhận duyệt hành động (D-38, D-46). Zalo OA và webhook chỉ gửi tin kèm liên kết mở Vedette. */
export const APPROVAL_CHANNELS: ChannelType[] = ['slack', 'telegram', 'email', 'zalo-personal']
