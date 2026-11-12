// Kiểu API module logs — suy ra từ hợp đồng Zod (contract.ts), không khai tay. Hằng số UI (danh sách loại, giao thức) ở dưới.
import type { z } from 'zod'
import type * as C from './contract'

export type SourceKind = z.infer<typeof C.SourceKind>
export type Proto = z.infer<typeof C.Proto>
export type SourceState = z.infer<typeof C.SourceState>
export type LogSource = z.infer<typeof C.LogSource>
export type SourceInput = z.infer<typeof C.SourceInput>
export type SourcesResponse = z.infer<typeof C.SourcesResponse>
export type UnknownSender = z.infer<typeof C.UnknownSender>
export type UnknownSendersResponse = z.infer<typeof C.UnknownSendersResponse>
export type NewItem = z.infer<typeof C.NewItem>
export type SpikeItem = z.infer<typeof C.SpikeItem>
export type IocHit = z.infer<typeof C.IocHit>
export type SeenVia = 'span_dns' | 'span_sni' | 'span_http' | 'span_flow'
export type Digest = z.infer<typeof C.Digest>
export type LogEvent = z.infer<typeof C.LogEvent>
export type EventWindow = z.infer<typeof C.EventWindow>
export type EventsResponse = z.infer<typeof C.EventsResponse>
export type SiemFormat = z.infer<typeof C.SiemFormat>
export type SiemEvent = z.infer<typeof C.SiemEvent>
export type SiemConfig = z.infer<typeof C.SiemConfig>
export type SiemInput = z.infer<typeof C.SiemInput>

export const defaultPort = (p: Proto) => (p === 'tls' ? 6514 : 514)
export const SIEM_EVENTS: SiemEvent[] = ['findings', 'alerts', 'honeypot', 'bad_conn']
