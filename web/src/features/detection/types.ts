// Types of the intrusion detection API, inferred from the zod contract (contract.ts), never written by hand.
import type { z } from 'zod'
import type * as C from './contract'

export type Severity = z.infer<typeof C.Severity>
export type FindingStatus = z.infer<typeof C.FindingStatus>
export type IncidentStatus = z.infer<typeof C.IncidentStatus>
export type DeviceRef = z.infer<typeof C.DeviceRef>
export type LinkedFinding = z.infer<typeof C.LinkedFinding>
export type AlertIncident = z.infer<typeof C.AlertIncident>
export type Alert = z.infer<typeof C.Alert>
export type AlertWindow = z.infer<typeof C.AlertWindow>
export type AlertSort = z.infer<typeof C.AlertSort>
export type AlertsResponse = z.infer<typeof C.AlertsResponse>
export type WatcherId = z.infer<typeof C.WatcherId>
export type WatcherState = z.infer<typeof C.WatcherState>
export type WatcherAction = z.infer<typeof C.WatcherAction>
export type Watcher = z.infer<typeof C.Watcher>
export type DetectionKind = z.infer<typeof C.DetectionKind>
export type KindCount = z.infer<typeof C.KindCount>
export type MirrorHit = z.infer<typeof C.MirrorHit>
export type Overview = z.infer<typeof C.Overview>

export const WATCHER_IDS: WatcherId[] = ['traps', 'logs', 'mirror_port', 'ips_events']
export const DETECTION_KINDS: DetectionKind[] = ['trap', 'bad_address', 'log_anomaly', 'unknown_device', 'intrusion']
export const ALERT_WINDOWS: AlertWindow[] = ['24h', '7d', '30d']
