// Kiểu API module inventory — suy ra từ hợp đồng Zod (contract.ts), không khai tay.
import type { z } from 'zod'
import * as C from './contract'

export const KINDS = C.AssetKind.options
/** The 13 kinds the fragile and regular-scan settings list. */
export const BEHAVIOUR_KINDS = C.BehaviourKind.options
export type ObsField = z.infer<typeof C.ObsField>
export type Observation = z.infer<typeof C.Observation>
export type RegularScan = z.infer<typeof C.RegularScan>
export type DeviceRow = z.infer<typeof C.DeviceRow>
export type DevicesResponse = z.infer<typeof C.DevicesResponse>
/** A software line as the list's matched_software and product carry it. */
export type ListSoftware = z.infer<typeof C.Software>
export type SoftwareName = z.infer<typeof C.SoftwareName>
export type SoftwareLine = z.infer<typeof C.SoftwareLine>
export type AlsoSeen = z.infer<typeof C.AlsoSeen>
export type DeviceDetail = z.infer<typeof C.DeviceDetail>
export type DetectedDiffers = z.infer<typeof C.DetectedDiffers>
export type DetectedField = z.infer<typeof C.DetectedField>
export type PossibleSame = z.infer<typeof C.PossibleSame>
export type SamePairs = z.infer<typeof C.SamePairs>
export type MergeInput = z.infer<typeof C.MergeInput>
export type MergeChoice = z.infer<typeof C.MergeChoice>
export type MergePreview = z.infer<typeof C.MergePreview>
export type MergeField = z.infer<typeof C.MergeField>
export type MergeSide = z.infer<typeof C.MergeSide>
export type DeviceAddress = z.infer<typeof C.DeviceAddress>
export type SameReason = z.infer<typeof C.SameReason>
export type SplitInput = z.infer<typeof C.SplitInput>
export type SourcesInput = z.infer<typeof C.SourcesInput>
export type SourcesState = z.infer<typeof C.SourcesState>
export type DeviceSourceRow = z.infer<typeof C.DeviceSourceRow>
export type DeviceSourcesView = z.infer<typeof C.DeviceSourcesView>
export type KeepSeparateInput = z.infer<typeof C.KeepSeparateInput>
export type CatalogItem = z.infer<typeof C.CatalogItem>
export type CatalogResponse = z.infer<typeof C.CatalogResponse>
export type SettingsSaved = z.infer<typeof C.SettingsSaved>
export type AddDeviceInput = z.infer<typeof C.AddDeviceInput>
export type AddDeviceResult = z.infer<typeof C.AddDeviceResult>
export type ImportResult = z.infer<typeof C.ImportResult>
export type ActiveWindow = z.infer<typeof C.ActiveWindow>
export type InventorySettings = z.infer<typeof C.InventorySettings>
export type SettingsInput = z.infer<typeof C.SettingsInput>
export type SensorStatus = z.infer<typeof C.SensorStatus>
export type Sensor = z.infer<typeof C.Sensor>
export type SensorsResponse = z.infer<typeof C.SensorsResponse>
export type SensorPatch = z.infer<typeof C.SensorPatch>
export type AgentKind = z.infer<typeof C.AgentKind>
export type AgentToken = z.infer<typeof C.AgentToken>
export type AgentNode = z.infer<typeof C.AgentNode>
export type AgentState = z.infer<typeof C.AgentState>
export type AgentsResponse = z.infer<typeof C.AgentsResponse>
export type CreateTokenResult = z.infer<typeof C.CreateTokenResult>
export type WazuhConnection = z.infer<typeof C.WazuhConnection>
export type WazuhInput = z.infer<typeof C.WazuhInput>
export type WazuhTestResult = z.infer<typeof C.WazuhTestResult>
export type SampleResult = z.infer<typeof C.SampleResult>
export type AgentReport = z.infer<typeof C.AgentReport>
export type Installers = z.infer<typeof C.Installers>
export type OsqueryPackage = z.infer<typeof C.OsqueryPackage>
export type OsqueryStatus = z.infer<typeof C.OsqueryStatus>
export type SnmpResponse = z.infer<typeof C.SnmpResponse>
export type SnmpVersion = z.infer<typeof C.SnmpVersion>
export type SnmpAuth = z.infer<typeof C.SnmpAuth>
export type SnmpPriv = z.infer<typeof C.SnmpPriv>
export type SnmpState = z.infer<typeof C.SnmpState>
export type SnmpReason = z.infer<typeof C.SnmpReason>
export type SnmpAnswer = z.infer<typeof C.SnmpAnswer>
export type DeviceSnmp = z.infer<typeof C.DeviceSnmp>
export type DeviceSnmpInput = z.infer<typeof C.DeviceSnmpInput>
export type SnmpCheckResult = z.infer<typeof C.SnmpCheckResult>
export type SnmpDeviceRow = z.infer<typeof C.SnmpDeviceRow>
export type SnmpNotice = z.infer<typeof C.SnmpNotice>
export type DeviceSource = z.infer<typeof C.DeviceSource>
export type DevicesQuery = z.infer<typeof C.DevicesQuery>
/** A device's badge (findings' device status); null when it has none. */
export type DeviceRisk = z.infer<typeof C.DeviceRisk>
