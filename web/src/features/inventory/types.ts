// Kiểu API module inventory — suy ra từ hợp đồng Zod (contract.ts), không khai tay.
import type { z } from 'zod'
import * as C from './contract'

export const KINDS = C.AssetKind.options
/** The 13 kinds the fragile and regular-scan settings list (D-511). */
export const BEHAVIOUR_KINDS = C.BehaviourKind.options
export type ObsField = z.infer<typeof C.ObsField>
export type Observation = z.infer<typeof C.Observation>
export type RegularScan = z.infer<typeof C.RegularScan>
export type DeviceRow = z.infer<typeof C.DeviceRow>
export type DevicesResponse = z.infer<typeof C.DevicesResponse>
export type SoftwareView = z.infer<typeof C.SoftwareView>
export type DeviceDetail = z.infer<typeof C.DeviceDetail>
export type PossibleSame = z.infer<typeof C.PossibleSame>
export type SamePairs = z.infer<typeof C.SamePairs>
export type MergeInput = z.infer<typeof C.MergeInput>
export type SourcesInput = z.infer<typeof C.SourcesInput>
export type SourcesState = z.infer<typeof C.SourcesState>
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
export type SnmpCredential = z.infer<typeof C.SnmpCredential>
export type SnmpCredentialInput = z.infer<typeof C.SnmpCredentialInput>
export type SnmpResponse = z.infer<typeof C.SnmpResponse>
export type SnmpTestReason = z.infer<typeof C.SnmpTestReason>
export type SnmpTestResult = z.infer<typeof C.SnmpTestResult>
export type DeviceSource = z.infer<typeof C.DeviceSource>
export type DevicesQuery = z.infer<typeof C.DevicesQuery>
export type SnmpRead = z.infer<typeof C.SnmpRead>
/** G4: a device's risk marker (exploited findings, or a recommended update); null when clean. */
export type DeviceRisk = z.infer<typeof C.DeviceRisk>
