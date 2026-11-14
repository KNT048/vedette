// Kiểu API module core, suy ra từ hợp đồng Zod (contract.ts), không khai tay.
import type { z } from 'zod'
import type * as C from './contract'
import type { Role } from '@/lib/session'
import type { ModuleId, ModuleState } from '@/lib/modules'

export type GeneralSettings = z.infer<typeof C.GeneralSettings>

export type SetupStatus = z.infer<typeof C.SetupStatus>
export type SetupModule = z.infer<typeof C.SetupModule>
export type BundleId = z.infer<typeof C.BundleId>
export type SetupPayload = z.infer<typeof C.SetupPayload>

export type AuthOptions = z.infer<typeof C.AuthOptions>

export type AccountSession = z.infer<typeof C.AccountSession>
export type Account = z.infer<typeof C.Account>
export type TotpStart = z.infer<typeof C.TotpStart>
export type TwofaMethod = z.infer<typeof C.TwofaMethod>
export type EmailCodeSent = z.infer<typeof C.EmailCodeSent>

export type AdminUser = z.infer<typeof C.AdminUser>
export type OidcConfig = z.infer<typeof C.OidcConfig>
export type OidcSave = z.infer<typeof C.OidcSave>
export type OidcStart = z.infer<typeof C.OidcStart>

export type AuditRow = z.infer<typeof C.AuditRow>
export type AuditResult = z.infer<typeof C.AuditResult>
export type AuditQuery = { q: string; user: string; group: string; from: string; to: string; actor: '' | 'people' }

export type UpdateChannel = z.infer<typeof C.UpdateChannel>
export type UpdateComponent = z.infer<typeof C.UpdateComponent>
export type UpdateAvailable = z.infer<typeof C.UpdateAvailable>
export type UpdateHistory = z.infer<typeof C.UpdateHistory>
export type UpdateRun = z.infer<typeof C.UpdateRun>
export type Advisory = z.infer<typeof C.Advisory>
export type ManagedPackage = z.infer<typeof C.ManagedPackage>
export type MaintenanceWindow = z.infer<typeof C.MaintenanceWindow>
export type OsPackage = z.infer<typeof C.OsPackage>
export type OsInfo = z.infer<typeof C.OsInfo>
export type OsState = z.infer<typeof C.OsState>
export type OsRun = z.infer<typeof C.OsRun>
export type BoxBackup = z.infer<typeof C.BoxBackup>
export type BoxBackups = z.infer<typeof C.BoxBackups>
export type RestoreRun = z.infer<typeof C.RestoreRun>
export type BackupUpload = z.infer<typeof C.BackupUpload>
export type SetupRestoreRun = z.infer<typeof C.SetupRestoreRun>
export type OsRebootBody = z.infer<typeof C.OsRebootBody>
export type UpdatesState = z.infer<typeof C.UpdatesState>
export type UpdateCheckError = z.infer<typeof C.UpdateCheckError>

export type PrivacyFlow = z.infer<typeof C.PrivacyFlow>
export type PrivacyState = z.infer<typeof C.PrivacyState>

export type McpToken = z.infer<typeof C.McpToken>
export type McpState = z.infer<typeof C.McpState>
export type McpTokenCreated = z.infer<typeof C.McpTokenCreated>

export type { ModuleId, ModuleState, Role }

export type NetworkState = z.infer<typeof C.NetworkState>
export type NetInterface = z.infer<typeof C.NetInterface>
export type IfaceRole = z.infer<typeof C.IfaceRole>
export type Management = z.infer<typeof C.Management>
export type ManagementBody = z.infer<typeof C.ManagementBody>
export type SpanConfig = z.infer<typeof C.SpanConfig>
export type SpanStatus = z.infer<typeof C.SpanStatus>
export type NtpConfig = z.infer<typeof C.NtpConfig>

export type ConnectorKind = z.infer<typeof C.ConnectorKind>
export type ConnectorTool = z.infer<typeof C.ConnectorTool>
export type ConnectorPin = z.infer<typeof C.ConnectorPin>
export type Connector = z.infer<typeof C.Connector>
export type ConnectorInput = z.infer<typeof C.ConnectorInput>
export type ConnectorTestResult = z.infer<typeof C.ConnectorTestResult>
