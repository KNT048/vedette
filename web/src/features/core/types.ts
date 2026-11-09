// Kiểu API module core, suy ra từ hợp đồng Zod (contract.ts), không khai tay.
import type { z } from 'zod'
import type * as C from './contract'
import type { Role } from '@/lib/session'
import type { ModuleId, ModuleState } from '@/lib/modules'

export type GeneralSettings = z.infer<typeof C.GeneralSettings>

export type SetupStatus = z.infer<typeof C.SetupStatus>
export type SetupModule = z.infer<typeof C.SetupModule>
export type BundleId = z.infer<typeof C.BundleId>
export type ChannelType = 'telegram' | 'zalo' | 'email'
export type SetupPayload = z.infer<typeof C.SetupPayload>

export type AuthOptions = z.infer<typeof C.AuthOptions>

export type AccountSession = z.infer<typeof C.AccountSession>
export type Account = z.infer<typeof C.Account>
export type TotpStart = z.infer<typeof C.TotpStart>
export type TwofaMethod = z.infer<typeof C.TwofaMethod>
export type EmailCodeSent = z.infer<typeof C.EmailCodeSent>

export type AdminUser = z.infer<typeof C.AdminUser>
export type OidcConfig = z.infer<typeof C.OidcConfig>

export type AuditRow = z.infer<typeof C.AuditRow>
export type AuditResult = z.infer<typeof C.AuditResult>
export type AuditQuery = { q: string; user: string; group: string; from: string; to: string }

export type UpdateChannel = z.infer<typeof C.UpdateChannel>
export type UpdateComponent = z.infer<typeof C.UpdateComponent>
export type UpdateAvailable = z.infer<typeof C.UpdateAvailable>
export type UpdateHistory = z.infer<typeof C.UpdateHistory>
export type Advisory = z.infer<typeof C.Advisory>
export type ManagedPackage = z.infer<typeof C.ManagedPackage>
export type MaintenanceWindow = z.infer<typeof C.MaintenanceWindow>
export type OsPackage = z.infer<typeof C.OsPackage>
export type OsInfo = z.infer<typeof C.OsInfo>
export type OsState = z.infer<typeof C.OsState>
export type OsRun = z.infer<typeof C.OsRun>
export type OsRebootBody = z.infer<typeof C.OsRebootBody>
export type UpdatesState = z.infer<typeof C.UpdatesState>

export type PrivacyFlow = z.infer<typeof C.PrivacyFlow>
export type PrivacyState = z.infer<typeof C.PrivacyState>

export type McpToken = z.infer<typeof C.McpToken>
export type McpState = z.infer<typeof C.McpState>
export type McpTokenCreated = z.infer<typeof C.McpTokenCreated>

export type { ModuleId, ModuleState, Role }
