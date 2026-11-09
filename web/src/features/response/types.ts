// Types inferred from the Zod contract (contract.ts); do not declare by hand.
import type { z } from 'zod'
import type * as C from './contract'

export type ActionStatus = z.infer<typeof C.ActionStatus>
export type ItemStatus = z.infer<typeof C.ItemStatus>
export type Change = z.infer<typeof C.Change>
export type Proposal = z.infer<typeof C.Proposal>
export type PlanStep = z.infer<typeof C.PlanStep>
export type Plan = z.infer<typeof C.Plan>
export type PlanList = z.infer<typeof C.PlanList>
export type ActionRequest = z.infer<typeof C.ActionRequest>
export type RequestItem = z.infer<typeof C.RequestItem>
export type Approval = z.infer<typeof C.Approval>
export type Evidence = z.infer<typeof C.Evidence>
export type Settings = z.infer<typeof C.Settings>
export type SettingsView = z.infer<typeof C.SettingsView>
export type SettingsInput = z.infer<typeof C.SettingsInput>
export type Window = z.infer<typeof C.Window>
/** Stored proposal: the live parts (state, request_id) are computed on read. */
export type StoredProposal = Omit<Proposal, 'state' | 'request_id'>
export type CatalogAction = z.infer<typeof C.CatalogAction>
export type CatalogInput = z.infer<typeof C.CatalogInput>
export type Catalog = z.infer<typeof C.Catalog>
export type Connection = z.infer<typeof C.Connection>
export type ConnKind = z.infer<typeof C.ConnKind>
export type Pack = z.infer<typeof C.Pack>
export type Rule = z.infer<typeof C.Rule>
export type RuleInput = z.infer<typeof C.RuleInput>
export type RuleAction = z.infer<typeof C.RuleAction>
export type Condition = z.infer<typeof C.Condition>
export type Op = z.infer<typeof C.Op>
export type EventView = z.infer<typeof C.EventView>
export type RunSummary = z.infer<typeof C.RunSummary>
export type Simulation = z.infer<typeof C.Simulation>
export type Template = z.infer<typeof C.Template>
export type TriggerInfo = z.infer<typeof C.TriggerInfo>
export type TriggerField = z.infer<typeof C.TriggerField>
export type Allowlist = z.infer<typeof C.Allowlist>
export type Blocklist = z.infer<typeof C.Blocklist>
export type BlockEntry = z.infer<typeof C.BlockEntry>
export type LogEntry = z.infer<typeof C.LogEntry>
export type ApprovalView = z.infer<typeof C.ApprovalView>
export type EmailLink = z.infer<typeof C.EmailLink>
export type Trigger = z.infer<typeof C.TriggerKind>
export type Risk = z.infer<typeof C.Risk>
export type AiState = z.infer<typeof C.AiState>
export type AiNote = z.infer<typeof C.AiNote>
export type ProposeBody = z.infer<typeof C.ProposeBody>
export type ProposeResult = z.infer<typeof C.ProposeResult>
export type Metrics = z.infer<typeof C.Metrics>
export type Stat = z.infer<typeof C.Stat>
