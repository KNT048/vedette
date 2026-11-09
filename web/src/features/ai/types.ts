// Kiểu API module ai — suy ra từ hợp đồng Zod (contract.ts), không khai tay.
import type { z } from 'zod'
import type * as C from './contract'

export type AiTier = z.infer<typeof C.AiTier>
export type AiJob = z.infer<typeof C.AiJob>
export type AiProfile = z.infer<typeof C.AiProfile>
export type ProfileInput = z.infer<typeof C.ProfileInput>
export type ProfileKind = z.infer<typeof C.ProfileKind>
export type ApiStyle = z.infer<typeof C.ApiStyle>
export type Assignments = z.infer<typeof C.Assignments>
export type TestInput = z.infer<typeof C.TestInput>
export type AiConfigView = z.infer<typeof C.AiConfigView>
export type ConfigInput = z.infer<typeof C.ConfigInput>
export type TestResult = z.infer<typeof C.TestResult>
export type Usage = z.infer<typeof C.Usage>
export type AiRun = z.infer<typeof C.AiRun>
export type ActivityResult = z.infer<typeof C.ActivityResult>
export type ActivityTool = z.infer<typeof C.ActivityTool>
export type ActivityEntry = z.infer<typeof C.ActivityEntry>
export type ActivityList = z.infer<typeof C.ActivityList>
export type ActivityVerify = z.infer<typeof C.ActivityVerify>
export type ActivitySettings = z.infer<typeof C.ActivitySettings>
export type ToolCall = z.infer<typeof C.ToolCall>
export type AskTable = z.infer<typeof C.AskTable>
export type AskResult = z.infer<typeof C.AskResult>
export type ExplainResult = z.infer<typeof C.ExplainResult>
export type FetchedSource = z.infer<typeof C.FetchedSource>
export type NewsResult = z.infer<typeof C.NewsResult>
export type DigestItem = z.infer<typeof C.DigestItem>
export type LogDigest = z.infer<typeof C.LogDigest>

// Harness (D-39)
export type HookWhen = z.infer<typeof C.HookWhen>
export type HookAction = z.infer<typeof C.HookAction>
export type HookHit = z.infer<typeof C.HookHit>
export type BuiltinRule = z.infer<typeof C.BuiltinRule>
export type Rule = z.infer<typeof C.Rule>
export type RuleInput = z.infer<typeof C.RuleInput>
export type RulesView = z.infer<typeof C.RulesView>
export type MemoryEntry = z.infer<typeof C.MemoryEntry>
export type MemorySuggestion = z.infer<typeof C.MemorySuggestion>
export type MemoryView = z.infer<typeof C.MemoryView>
export type MemoryInput = z.infer<typeof C.MemoryInput>
export type MemoryPatch = z.infer<typeof C.MemoryPatch>
export type Skill = z.infer<typeof C.Skill>
export type KnowledgeStatus = z.infer<typeof C.KnowledgeStatus>
export type KnowledgeDoc = z.infer<typeof C.KnowledgeDoc>
export type KnowledgeView = z.infer<typeof C.KnowledgeView>
export type KnowledgeInput = z.infer<typeof C.KnowledgeInput>
export type KnowledgeSettings = z.infer<typeof C.KnowledgeSettings>
export type KnowledgePatch = z.infer<typeof C.KnowledgePatch>
export type BuiltinHook = z.infer<typeof C.BuiltinHook>
export type HookMatch = z.infer<typeof C.HookMatch>
export type CustomHook = z.infer<typeof C.CustomHook>
export type HookInput = z.infer<typeof C.HookInput>
export type HooksView = z.infer<typeof C.HooksView>
export type HookTestInput = z.infer<typeof C.HookTestInput>
export type HookTestResult = z.infer<typeof C.HookTestResult>
