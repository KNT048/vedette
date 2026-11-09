// The action template library as DATA (D-58, action-templates.md): per-device knowledge (commands, API paths, undo, read-back, risk) lives in the
// JSON files next to this one, validated here when they are loaded. No code path in the core names a brand; vendor names appear only in these
// files. The real box loads the same shape from a signed library shipped with updates (customers add and edit their own).
import { z } from 'zod'
import type { Risk, RuleInput } from '../types'
import type { StoredCat, TemplateDef } from '../data'
import library from './action-templates.sample.json'
import ruleLibrary from './rule-templates.sample.json'

const Tpl = z.object({ cli: z.string(), method: z.enum(['', 'GET', 'PUT', 'PATCH', 'POST', 'DELETE']), path: z.string(), body: z.string(), headers: z.string() })
const ActionTemplate = z.object({
  id: z.string().regex(/^[a-z0-9_]{2,48}$/), pack: z.string().min(1).max(60), kind: z.enum(['box', 'device']), name: z.string().min(1).max(100), description: z.string().min(1),
  connection_id: z.string().nullable().describe('Sample binding to a sample connection; null = the customer picks one'), tool: z.string().nullable(), rollback_tool: z.string().nullable(),
  run: Tpl, rollback: Tpl, verify: Tpl, risk: z.enum(['low', 'medium', 'high']), enabled: z.boolean(), ai_may_propose: z.boolean(),
  unverified: z.boolean().describe('The vendor documentation or a device test has not confirmed it yet: the description then says so'),
})
const Library = z.object({ library: z.string(), notice: z.string(), unverified_note: z.string(), actions: z.array(ActionTemplate).min(1) })

const lib = Library.parse(library)
const ids = lib.actions.map((a) => a.id)
if (new Set(ids).size !== ids.length) throw new Error('action-templates.sample.json: duplicate id')

/** The unverified marking is part of the description the user reads (and the AI sees), never only a flag. */
export const UNVERIFIED_NOTE = lib.unverified_note
export const seedCatalog = (): StoredCat[] => lib.actions.map(({ unverified, description, ...a }) => ({
  ...a, builtin: true, risk: a.risk as Risk, description: unverified ? `${description} ${lib.unverified_note}.` : description,
}))

const RuleShape = z.object({ field: z.string(), op: z.string(), value: z.string(), n: z.number().nullable(), window_min: z.number().nullable() })
const RuleActionShape = z.object({ action_id: z.string(), params: z.record(z.string(), z.string()), ttl_min: z.number().nullable() })
const RuleBody = z.object({
  name: z.string(), enabled: z.boolean(), live: z.boolean(), trigger: z.string(), match: z.enum(['all', 'any']), conditions: z.array(RuleShape), actions: z.array(RuleActionShape),
  pre_approved: z.boolean(), max_per_hour: z.number().int(), schedule_min: z.number().int().nullable(),
})
const RuleLibrary = z.object({
  templates: z.array(z.object({ id: z.string(), name: z.string(), description: z.string(), rule: RuleBody })),
  seed_rules: z.array(RuleBody.extend({ id: z.string(), template_id: z.string().nullable() })),
})
const rules = RuleLibrary.parse(ruleLibrary)
for (const r of [...rules.templates.map((t) => t.rule), ...rules.seed_rules]) {
  for (const a of r.actions) if (!ids.includes(a.action_id)) throw new Error(`rule-templates.sample.json: "${r.name}" uses unknown action ${a.action_id}`)
}
const unverified = new Set(lib.actions.filter((a) => a.unverified).map((a) => a.id))
/** A rule template that uses a not-yet-verified action says so in the gallery, like the action does. */
export const TEMPLATES: TemplateDef[] = rules.templates.map((t) => ({
  ...t, rule: t.rule as RuleInput,
  description: t.rule.actions.some((a) => unverified.has(a.action_id)) ? `${t.description} ${lib.unverified_note}.` : t.description,
}))
/** Seed rules of the trial build that use a template action (the ones that use only generic box actions stay in the engine). */
export const SEED_RULES = rules.seed_rules
