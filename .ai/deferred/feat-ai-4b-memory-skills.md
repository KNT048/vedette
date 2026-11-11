# Deferred: feat/ai-4b-memory-skills (WP-25 slice 4b)

- [ ] Slice 5 (ask flow): who creates memory suggestions. Nothing calls `Service.SuggestMemory` yet, so `ai_memory_suggestion` stays empty in a real box and `suggest_enabled` (default off) has no effect until the ask flow, the log digest or another job calls it with the text and its evidence. Do not invent a producer before that story.
- [ ] Signed content pack in `skills/` (INV-9, docs/AI_ASSISTANT.md 2): skills are a list in code (`skillDefs` in modules/ai/skills.go, same 11 entries as SKILL_DEFS of the mock); prompts and schemas of a skill that update without a binary release, the box rollback and customer skills in `data/skills/` are deferred.
- [ ] Skill `fingerprint-fallback` has no AI job: its switch is stored and shown but nothing reads it until a job uses it (then add the job to `skillDefs`).
- [ ] GUI (Kiên's mock): the real API answers a memory text outside 3..300 characters with 400 `invalid` (field `text`, from the OpenAPI schema) before the `invalid_memory` of the mock; the memory form shows a field error for both, to check at integration (same as rules).
- [ ] The ids of left-out memories are in the activity summary only on a successful call; the names of the hooks that stopped them are in `hooks` on every row. Add the ids to failed/blocked rows only if somebody needs them.
