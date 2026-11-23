---
name: example-skill
version: 0.1.0
description: One sentence saying what the skill does, when it is triggered (button/event), for which story.
stories: [S-AI-2]
trigger: manual            # manual | event:<name> | schedule:<cron>
tier_budget: { min: 0, med: 4000, max: 20000 }   # estimated input tokens per call
tools_allowed: []          # read-only tools only: search_assets, events_around, lookup_ioc, lookup_cve
inputs_schema: ./input.schema.json
output_schema: ./output.schema.json
language: vi
---

# Skill: example

## What it does
## What it does not do
## Input the box prepares (the AI does not look for it)
## Output (a strict schema; has `citations[]`)
## Fixtures
`fixtures/*.json`: input + expected output; run in CI with a cheap model when a key is available.
