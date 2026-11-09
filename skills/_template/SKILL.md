---
name: example-skill
version: 0.1.0
description: Một câu nói skill làm việc gì, kích hoạt khi nào (nút/sự kiện), cho story nào.
stories: [S-AI-2]
trigger: manual            # manual | event:<tên> | schedule:<cron>
tier_budget: { min: 0, med: 4000, max: 20000 }   # token vào ước lượng mỗi lần
tools_allowed: []          # chỉ tool chỉ-đọc: search_assets, events_around, lookup_ioc, lookup_cve
inputs_schema: ./input.schema.json
output_schema: ./output.schema.json
language: vi
---

# Skill: example

## Làm gì
## Không làm gì
## Input hộp chuẩn bị (AI không tự tìm)
## Output (schema cứng; có `citations[]`)
## Fixtures
`fixtures/*.json` — input + output kỳ vọng; chạy trong CI với model rẻ khi có key.
