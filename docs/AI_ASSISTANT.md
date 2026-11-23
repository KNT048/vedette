# AI assistant: BYOK, skills, RAG, 3 levels

Principle: the product does not sell AI. The customer plugs in their own key/model; the software provides **specific, useful jobs**. The customer pays for tokens to their own provider. No token prices are discussed in the product apart from the gauge.

## 1. Provider

| Type | How it connects | Declared capabilities |
|---|---|---|
| Anthropic | Native API (Messages), tool use, structured output | `tools`, `structured`, `web_search` (if on) |
| OpenAI-compatible | `base_url` + key: OpenAI, Ollama, vLLM, LM Studio, OpenRouter, an internal gateway | `tools` (if the model supports it), `structured` (json schema) |
| Gemini | API native | `tools`, `structured` |

- Configuration: provider, `base_url`, key (encrypted, only the last 4 characters shown), model, context limit, capability flags (probed with a test call). Several profiles: for example "Haiku for logs, Opus for explanations".
- **The key never leaves the box** except in the request to the provider. It never goes through a central server.
- Gauge: tokens in/out by skill/day/month; a daily token cap by level; over the cap → lower the level → notify.

## 2. Skills: packages of specific jobs, updatable

Each skill is a folder in `skills/<name>/`, in a format compatible with Agent Skills (`SKILL.md` + extra files) so customers can reuse it with other tools:

```
skills/explain-finding/
  SKILL.md         # frontmatter: name, version, description, trigger (event/button), tier_budget {min,med,max}, tools_allowed[], inputs schema, output schema
  prompt.vi.md     # system/instructions in Vietnamese (en optional)
  output.schema.json
  fixtures/        # sample input + expected output (regression tests, run with a cheap model in CI if a key is available)
  README.md        # what this job does, and what it does not
```

Skills ship through the **content pack** (signed) → prompts/schemas are updated without releasing a binary. The box keeps the previous version for rollback. A skill the customer writes goes in `data/skills/` (lower priority, never overwritten).

### The initial skill list (each traces to a story)

| Skill | Story | Input (the box prepares it, the AI does not look for it) | Output (schema) | Tier |
|---|---|---|---|---|
| `explain-finding` | S-AI-2 | the CVE record (a shortened cvelist JSON), feed signals (KEV/EPSS/PoC/sightings), the asset + software + version + firewall vendor declared, the related 24h of logs (aggregated), the mitigation pack if there is one | `{affected: yes/no/unknown, why, patch_steps[], temp_mitigations[], config_snippets{vendor: text}, detection_hints[], citations[]}` | once per CVE/asset, cached by hash |
| `cve-news` | S-AI-3 | text the box has fetched: the NVD record, one vendor advisory from the host list, a search of the GitHub repository for `CVE-...` (PoC?), 6 feeds watchTowr/GreyNoise/SANS ISC/Rapid7/Unit 42/Project Zero; cleaned, size-limited, inside a fenced block | `{exploited, public_exploit, workaround, other[]}` → `lines` with labels attached by the box; `sources`, `citations` built by the box | on request; the provider's web search is never used at any level (FORBID-6) |
| `log-digest` | S-AI-4 | an aggregate table (signature, src, dst, count, delta vs baseline), IOC hits, the related assets | `{items: [{severity, evidence_lines[], recommendation}], summary}` | min: 1/day · med: 1/hour · max: per new alert |
| `log-investigate` | S-AI-4 (max) | as above + **read-only tools**: `search_assets`, `events_around(ip, at, minutes)` (line kinds and counts of an address, bad connections; no log lines), `lookup_ioc`, `lookup_cve` | as above + a recorded `tool_calls[]` | max, on click |
| `mitigation-config` | S-MIT-1 | the CVE + firewall vendor + model/version + a short topology (WAN/LAN) | `{snippets{vendor: text}, side_effects[], verify_steps[]}` | on request |
| `fingerprint-fallback` | S-INV-1 | a banner/sysDescr/HTTP title that nmap/Recog could not assign | `{vendor, product, version?, confidence}` | batch, a cheap model |
| `translate-advisory` | S-FEED-2 | an English advisory | Vietnamese, keeping numbers/versions | batch |
| `weekly-report` | S-REP-1 | the week's figures (new/handled/remaining findings, honeypot, anomalous logs) | a 1-page markdown | 1/week |
| `pdpl-assessment` | S-REP-2 | inventory + scan + configuration | a report by legal section (a fixed template, the AI only fills it in) | on request |
| `ask-my-data` | S-AI-5 | a question + read-only tools | an answer + a table; when memory suggestions are on, at most one `Remember:` line that the box strips out as a suggestion | on request |

`mitigation-config` runs in two places: **the central side**, with the project's key, drafting a mitigation pack for a maintainer to confirm through a PR (S-MIT-4, `DATA_PIPELINE.md` §5b); **the box**, with the customer's key, only when a CVE has no confirmed pack (S-MIT-1). The result on the box never appears as a confirmed recommendation.

## 3. RAG: find the right context before asking

- **Store**: assets/findings (from the DB, rendered as short text), mitigation packs, fetched advisories, translations, skill READMEs, product documentation, 7-day aggregated logs.
- **Index**: SQLite **FTS5 (BM25)** from the start, with no dependency on embeddings; optional vectors (`sqlite-vec`) with embeddings from the customer's provider or Ollama (bge-m3 is good for Vietnamese). Hybrid (BM25 + vector) when vectors exist.
- **Chunks**: by entity (1 asset = 1 doc; 1 CVE = 1 doc; an advisory is split into ~800 tokens with a title). Updated incrementally when the DB changes.
- **Retrieval**: per skill, a small top-k (5-12), filtered by site/tenant and the asker's permission; each chunk carries a `source` so the AI can cite it; an answer without a citation → the UI labels it "no source".
- **Customer documents (S-AI-7, slice 4c)**: MD/TXT/DOCX ≤ 10 MB (PDF is not supported yet: it needs reading in a bounded child process) uploaded by an administrator; the box reads them and cuts passages of ~3200 bytes, an FTS5 (BM25) index on the box, no embeddings; each call of a job that carries internal data takes at most 4 passages that match the question, each passing through the hooks, as a fenced data block (never in the system prompt).
- **No RAG** for data the box can supply exactly with a query (an asset by IP...): use a read-only tool.

## 4. Three token levels (S-AI-4)

| Level | What is sent | When | Default cap |
|---|---|---|---|
| Minimum | 1 digest/day: the top-N aggregated anomalies + IOC hits; `explain-finding` only on click | an expensive model or a small local one | ~10k tokens/day |
| Medium | every hour: a batch of **new** events + the anomaly window, with the assets; `explain-finding` runs by itself for new high-level findings | default | ~60k/day |
| Maximum | per new alert (not built yet); `log-investigate` with tools on click; `cve-news` runs by itself (not built yet) | a customer with a SOC/IT | set by the customer |

Over the cap → lower the level → record a notice. Every call records `ai_run` (skill, tokens, model, input hash) for lookup and cache.

## 5. Guardrail

- Logs, feeds, web and agents are **untrusted data**: put in a labelled data block, the system prompt fixes the role; filter injection (regex + a pattern list "ignore previous...", and a small classifier when available) before passing it in; fetched text is size-limited.
- **The AI takes no actions**: no write tools; every output is a proposal, with the label "AI generated, needs a person to confirm" (S-AI-6); the button that applies a configuration belongs to a person and is audited.
- Output follows a **strict schema**; if it cannot be parsed → show it raw with a warning, with no inference.
- Redact before sending: secrets, tokens, passwords in logs, and optionally PII (email, phone number) according to a setting.
- A customer that cannot send data out → the same UI with an internal Ollama/vLLM.
- Tests: skill fixtures run in CI with a cheap model when the project's key is available; measure the schema-correct rate and the citation rate.

## 6. MCP

- The `mcp-server` module: Vedette **provides** read-only tools to outside agents (Claude Desktop/Code, a SIEM with MCP): `search_assets`, `get_finding`, `lookup_cve`, `lookup_ioc`, `recent_events`, `hot_board`. Bound to localhost by default; scoped tokens.
- Vedette does **not** consume an external MCP server in M6; it is left for later if there is a story.
