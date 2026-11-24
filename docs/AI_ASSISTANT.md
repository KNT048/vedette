# AI assistant: bring your own key

The `ai` module (optional, off by default, labelled Preview in v1) lets a box use an AI provider the customer chooses, with the
customer's own key, for specific jobs: explaining a finding, drafting a mitigation configuration, summarising CVE news, reading the
logs, answering questions about the box's own data. Vedette sells no AI and runs no AI service; the customer pays their provider for
the tokens. The rules the code holds to are in [`modules/ai/CONTRACT.md`](../modules/ai/CONTRACT.md); what is sent to the provider,
job by job, is flow 3 of [PRIVACY.md](../PRIVACY.md).

## 1. Providers and profiles

| Provider type | How it connects |
|---|---|
| Anthropic | the native Messages API |
| OpenAI | the OpenAI API |
| OpenAI-compatible | a base URL and a key: Ollama, vLLM, LM Studio, OpenRouter, an internal gateway |
| Gemini | the native Gemini API |

- A **profile** is one provider, address, key and model. Several profiles can exist (for example a small model for logs and a larger
  one for explanations). A profile is marked **in your network** or **cloud**; an in-network profile must use a private address or a
  name that resolves to one, checked at every connection, and may have no key.
- The key is stored encrypted (`core/secrets`), only its last 4 characters are shown, and it is never logged or exported. A stored key
  goes only to the address it was saved for: changing the provider type or the address needs the key entered again.
- **Test** sends three tiny fixed requests to learn what the model supports (tools, structured output); the Add profile dialog reads the
  provider's model list. The box makes these calls, not the browser.

## 2. Jobs, assignments and skills

There are ten jobs: `explain-finding`, `mitigation-config`, `cve-news`, `log-digest`, `log-investigate`, `ask-my-data`,
`weekly-report`, `pdpl-assessment`, `translate-advisory` and `response-plan`. An administrator assigns each job a primary profile and a
fallback; the job moves to the fallback when the primary fails, times out, is out of its own budget or is excluded by the privacy rule,
and the result says which profile answered.

When an administrator turns on the **privacy rule**, the jobs that carry internal data (every job except `cve-news` and
`translate-advisory`) may use only in-network profiles; the rule is checked when a job is assigned and again before each call.

**Skills** are the product's own job descriptions, listed in code (`modules/ai/skills.go`): eleven entries, one per job plus
`fingerprint-fallback`, which has no job yet. Each can be switched off; a job whose skill is off does not run and its button is not
offered. Customers cannot add skills in v1. The `skills/` folder of the repository holds only a format template for later.

| Skill | What it does | Input the box prepares |
|---|---|---|
| `explain-finding` | Says whether a vulnerability affects your devices, why, and how to patch or work around it | the CVE record the box holds, the exploited-list entry, the matched devices and their stored fix |
| `mitigation-config` | Drafts firewall configuration to block an attack until you can patch ("Ask my AI" on a finding without a confirmed pack) | the CVE, the device, and the firewalls and routers on its path as far as the box knows them |
| `cve-news` | Summarises the advisories, public exploit code and blog posts the box fetched for a CVE | text the box fetched (NVD, one vendor advisory, a GitHub search, six security blogs), cleaned and capped; the provider never browses the web |
| `log-digest` | Turns grouped log events into a short list of what to look at | kinds of log line with counts, spikes and connections to listed bad addresses; never a log line |
| `log-investigate` | Checks points of the digest with read-only tools (maximum level only) | as above, plus read-only lookups |
| `ask-my-data` | Answers questions about devices and findings | the question, then the results of read-only tools the model asks for |
| `weekly-report` | Writes the one-page weekly summary | the week's figures |
| `pdpl-assessment` | Fills the data protection self-assessment | inventory and scan figures |
| `translate-advisory` | Translates a vendor advisory, keeping numbers and versions exact | the advisory text |
| `response-plan` | Proposes what to do now for a device with a critical finding (part of the `response` module, not offered in v1) | the finding and the actions an administrator allowed |
| `fingerprint-fallback` | Names a device from a banner the scanners recognise but cannot place | no job yet |

A confirmed recommendation pack (`content/mitigation/packs/`, reviewed by a maintainer and shipped with the signed software update)
is always shown as confirmed; an AI answer never is.

## 3. Context: rules, memories and documents

- **Built-in rules** (scope, evidence, read-only, untrusted data) go with every call and cannot be edited or turned off. An
  administrator can add up to 30 company rules of up to 300 characters.
- **Memories**: up to 100 short facts an administrator keeps, sent with calls that carry internal data. When suggestions are on, the AI
  may suggest a memory; it is used only after an administrator accepts it.
- **Knowledge base**: PDF, Markdown, text and DOCX documents (up to 10 MB each, 50 in all), read and indexed on the box with SQLite
  FTS5 (no embeddings). A call for a job a document is assigned to carries at most 4 matching passages (12,000 characters in all).
- Data the box can give exactly (a device by IP, the findings of a device) is not searched for: the model asks a read-only tool.

## 4. Token level and budget

- The administrator picks a level, which is never changed automatically: **minimum** (about 10,000 tokens a day; a short log digest),
  **medium** (the default, about 60,000; a full digest), **maximum** (depends on the alerts; the digest can call `log-investigate`).
- A **monthly token budget** is shared by all profiles (default 6,000,000 tokens, from 1,000 to 150,000,000), and each profile can have
  its own. Below the budget every call goes through; at 100 % calls are refused until the month renews, or move to the fallback when
  only a profile's own budget is spent. No money is shown; set a spending limit in the provider's console as well.

## 5. Guardrails

- **The AI has no write tools.** The model is offered only read tools; a write tool of a connection is never in its tool list. Any
  change to a device goes through an action a person approves in the `response` module.
- **Untrusted data**: text from feeds, logs, devices, web pages and documents goes to the model only as fenced data it is told never to
  obey, and the answer must match a strict schema.
- **Hooks** run before the call, after the answer and before a tool call, and can block, mask or ask for approval. The built-in
  personal-data hook masks email addresses, phone numbers and device secrets (passwords, hashes, SNMP communities, keys) and stops a
  call whose text holds an ID number, unless an administrator turns it off.
- **Labels**: every AI answer names its model, profile and tokens and carries "AI-generated, needs a person to confirm"; there is no
  action button on an AI answer. The model never writes a link: it cites numbered references the box offers.
- **AI log**: every call, including blocked and failed ones, writes one entry with hashes of what was sent and received (not the text)
  into a hash chain that a daily job verifies; entries are kept 365 days by default (at least 90).

## 6. MCP

The separate `mcp-server` module (not offered in v1) lets an MCP client the customer runs read devices, findings and feed entries with
a scoped read-only token, on `127.0.0.1:8765` only. Vedette does not call external MCP servers.
