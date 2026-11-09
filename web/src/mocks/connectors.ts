// D-39: connections the in-box AI may use to reach other systems (MCP servers, SSH, HTTP, device APIs).
// The ai module owns the UI and endpoints (Settings → AI assistant → Connections); the response module (D-41)
// reads this store to find write tools. Every tool is 'read' or 'write'; write tools only ever run through an
// approved response action, never from a chat answer (hook "write tools need approval", always on).
import { collection } from './db'
import type { ConnectionKindId } from '@/lib/connections'
import { seedConnectors } from './seed/connectors'

export type ConnectorKind = ConnectionKindId
export interface ConnectorTool { name: string; access: 'read' | 'write'; description: string; enabled: boolean }
export interface Connector {
  id: string
  name: string
  kind: ConnectorKind
  /** Base URL, host:port, or the MCP command */
  target: string
  /** Inventory device this connection controls, when known (for response plans) */
  asset_id: string | null
  auth: { type: 'none' | 'token' | 'basic' | 'ssh-key'; last4: string | null }
  /** Hosts, URL prefixes or command patterns the AI may use through this connection */
  allow: string[]
  tools: ConnectorTool[]
  enabled: boolean
  status: 'ok' | 'error' | 'untested'
  last_test: string | null
}

export const connectorsStore = collection<Connector[]>('ai_connectors', seedConnectors, () => [])

/** Enabled write tools on enabled connections (what the response module may propose). */
export const writeTools = () => connectorsStore.get().filter((c) => c.enabled).flatMap((c) => c.tools.filter((t) => t.enabled && t.access === 'write').map((t) => ({ connector: c, tool: t })))
