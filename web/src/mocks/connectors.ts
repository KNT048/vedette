// D-39, D-93: connections to other systems (MCP servers, SSH, HTTP, device APIs).
// The core module owns the UI and endpoints (Settings → Connections, always mounted); the response module (D-41)
// reads this store to find write tools, and the AI will read through it later. Every tool is 'read' or 'write'; write tools only ever run through an
// approved response action, never from a chat answer (hook "write tools need approval", always on).
import { collection } from './db'
import { seedConnectors } from './seed/connectors'

export type { Connector, ConnectorKind, ConnectorTool } from '@/features/core/types'
import type { Connector } from '@/features/core/types'

export const connectorsStore = collection<Connector[]>('core_connections', seedConnectors, () => [])

/** Enabled write tools on enabled connections (what the response module may propose). */
export const writeTools = () => connectorsStore.get().filter((c) => c.enabled).flatMap((c) => c.tools.filter((t) => t.enabled && t.access === 'write').map((t) => ({ connector: c, tool: t })))
