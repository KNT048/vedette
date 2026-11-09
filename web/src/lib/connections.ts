// Generic connection kinds (D-58): the core knows how to talk, not to which brand. Device knowledge (commands, API paths, least
// privilege, undo) is data in the action template library (features/response/templates). Shared by the ai module (connections)
// and the response module (action catalog).
//
//   http              HTTP API (a device API, a web service)
//   ssh               SSH / CLI
//   netconf-restconf  NETCONF / RESTCONF
//   automation        automation platform (Ansible AWX/Tower, n8n...)
//   mcp-http          MCP server reached by URL        } one kind, two ways to reach it
//   mcp-stdio         MCP server started by a command  }
// Block list pull is not a connection: the box publishes a list and the device fetches it (response action `blocklist_add`, pack "box").
import { z } from 'zod'

export const CONNECTION_KINDS = ['http', 'ssh', 'netconf-restconf', 'automation', 'mcp-http', 'mcp-stdio'] as const
export const ConnectionKind = z.enum(CONNECTION_KINDS)
export type ConnectionKindId = z.infer<typeof ConnectionKind>

export type Auth = 'none' | 'token' | 'basic' | 'ssh-key'
/** Which sign-in each kind of connection can use (the dialog locks the others; the server refuses them). */
export const KIND_AUTH: Record<ConnectionKindId, Auth[]> = {
  http: ['none', 'token', 'basic'], ssh: ['ssh-key', 'basic'], 'netconf-restconf': ['basic', 'token'], automation: ['token', 'basic'],
  'mcp-http': ['none', 'token', 'basic'], 'mcp-stdio': ['none', 'token'],
}
/** Kinds that carry an action as an HTTP request (method, path, body). */
export const HTTP_KINDS: ConnectionKindId[] = ['http', 'netconf-restconf', 'automation']
export const isHttpKind = (k: string | null | undefined): boolean => HTTP_KINDS.includes(k as ConnectionKindId)
export const isMcpKind = (k: string | null | undefined): boolean => k === 'mcp-http' || k === 'mcp-stdio'
/** Sign-in that carries a user name: SSH always, and Basic on any kind (D-94). */
export const usesUsername = (kind: string, auth: string): boolean => kind === 'ssh' || auth === 'basic'
/** The identity of the server a connection talks to: host and port after normalisation (a path, a trailing slash or letter case do not count). Its pin and its saved secret belong to it. */
export const hostPort = (kind: string, target: string): string => {
  try {
    if (kind === 'ssh') { const m = /^(.*?)(?::(\d{1,5}))?$/.exec(target.trim().toLowerCase())!; return `${m[1]}:${m[2] ?? '22'}` }
    return new URL(target).host.toLowerCase()
  } catch { return target.trim().toLowerCase() }
}
