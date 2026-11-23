// API contract: each module declares its endpoints with a Zod schema in features/<m>/contract.ts.
// api/openapi.json is generated from here (`pnpm openapi`); the contract test calls the mock and checks the response matches the schema.
// The types used in the UI come from z.infer of this very schema, so the UI, the mock and the M2 backend cannot drift apart.
import type { z } from 'zod'
import type { Role } from './session'

export type Method = 'get' | 'post' | 'put' | 'patch' | 'delete'

export interface Endpoint {
  method: Method
  /** An OpenAPI-style path without the /api/v1 prefix. Example: /feeds/cve/{id} */
  path: string
  /** One sentence: what the endpoint does for the user. */
  summary: string
  stories: string[]
  /** The minimum role; 'public' = no sign-in needed. */
  role: Role | 'public'
  params?: z.ZodObject
  query?: z.ZodObject
  /** Request headers the operation reads (OpenAPI `in: header`), for an upload whose body is the file itself. */
  headers?: z.ZodObject
  /** 'file' = the body is the raw bytes of a file the user uploads (`application/octet-stream`). */
  body?: z.ZodType | 'file'
  /** true = the request body may be left out (an empty request is accepted); `requestBody.required` is false. Only where an older caller sends none. */
  bodyOptional?: boolean
  /** null = 204 with no content. 'file' = a file download (CSV, JSON, rule). 'text' = plain `text/plain; charset=utf-8` text (the blocklist for firewalls). */
  response: z.ZodType | null | 'file' | 'text'
  /** Media type of a 'file' response; default application/octet-stream. */
  fileType?: string
  /** HTTP status of a successful response that has content (API_CONVENTIONS §12). Default 200; 201 = created; 202 = accepted, continues in the background. An endpoint that returns two codes depending on the case: keep the default and say so in `summary`. */
  status?: 200 | 201 | 202
  /** A value for the contract test to try a GET with (a path with parameters needs an example, otherwise it is skipped). */
  example?: { params?: Record<string, string>; query?: Record<string, string> }
}

export const defineEndpoints = (e: Endpoint[]) => e
