// Sinh ../api/openapi.json từ hợp đồng Zod của các module (D-18). Chạy: `pnpm openapi`.
import { writeFileSync, mkdirSync } from 'node:fs'
import { createServer } from 'vite'

const server = await createServer({ server: { middlewareMode: true }, appType: 'custom', logLevel: 'error', configFile: new URL('../vite.config.ts', import.meta.url).pathname })
try {
  const { buildOpenApi } = await server.ssrLoadModule('/src/lib/openapi.ts')
  const doc = buildOpenApi()
  const dir = new URL('../../api/', import.meta.url)
  mkdirSync(dir, { recursive: true })
  writeFileSync(new URL('openapi.json', dir), JSON.stringify(doc, null, 2) + '\n')
  const ops = Object.values(doc.paths).reduce((n, p) => n + Object.keys(p).length, 0)
  console.log(`api/openapi.json: ${Object.keys(doc.paths).length} đường dẫn, ${ops} thao tác`)
} finally {
  await server.close()
}
