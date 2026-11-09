// Writes ../modules/core/testdata/chain_vectors.json from the mock hash implementation (DATA_MODEL §5.3). Run: `pnpm chain-vectors`.
import { writeFileSync, mkdirSync } from 'node:fs'
import { createServer } from 'vite'

const server = await createServer({ server: { middlewareMode: true }, appType: 'custom', logLevel: 'error', configFile: new URL('../vite.config.ts', import.meta.url).pathname })
try {
  const { chainVectors } = await server.ssrLoadModule('/src/lib/chainVectors.ts')
  const dir = new URL('../../modules/core/testdata/', import.meta.url)
  mkdirSync(dir, { recursive: true })
  writeFileSync(new URL('chain_vectors.json', dir), JSON.stringify(chainVectors(), null, 2) + '\n')
  console.log('modules/core/testdata/chain_vectors.json written')
} finally {
  await server.close()
}
