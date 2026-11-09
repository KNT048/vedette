import { setupWorker } from 'msw/browser'
import { handlers } from './handlers'
import { mockedHandlers } from './realFilter'
import { realModules } from '@/lib/apiModules'

// VITE_API_REAL=core,inventory | all: those modules go to the network (Vite proxies /api to the Go backend).
const isReal = realModules(import.meta.env.VITE_API_REAL, import.meta.env.VITE_API_MOCK)
export const worker = setupWorker(...mockedHandlers(handlers, isReal))
