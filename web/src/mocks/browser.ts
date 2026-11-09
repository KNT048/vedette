import { setupWorker } from 'msw/browser'
import { handlers } from './handlers'
import { mockedHandlers } from './realFilter'
import { realModules } from '@/lib/apiModules'
import { realSessionHandler, setRealSession } from './realSession'

// VITE_API_REAL=core,inventory | all: those modules go to the network (Vite proxies /api to the Go backend).
const isReal = realModules(import.meta.env.VITE_API_REAL, import.meta.env.VITE_API_MOCK)
const mocked = mockedHandlers(handlers, isReal)
// Core is real but some module is mocked: the mocked ones need to know who the real backend has signed in.
const needRealSession = isReal('core') && mocked.length > 0
setRealSession(needRealSession)
export const worker = setupWorker(...(needRealSession ? [realSessionHandler(isReal)] : []), ...mocked)
