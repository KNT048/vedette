import { createContext, useContext } from 'react'
import { useScope } from '@/lib/v1'

/** D-624 (#819): true while AI response is on here but this build does not offer it. The screens then take no NEW action (create,
 *  edit, approve, run, turn on) and keep every way back: Reject, Roll back, Emergency stop, turning a rule off or back to dry run,
 *  deleting a rule, turning execution off (mirror of D-403). Set by ResponsePage, ResponseSettings and FindingPanel. */
export const FrozenCtx = createContext(false)
export const useFrozen = () => useContext(FrozenCtx)
export const useLeaving = () => useScope('response') === 'leaving'
