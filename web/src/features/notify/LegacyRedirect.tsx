import { Navigate, useParams } from 'react-router'
import { QueryState, RequireModule } from '@/components/common/States'
import { useLegacyTarget } from './api'

/** D-52: old /alerts/:id links go to the incident, or to the finding for an old vulnerability alert. */
function Target() {
  const { id = '' } = useParams()
  const q = useLegacyTarget(id)
  return <QueryState query={q}>{(d) => <Navigate to={d.to} replace />}</QueryState>
}
export default function LegacyRedirect() {
  return <RequireModule module="notify"><Target /></RequireModule>
}
