import { Navigate } from 'react-router'

/** /alerts is now /incidents. */
export default function LegacyIndexRedirect() {
  return <Navigate to="/incidents" replace />
}
