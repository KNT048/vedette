import { Navigate } from 'react-router'

/** D-52: /alerts is now /incidents. */
export default function LegacyIndexRedirect() {
  return <Navigate to="/incidents" replace />
}
