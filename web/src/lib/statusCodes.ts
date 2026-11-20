// The status vocabularies every module's contract shares. One list per idea, so a page, a report and an alert never
// name the same state two ways. Labels, colours and tooltips belong to the components that render them.

/** A finding's one status, most urgent first: the five urgency layers, then the handled statuses. */
export const FINDING_STATUSES = [
  'under_attack', 'exploited', 'public_exploit', 'critical_edge', 'update_recommended',
  'patched', 'mitigated', 'accepted', 'not_relevant', 'false_positive',
] as const
export type FindingStatusCode = (typeof FINDING_STATUSES)[number]

/** An incident's handling state: new until a person acknowledges or resolves it (or the box closes it). */
export const INCIDENT_STATUSES = ['new', 'acknowledged', 'resolved'] as const
export type IncidentStatusCode = (typeof INCIDENT_STATUSES)[number]
