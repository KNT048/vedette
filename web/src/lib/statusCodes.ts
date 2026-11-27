// The status vocabularies every module's contract shares. One list per idea, so a page, a report and an alert never
// name the same state two ways. Labels, colours and tooltips belong to the components that render them.
// The finding vocabulary is the findings contract's (features/findings/contract.ts builds its enums from these lists).

/** A finding's open statuses: the urgency layers 1 to 5 in order, so the status of layer n is OPEN_FINDING_STATUSES[n - 1]. */
export const OPEN_FINDING_STATUSES = ['under_attack', 'exploited', 'public_exploit', 'critical_edge', 'update_recommended'] as const
export type OpenFindingStatus = (typeof OPEN_FINDING_STATUSES)[number]

/** How a finding was handled; a handled finding's status is its resolution. */
export const FINDING_RESOLUTIONS = ['patched', 'mitigated', 'accepted', 'not_relevant', 'false_positive'] as const
export type FindingResolution = (typeof FINDING_RESOLUTIONS)[number]

/** A finding's one status, most urgent first: the five urgency layers, then the handled statuses. */
export const FINDING_STATUSES = [...OPEN_FINDING_STATUSES, ...FINDING_RESOLUTIONS] as const
export type FindingStatusCode = (typeof FINDING_STATUSES)[number]

/** A device's badge: its most urgent open finding status, else possible when only questions wait for a person. */
export const DEVICE_STATUSES = [...OPEN_FINDING_STATUSES, 'possible'] as const
export type DeviceStatusCode = (typeof DEVICE_STATUSES)[number]

/** An incident's handling state: new until a person acknowledges or resolves it (or the box closes it). */
export const INCIDENT_STATUSES = ['new', 'acknowledged', 'resolved'] as const
export type IncidentStatusCode = (typeof INCIDENT_STATUSES)[number]

/** A run's state, the same eight words for every engine (core/run Status): queued waits for its lane; waiting is paused with
 *  work left until what it names (the scan window, another run); running and stopping hold the lane; the last four are final. */
export const RUN_STATUSES = ['queued', 'waiting', 'running', 'stopping', 'done', 'partial', 'failed', 'stopped'] as const
export type RunStatusCode = (typeof RUN_STATUSES)[number]

/** A step's state (core/run StepStatuses): the run states, and skipped for a step that did not run (its note says why). */
export const STEP_STATUSES = [...RUN_STATUSES, 'skipped'] as const
export type StepStatusCode = (typeof STEP_STATUSES)[number]
