import type { TargetNode } from './types'

/**
 * The place of the target's scan schedule, under the scan line of its page. A node's schedule is a shared schedule under
 * `node.schedule_key` (exposure.target:<id>), set with the shared schedule editor (preview of the next runs, pause, run once,
 * window and limits). That editor and its API are not in the app yet, so nothing is drawn here until they are: this component
 * is where it goes, `<ScheduleEditor scheduleKey={node.schedule_key} />`.
 */
export function ScheduleSlot({ node }: { node: TargetNode }) {
  void node.schedule_key
  return null
}
