import { useTranslation } from 'react-i18next'
import { CodeBlock } from '@/components/common/CodeBlock'
import { fmtDateTime } from '@/lib/format'
import type { AgentState } from './types'

/** The host and port the agent calls, from the box address of the agents response ("https://10.0.0.5:8443"); null when it has none. */
export function boxHostPort(url: string | undefined): { host: string; port: string } | null {
  if (!url) return null
  try {
    const u = new URL(url)
    return { host: u.hostname, port: u.port || '443' }
  } catch { return null }
}

/** The service commands for a machine's system: look at the osquery agent, start it again, and test that this machine reaches the box
 *  (the agent can run and still not reach it). Windows runs them in PowerShell as Administrator; Linux needs root. */
export const AGENT_COMMANDS = {
  windows: { check: 'Get-Service osqueryd', restart: 'Restart-Service osqueryd', reach: (h: string, p: string) => `Test-NetConnection ${h} -Port ${p}` },
  linux: { check: 'systemctl status osqueryd', restart: 'sudo systemctl restart osqueryd', reach: (h: string, p: string) => `timeout 5 bash -c '</dev/tcp/${h}/${p}' && echo reachable` },
} as const

/** What a quiet or never-reported agent says where the person looks. Quiet: since when, then the two causes (the service stopped, or it
 *  runs but cannot reach the box) each with its own commands. Never reported: the agent is running and calling, it has delivered nothing. */
export function AgentQuietNote({ state, since, os, box }: { state: Exclude<AgentState, 'reporting' | 'replaced'>; since: string | null; os: 'windows' | 'linux'; box?: string }) {
  const { t } = useTranslation('inventory')
  const cmd = AGENT_COMMANDS[os]
  const hp = boxHostPort(box)
  if (state === 'never_reported') {
    return (
      <div className="grid gap-1.5" data-testid="agent-never-reported">
        <p className="text-meta font-medium text-warn">{t('agents.neverReported.title')}</p>
        <p className="text-caption text-muted">{t('agents.neverReported.body')}</p>
      </div>
    )
  }
  return (
    <div className="grid gap-2" data-testid="agent-quiet">
      <p className="text-meta font-medium text-warn">{since ? t('agents.quiet.since', { when: fmtDateTime(since) }) : t('agents.quiet.sinceUnknown')}</p>
      <div className="grid gap-1.5">
        <p className="text-caption font-medium">{t('agents.quiet.stopped')}</p>
        <p className="text-caption text-muted">{t(os === 'windows' ? 'agents.quiet.whereWindows' : 'agents.quiet.whereLinux')}</p>
        <CodeBlock label={t('agents.quiet.check')} code={cmd.check} />
        <CodeBlock label={t('agents.quiet.restart')} code={cmd.restart} />
        {os === 'linux' ? <p className="text-caption text-muted">{t('agents.quiet.sysv')}</p> : null}
      </div>
      <div className="grid gap-1.5">
        <p className="text-caption font-medium">{t('agents.quiet.running')}</p>
        <p className="text-caption text-muted">{hp ? t('agents.quiet.runningBody', { box: `${hp.host}:${hp.port}` }) : t('agents.quiet.runningBodyNoBox')}</p>
        {hp ? <CodeBlock label={t('agents.quiet.reach')} code={cmd.reach(hp.host, hp.port)} /> : null}
      </div>
      <p className="text-caption text-muted">{t('agents.quiet.repair')}</p>
    </div>
  )
}
