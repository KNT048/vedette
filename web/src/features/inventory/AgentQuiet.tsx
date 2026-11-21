import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { kindLabel } from '@/lib/deviceTypes'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useAgentReport, useAgents } from './api'
import { nameOf } from './nameOf'
import type { AgentState, DeviceDetail, DeviceSourceRow } from './types'

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

/** What an osquery agent's troubleshooting says. Quiet: since when, then the two causes (the service stopped, or it runs but cannot
 *  reach the box) each with its own commands. Never reported: the agent is running and calling, it has delivered nothing. Reporting:
 *  the same two checks, for a person who wants to look. */
export function AgentQuietNote({ state, since, os, box }: { state: Exclude<AgentState, 'replaced'>; since: string | null; os: 'windows' | 'linux'; box?: string }) {
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
    <div className="grid gap-2" data-testid={state === 'quiet' ? 'agent-quiet' : 'agent-steps'}>
      {state === 'quiet' ? <p className="text-meta font-medium text-warn">{since ? t('agents.quiet.since', { when: fmtDateTime(since) }) : t('agents.quiet.sinceUnknown')}</p> : null}
      <div className="grid gap-1.5">
        <p className="text-caption font-medium">{t(state === 'quiet' ? 'agents.quiet.stopped' : 'agents.check.service')}</p>
        <p className="text-caption text-muted">{t(os === 'windows' ? 'agents.quiet.whereWindows' : 'agents.quiet.whereLinux')}</p>
        <CodeBlock label={t('agents.quiet.check')} code={cmd.check} />
        <CodeBlock label={t('agents.quiet.restart')} code={cmd.restart} />
        {os === 'linux' ? <p className="text-caption text-muted">{t('agents.quiet.sysv')}</p> : null}
      </div>
      <div className="grid gap-1.5">
        <p className="text-caption font-medium">{t(state === 'quiet' ? 'agents.quiet.running' : 'agents.check.reach')}</p>
        <p className="text-caption text-muted">{state === 'quiet'
          ? (hp ? t('agents.quiet.runningBody', { box: `${hp.host}:${hp.port}` }) : t('agents.quiet.runningBodyNoBox'))
          : (hp ? t('agents.check.reachBody', { box: `${hp.host}:${hp.port}` }) : t('agents.check.reachBodyNoBox'))}</p>
        {hp ? <CodeBlock label={t('agents.quiet.reach')} code={cmd.reach(hp.host, hp.port)} /> : null}
      </div>
      <p className="text-caption text-muted">{t('agents.quiet.repair')}</p>
    </div>
  )
}

/** An interval in words: "5 minutes", "1 hour", "1 day". */
function useEvery() {
  const { t } = useTranslation('inventory')
  return (s: number) => (s < 3600 ? t('agents.check.minutes', { count: Math.max(1, Math.round(s / 60)) })
    : s < 86400 ? t('agents.check.hours', { count: Math.round(s / 3600) }) : t('agents.check.days', { count: Math.round(s / 86400) }))
}

/** "Check" on the agent row of a device's Sources: how the agent is doing, judged by its own rhythm, and the troubleshooting steps
 *  for its machine. The steps are here, behind the button, never on the page by default. */
export function AgentCheckDialog({ d, row, onClose }: { d: DeviceDetail; row: DeviceSourceRow; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const every = useEvery()
  const name = nameOf(d.asset, kindLabel(d.asset.kind))
  const report = useAgentReport(d.asset.id).data
  const box = useAgents(true).data?.server_url
  const at = row.last_at
  const state = report?.state ?? null
  const line = row.state === 'quiet' ? (at ? t('agents.check.quiet', { when: fmtRelative(at) }) : t('agents.check.quietUnknown'))
    : row.state === 'off' ? t('agents.check.off')
    : at ? t('agents.check.reporting', { when: fmtRelative(at) }) : null
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent wide title={t('agents.check.title', { name })}>
        <div className="grid min-w-0 gap-4 [&>*]:min-w-0" data-testid="agent-check">
          <div className="grid gap-1">
            {line ? <p className="text-sm font-medium">{line}</p> : null}
            {report?.rhythm_s ? <p className="text-meta text-muted">{t(row.agent === 'wazuh' ? 'agents.check.pulls' : 'agents.check.calls', { every: every(report.rhythm_s) })}</p> : null}
          </div>
          {row.agent === 'wazuh' ? (
            <p className="text-meta">{t('agents.check.wazuhBody')}{' '}
              <Link to="/devices/setup?tab=wazuh" className="font-medium text-accent underline underline-offset-4" onClick={onClose}>{t('agents.check.wazuhLink')}</Link></p>
          ) : report?.os && state && state !== 'replaced' ? (
            <AgentQuietNote state={state} since={report.quiet_since} os={report.os} box={box} />
          ) : null}
        </div>
        <DialogFooter>
          <Link to="/devices/setup?tab=agents" className="mr-auto self-center text-meta font-medium text-accent underline underline-offset-4" onClick={onClose}>{t('sources.agent.manage')}</Link>
          <DialogClose asChild><Button>{t('common:close')}</Button></DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
