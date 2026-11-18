import { useTranslation } from 'react-i18next'
import { CodeBlock } from '@/components/common/CodeBlock'
import { fmtDateTime } from '@/lib/format'
import type { AgentState } from './types'

/** The service commands for a machine's system: look at the osquery agent, and start it again. Windows runs them in PowerShell as
 *  Administrator; Linux needs root. */
export const AGENT_COMMANDS = {
  windows: { check: 'Get-Service osqueryd', restart: 'Restart-Service osqueryd' },
  linux: { check: 'systemctl status osqueryd', restart: 'sudo systemctl restart osqueryd' },
} as const

/** What a quiet (or never-reported) agent says where the person looks: since when, what to do, the exact commands for its system. */
export function AgentQuietNote({ state, since, os }: { state: Exclude<AgentState, 'reporting'>; since: string | null; os: 'windows' | 'linux' }) {
  const { t } = useTranslation('inventory')
  const cmd = AGENT_COMMANDS[os]
  return (
    <div className="grid gap-1.5" data-testid="agent-quiet">
      <p className="text-meta font-medium text-warn">
        {state === 'quiet' && since ? t('agents.quiet.since', { when: fmtDateTime(since) }) : t('agents.quiet.never')}
      </p>
      <p className="text-caption text-muted">{t(os === 'windows' ? 'agents.quiet.whereWindows' : 'agents.quiet.whereLinux')}</p>
      <CodeBlock label={t('agents.quiet.check')} code={cmd.check} />
      <CodeBlock label={t('agents.quiet.restart')} code={cmd.restart} />
      <p className="text-caption text-muted">{t('agents.quiet.repair')}</p>
    </div>
  )
}
