import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Section } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { useSkills, useToggleSkill } from '../harness-api'
import { List, Row, Toggle } from './shared'

/** Skill của sản phẩm (docs/AI_ASSISTANT.md §2): mỗi skill một việc cụ thể, bật/tắt riêng. */
export default function SkillsTab() {
  const { t } = useTranslation('ai')
  const skills = useSkills()
  const toggle = useToggleSkill()
  return (
    <Section title={t('harness.skills.title')} description={t('harness.skills.body')} stories={['S-AI-7']}>
      <QueryState query={skills}>
        {({ items }) => (
          <List label={t('harness.skills.title')}>
            {items.map((s) => (
              <Row key={s.id} dim={!s.enabled}
                actions={<Toggle checked={s.enabled} label={t('harness.skills.enable', { name: s.name })} onChange={(enabled) => toggle.mutate({ id: s.id, enabled }, { onError: (e) => toast.error(e instanceof Error ? e.message : String(e)) })} />}>
                <p className="font-medium">{s.name} {!s.enabled ? <Chip tone="off">{t('harness.off')}</Chip> : null}</p>
                <p className="text-muted">{s.what}</p>
                <p className="text-[13px] text-muted">{s.jobs.length ? t('harness.skills.usedBy', { jobs: s.jobs.map((j) => t(`jobs.${j}.name`)).join(', ') }) : t('harness.skills.batch')}</p>
              </Row>
            ))}
          </List>
        )}
      </QueryState>
    </Section>
  )
}
