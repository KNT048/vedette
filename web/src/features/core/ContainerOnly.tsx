// What a container-only install (no vedette-host, D-168) shows instead of the controls of the appliance (D-381): what
// the customer does on their own machine, with the commands of docs/INSTALL-CONTAINER.md. The pages never call the
// host endpoints there, which can only answer 409 not_appliance.
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { CodeBlock } from '@/components/common/CodeBlock'

// docs/INSTALL-CONTAINER.md section 5 and 6, word for word (the image is deploy/containers/pins.env DEBIAN_IMAGE).
const DEBIAN = 'docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2'
export const UPDATE_CMD = `docker compose --env-file vedette.env pull
docker compose --env-file vedette.env up -d`
export const BACKUP_CMD = `docker compose --env-file vedette.env stop core
docker run --rm --network none -v vedette_data:/data:ro -v "$PWD":/backup \\
  ${DEBIAN} \\
  sh -c 'umask 077 && tar czf /backup/vedette-data.tgz -C /data .'
docker compose --env-file vedette.env start core`
export const RESTORE_CMD = `docker compose --env-file vedette.env create core
docker run --rm --network none -v vedette_data:/data -v "$PWD":/backup:ro \\
  ${DEBIAN} \\
  sh -c 'cd /data && tar xzf /backup/vedette-data.tgz'
docker compose --env-file vedette.env start core`

/** Settings → Updates on a container-only install (S-CORE-9 G4): the customer pulls the new images; the operating system is theirs. */
export function ContainerUpdates() {
  const { t } = useTranslation('core')
  return (
    <>
      <Section title={t('container.updates.title')} description={t('container.updates.desc')}>
        <div className="grid max-w-3xl gap-2">
          <CodeBlock label={t('container.updates.label')} code={UPDATE_CMD} />
          <p className="text-[13px] text-muted">{t('container.updates.back')}</p>
        </div>
      </Section>
      <Section title={t('container.os.title')} description={t('container.os.desc')}>{null}</Section>
    </>
  )
}

/** Settings → Data on a container-only install (S-CORE-9 G2): a backup is a copy of the Docker volume vedette_data. */
export function ContainerBackup() {
  const { t } = useTranslation('core')
  return (
    <Section title={t('container.backup.title')} description={t('container.backup.desc')}>
      <div className="grid max-w-3xl gap-2">
        <CodeBlock label={t('container.backup.label')} code={BACKUP_CMD} />
        <p className="text-[13px] text-muted">{t('container.backup.keep')}</p>
        <CodeBlock label={t('container.backup.restoreLabel')} code={RESTORE_CMD} />
      </div>
    </Section>
  )
}

/** Settings → Box network on a container-only install (S-CORE-9 G2, G6): the machine's network is the customer's. */
export function ContainerNetwork() {
  const { t } = useTranslation('core')
  return <Section title={t('container.network.title')} description={t('container.network.desc')}>{null}</Section>
}
