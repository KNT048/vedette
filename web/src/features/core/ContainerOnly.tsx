// What a container-only install (no vedette-host, D-168) shows instead of the controls of the appliance (D-381): what
// the customer does on their own machine, with the commands of docs/INSTALL-CONTAINER.md. The pages never call the
// host endpoints there, which can only answer 409 not_appliance.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { Section } from '@/components/common/PageHeader'
import { CodeBlock } from '@/components/common/CodeBlock'
import { QueryState } from '@/components/common/States'
import { Segmented } from '@/components/ui/segmented'
import { useModules } from '@/lib/modules'
import { fmtRelative } from '@/lib/format'
import { useUpdates } from './api'
import type { UpdateAvailable, UpdatesState } from './types'

/** Where a page waits for the install kind (GET /modules): loading, or the error with Try again when it fails; never an endless spinner. */
export function InstallPending() {
  return <QueryState query={useModules()}>{() => null}</QueryState>
}

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

type Engine = 'docker' | 'podman'
/** The same commands for Podman: `podman compose` (compose v2 provider), `podman run` and `podman logs` take the same arguments (docs/INSTALL-CONTAINER.md). */
export const forEngine = (cmd: string, e: Engine) => (e === 'docker' ? cmd : cmd.replace(/^docker /gm, 'podman '))
/** The images a container-only install runs (compose.yaml, compose.sensors.yaml): the cosign lines name only these. */
const CONTAINER_SERVICES = ['core', 'sensor', 'scan']
/** release.RegistryPrefix: the only registry and repository family of the release images (D-104 (1)). */
const REGISTRY = 'ghcr.io/knt048/vedette-'
/** One `cosign verify` per image of the release this install runs, by the digest of its signed manifest. */
export const verifyCmd = (images: ReadonlyArray<{ service: string; digest: string }>) =>
  images.filter((i) => CONTAINER_SERVICES.includes(i.service)).map((i) => `cosign verify --key cosign.pub ${REGISTRY}${i.service}@${i.digest}`).join('\n')

/**
 * Settings → Updates on a container-only install (S-CORE-9 G4, D-381): core's own update check says whether a newer
 * release exists (it runs without a host); the customer updates with two blocks of commands on their machine, for Docker
 * or Podman. No Apply: nothing here installs anything. The release files come from the release page; the page never
 * makes up a download address (the release assets are slice 7 of WP-08m).
 */
export function ContainerUpdates() {
  const { t } = useTranslation('core')
  const q = useUpdates()
  const [engine, setEngine] = useState<Engine>('docker')
  const offer = q.data?.available.find((a) => a.component === 'software')
  return (
    <>
      <Section title={t('container.updates.title')} description={t('container.updates.desc')}>
        <div className="grid max-w-3xl gap-3">
          <Segmented label={t('container.updates.engine')} value={engine} onChange={setEngine} className="justify-self-start"
            options={[{ value: 'docker', label: 'Docker' }, { value: 'podman', label: 'Podman' }]} />
          <QueryState query={q}>{(s) => <ReleaseStatus s={s} />}</QueryState>
          {offer ? <OfferSteps offer={offer} engine={engine} /> : (
            <>
              <CodeBlock label={t('container.updates.label')} code={forEngine(UPDATE_CMD, engine)} />
              <p className="text-[13px] text-muted">{t('container.updates.back')}</p>
            </>
          )}
        </div>
      </Section>
      <Section title={t('container.os.title')} description={t('container.os.desc')}>{null}</Section>
    </>
  )
}

/** Whether core knows of a newer release: the offered version and its notes, or why there is none to show. */
function ReleaseStatus({ s }: { s: UpdatesState }) {
  const { t } = useTranslation('core')
  const offer = s.available.find((a) => a.component === 'software')
  const running = s.components.find((c) => c.id === 'software')?.version ?? ''
  if (offer) return (
    <div role="status" className="grid gap-1 rounded-md border border-accent/40 bg-accent-soft px-4 py-3 text-sm">
      <p className="font-medium">{t('container.updates.offer', { version: offer.version, running })}</p>
      {offer.note ? <p className="whitespace-pre-line text-muted">{offer.note}</p> : null}
    </div>
  )
  if (!s.check_enabled) return (
    <p role="status" className="text-sm">{t('container.updates.checkOff')} <Link to="/settings/privacy" className="text-accent underline-offset-4 hover:underline">{t('container.updates.privacyLink')}</Link>.</p>
  )
  if (!s.last_check) return <p role="status" className="text-sm">{t('container.updates.notYet')}</p>
  return <p role="status" className="text-sm">{t('container.updates.latest', { version: running, when: fmtRelative(s.last_check) })}</p>
}

/** The two blocks of S-CORE-9 G4 for the offered release: (1) update, (2) check each image with cosign. */
function OfferSteps({ offer, engine }: { offer: UpdateAvailable; engine: Engine }) {
  const { t } = useTranslation('core')
  const verify = verifyCmd(offer.images ?? [])
  return (
    <>
      <h3 className="mt-2 text-sm font-semibold">{t('container.updates.block1', { version: offer.version })}</h3>
      <ol className="grid list-decimal gap-3 pl-5 text-sm">
        <li className="grid gap-1.5">{t('container.updates.stepKeep')}<CodeBlock code="mv vedette.env vedette.env.old" /></li>
        <li className="grid gap-1.5">{t('container.updates.stepFetch', { version: offer.version })}<CodeBlock code="minisign -Vm vedette.env -p vedette.pub" /></li>
        <li className="grid gap-1.5">{t('container.updates.stepLines')}<CodeBlock code={forEngine(UPDATE_CMD, engine)} /></li>
      </ol>
      <p className="text-[13px] text-muted">{t('container.updates.back')}</p>
      {verify ? (
        <>
          <h3 className="mt-2 text-sm font-semibold">{t('container.updates.block2')}</h3>
          <p className="text-sm">{t('container.updates.verifyWhy', { version: offer.version })}</p>
          <CodeBlock label={t('container.updates.verifyLabel')} code={verify} />
        </>
      ) : null}
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
