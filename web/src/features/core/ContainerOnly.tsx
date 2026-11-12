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
const forEngine = (cmd: string, e: Engine) => (e === 'docker' ? cmd : cmd.replace(/^docker /gm, 'podman '))
/** The images a container-only install runs (compose.yaml, compose.sensors.yaml): the cosign lines name only these. */
const CONTAINER_SERVICES = ['core', 'sensor', 'scan']
/** release.RegistryPrefix: the only registry and repository family of the release images (D-104 (1)). */
const REGISTRY = 'ghcr.io/knt048/vedette-'
type Image = { service: string; digest: string }
/** One `cosign verify` per image of the release this install runs, by the digest of its signed manifest. */
const verifyCmd = (images: readonly Image[]) => images.map((i) => `cosign verify --key cosign.pub ${REGISTRY}${i.service}@${i.digest}`).join('\n')
/** The image lines of the downloaded vedette.env must name those same digests: it prints how many lines do (one per image). */
const matchCmd = (images: readonly Image[]) => `grep -cF ${images.map((i) => `-e '${REGISTRY}${i.service}@${i.digest}'`).join(' ')} vedette.env`
const SAFE_VERSION = /^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$/
/** The four files every release publishes for this install, each with a .minisig (D-451): an update replaces all of them. */
const RELEASE_FILES = ['vedette.env', 'compose.yaml', 'compose.sensors.yaml', 'compose.syslog.yaml']
/** The kept folder is named after the release it runs, so a second update never overwrites the way back (mv -n refuses). */
const keptName = (running: string) => `vedette-${SAFE_VERSION.test(running) ? running : 'old'}`
const keepCmd = (kept: string) => `mkdir -p ${kept} && mv -n ${RELEASE_FILES.join(' ')} ${kept}/`
/** The release assets on GitHub Releases (D-150, D-451), the same place install.sh and the box download from. */
const fetchCmd = (version: string) => `u=https://github.com/KNT048/vedette/releases/download/v${SAFE_VERSION.test(version) ? version : '<version>'}
for f in ${RELEASE_FILES.join(' ')}; do curl -fsSLO "$u/$f" && curl -fsSLO "$u/$f.minisig"; done`
const minisignCmd = RELEASE_FILES.map((f) => `minisign -Vm ${f} -p vedette.pub`).join('\n')

/**
 * Settings → Updates on a container-only install (S-CORE-9 G4, D-381): core's own update check says whether a newer
 * release exists (it runs without a host); the customer updates with two blocks of commands on their machine, for Docker
 * or Podman. No Apply: nothing here installs anything. The four release files are the assets of the offered version on
 * GitHub Releases (D-451); the customer checks each with the vedette.pub kept from the install, never a key from that page.
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
          {offer ? <OfferSteps offer={offer} running={q.data?.components.find((c) => c.id === 'software')?.version ?? ''} engine={engine} /> : !q.data && !q.error ? null : (
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
  const main = offer ? (
    <div className="grid gap-1 rounded-md border border-accent/40 bg-accent-soft px-4 py-3 text-sm">
      <p className="font-medium">{t('container.updates.offer', { version: offer.version, running })}</p>
      {offer.note ? <p className="whitespace-pre-line text-muted">{offer.note}</p> : null}
    </div>
  ) : !s.check_enabled ? (
    <p className="text-sm">{t('container.updates.checkOff')} <Link to="/settings/privacy" className="text-accent underline-offset-4 hover:underline">{t('container.updates.privacyLink')}</Link>.</p>
  ) : !s.last_check ? <p className="text-sm">{t('container.updates.notYet')}</p>
  : <p className="text-sm">{t('container.updates.latest')}</p>
  // The running version and the last check, always (the offer and "never" texts alone do not say both).
  return (
    <>
      {main}
      <p className="text-[13px] text-muted">{t('container.updates.running', { version: running })} {s.last_check ? t('container.updates.checked', { when: fmtRelative(s.last_check) }) : t('container.updates.neverChecked')}</p>
    </>
  )
}

/**
 * The steps of S-CORE-9 G4 for the offered release, in the order they are safe to run: move the four files of the running
 * release into a kept folder, download the new release's four files and check their minisign signatures (D-451: a release
 * that changes a compose file reaches the customer), check each image with cosign and that vedette.env names those same
 * digests (block 2), and only then copy the two local lines, pull and start (block 1).
 */
function OfferSteps({ offer, running, engine }: { offer: UpdateAvailable; running: string; engine: Engine }) {
  const { t } = useTranslation('core')
  const kept = keptName(running)
  const images = (offer.images ?? []).filter((i) => CONTAINER_SERVICES.includes(i.service))
  return (
    <>
      <h3 className="mt-2 text-sm font-semibold">{t('container.updates.block1', { version: offer.version })}</h3>
      <ol className="grid list-decimal gap-3 pl-5 text-sm">
        <li className="grid gap-1.5">{t('container.updates.stepKeep', { kept })}<CodeBlock code={keepCmd(kept)} /></li>
        <li className="grid gap-1.5">
          {t('container.updates.stepFetch', { version: offer.version })}<CodeBlock code={fetchCmd(offer.version)} />
          {t('container.updates.stepVerify', { version: offer.version })}<CodeBlock code={minisignCmd} />
        </li>
        {images.length ? (
          <li className="grid gap-1.5">
            {t('container.updates.verifyWhy', { version: offer.version })}
            <CodeBlock label={t('container.updates.verifyLabel')} code={verifyCmd(images)} />
            {t('container.updates.matchWhy', { count: images.length })}
            <CodeBlock code={matchCmd(images)} />
          </li>
        ) : null}
        <li className="grid gap-1.5">{t('container.updates.stepLines', { kept })}<CodeBlock code={forEngine(UPDATE_CMD, engine)} /></li>
      </ol>
      <p className="text-[13px] text-muted">{t('container.updates.backOffer', { kept })}</p>
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
