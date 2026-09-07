import * as Assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import * as Fs from 'node:fs'
import * as Os from 'node:os'
import * as Path from 'node:path'
import * as Process from 'node:process'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { ResolveRebuildProducerSelection } from '../sources/rebuild_producer.js'

/* oxlint-disable oxibelt/pascal-case -- Fixtures mirror workflow JSON fields. */

const Revision = 'a'.repeat(40)
const RepositoryRoot = fileURLToPath(new URL('../..', import.meta.url))

function ProducerRun(Overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 123456789,
    run_attempt: 2,
    path: '.github/workflows/release.yml',
    event: 'release',
    status: 'completed',
    conclusion: 'success',
    head_sha: Revision,
    head_branch: '1.2.3',
    repository: { full_name: 'OxiBelt/OxiBelt' },
    head_repository: { full_name: 'OxiBelt/OxiBelt' },
    ...Overrides
  }
}

void test('automatic workflow_run selection requires its exact trusted producer identity', () => {
  Assert.deepEqual(ResolveRebuildProducerSelection({
    eventName: 'workflow_run',
    releaseTag: '1.2.3',
    revision: Revision,
    producerRun: ProducerRun()
  }), {
    producerRunId: 123456789,
    producerRunAttempt: 2,
    producerRunInvocationUri: 'https://github.com/OxiBelt/OxiBelt/actions/runs/123456789/attempts/2'
  })
  Assert.throws(() => ResolveRebuildProducerSelection({
    eventName: 'workflow_run', releaseTag: '1.2.3-build.aaaaaaaa', revision: Revision, producerRun: ProducerRun()
  }), /stable or beta/)
  Assert.throws(() => ResolveRebuildProducerSelection({
    eventName: 'workflow_run', releaseTag: '1.2.3', revision: Revision, producerRun: undefined
  }), /must be an object/)
})

void test('manual selected producer rejects partial, non-canonical, unsafe, and mismatched identities', () => {
  const Base = { eventName: 'workflow_dispatch' as const, releaseTag: '1.2.3', revision: Revision }
  Assert.throws(() => ResolveRebuildProducerSelection({ ...Base, manualProducerRunId: '123456789' }), /supplied together/)
  Assert.throws(() => ResolveRebuildProducerSelection({ ...Base, manualProducerRunId: '0123', manualProducerRunAttempt: '2', producerRun: ProducerRun() }), /canonical positive decimal/)
  Assert.throws(() => ResolveRebuildProducerSelection({ ...Base, manualProducerRunId: '123\n', manualProducerRunAttempt: '2', producerRun: ProducerRun() }), /canonical positive decimal/)
  Assert.throws(() => ResolveRebuildProducerSelection({ ...Base, manualProducerRunId: '9007199254740992', manualProducerRunAttempt: '2', producerRun: ProducerRun() }), /safe integer/)
  Assert.throws(() => ResolveRebuildProducerSelection({ ...Base, manualProducerRunId: '123456789', manualProducerRunAttempt: '3', producerRun: ProducerRun() }), /does not bind/)
  Assert.throws(() => ResolveRebuildProducerSelection({ ...Base, manualProducerRunId: '123456789', manualProducerRunAttempt: '2', producerRun: ProducerRun({ head_repository: { full_name: 'fork/OxiBelt' } }) }), /head repository/)
  Assert.throws(() => ResolveRebuildProducerSelection({ ...Base, manualProducerRunId: '123456789', manualProducerRunAttempt: '2', producerRun: ProducerRun({ path: '.github/workflows/other.yml' }) }), /does not bind/)
})

void test('manual selected producer maps tag channels to the exact producer event', () => {
  const Resolve = (Tag: string, Event: string): void => {
    Assert.doesNotThrow(() => ResolveRebuildProducerSelection({
      eventName: 'workflow_dispatch', releaseTag: Tag, revision: Revision,
      manualProducerRunId: '123456789', manualProducerRunAttempt: '2',
      producerRun: ProducerRun({ event: Event, head_branch: Tag })
    }))
  }
  Resolve('1.2.3-beta.4', 'release')
  Resolve('1.2.3-build.aaaaaaaa', 'push')
  Resolve('1.2.3-build.aaaaaaaa', 'workflow_dispatch')
  Assert.throws(() => ResolveRebuildProducerSelection({
    eventName: 'workflow_dispatch', releaseTag: '1.2.3', revision: Revision,
    manualProducerRunId: '123456789', manualProducerRunAttempt: '2', producerRun: ProducerRun({ event: 'push' })
  }), /does not bind/)
})

void test('manual dispatch without producer selection preserves legacy zero identity', () => {
  Assert.deepEqual(ResolveRebuildProducerSelection({
    eventName: 'workflow_dispatch', releaseTag: '1.2.3-build.aaaaaaaa', revision: Revision
  }), { producerRunId: 0, producerRunAttempt: 0 })
  Assert.throws(() => ResolveRebuildProducerSelection({
    eventName: 'workflow_dispatch', releaseTag: '1.2.3\n', revision: Revision
  }), /release tag is invalid/)
})

function ProducerSelectionShell(): string {
  const Workflow = Fs.readFileSync(Path.join(RepositoryRoot, '.github/workflows/verify-release-rebuild.yml'), 'utf8')
  const Start = Workflow.indexOf('          producer_metadata=')
  const End = Workflow.indexOf('\n\n          if [[ "${release_tag}" == *-build.* ]];', Start)
  if (Start < 0 || End < 0) throw new Error('producer selection shell block is missing from workflow')
  return Workflow.slice(Start, End).replace(/^ {10}/gm, '')
}

function RunProducerSelectionShell(Options: {
  eventName: 'workflow_dispatch' | 'workflow_run'
  manualId?: string
  manualAttempt?: string
  workflowRun?: Record<string, unknown> | null
  producerRun?: Record<string, unknown>
}): { status: number | null, stdout: string, stderr: string, ghCalls?: string } {
  const Root = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-rebuild-producer-shell-'))
  const BinaryDirectory = Path.join(Root, 'bin')
  const CounterPath = Path.join(Root, 'gh-invocations')
  const FixturePath = Path.join(Root, 'producer.json')
  try {
    Fs.mkdirSync(BinaryDirectory)
    Fs.writeFileSync(FixturePath, JSON.stringify(Options.producerRun ?? ProducerRun()))
    Fs.writeFileSync(Path.join(BinaryDirectory, 'gh'), '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >>"$GH_COUNTER"\ncp "$PRODUCER_FIXTURE_PATH" /dev/stdout\n')
    Fs.chmodSync(Path.join(BinaryDirectory, 'gh'), 0o700)
    const Script = [
      'set -euo pipefail',
      'release_tag=1.2.3',
      `revision=${Revision}`,
      'automatic=$([[ "${EVENT_NAME}" == workflow_run ]] && printf true || printf false)',
      ProducerSelectionShell(),
      'printf "selection=%s/%s/%s\\n" "${producer_run_id}" "${producer_run_attempt}" "${producer_run_invocation_uri}"'
    ].join('\n')
    const Result = spawnSync('bash', ['-c', Script], {
      cwd: RepositoryRoot,
      encoding: 'utf8',
      env: {
        ...Process.env,
        EVENT_NAME: Options.eventName,
        GH_COUNTER: CounterPath,
        MANUAL_PRODUCER_RUN_ATTEMPT: Options.manualAttempt ?? '',
        MANUAL_PRODUCER_RUN_ID: Options.manualId ?? '',
        PATH: `${BinaryDirectory}:${Process.env.PATH ?? ''}`,
        PRODUCER_FIXTURE_PATH: FixturePath,
        RUNNER_TEMP: Root,
        WORKFLOW_RUN_JSON: JSON.stringify(Options.workflowRun === undefined ? ProducerRun() : Options.workflowRun)
      }
    })
    return {
      status: Result.status,
      stdout: String(Result.stdout),
      stderr: String(Result.stderr),
      ghCalls: Fs.existsSync(CounterPath) ? Fs.readFileSync(CounterPath, 'utf8') : undefined
    }
  } finally {
    Fs.rmSync(Root, { force: true, recursive: true })
  }
}

void test('workflow producer-selection shell preserves omitted compatibility and authenticates exact manual and automatic sources', () => {
  const Omitted = RunProducerSelectionShell({ eventName: 'workflow_dispatch' })
  Assert.equal(Omitted.status, 0, Omitted.stderr)
  Assert.match(Omitted.stdout.trimEnd(), /selection=0\/0\/$/)
  Assert.equal(Omitted.ghCalls, undefined)

  const Selected = RunProducerSelectionShell({
    eventName: 'workflow_dispatch', manualId: '123456789', manualAttempt: '2'
  })
  Assert.equal(Selected.status, 0, Selected.stderr)
  Assert.equal(Selected.ghCalls?.trim(), 'api --method GET /repos/OxiBelt/OxiBelt/actions/runs/123456789/attempts/2')
  Assert.match(Selected.stdout.trimEnd(), /selection=123456789\/2\/https:\/\/github.com\/OxiBelt\/OxiBelt\/actions\/runs\/123456789\/attempts\/2$/)

  for (const [ManualId, ManualAttempt] of [
    ['', '2'], ['0', '2'], ['0123', '2'], ['123\n', '2'], ['123/attempts/2?x=y', '2'], ['$(false)', '2'], ['9007199254740992', '2']
  ]) {
    const Invalid = RunProducerSelectionShell({ eventName: 'workflow_dispatch', manualId: ManualId, manualAttempt: ManualAttempt })
    Assert.notEqual(Invalid.status, 0)
    Assert.match(Invalid.stderr, /canonical positive decimal safe integers/)
    Assert.equal(Invalid.ghCalls, undefined)
  }

  const Automatic = RunProducerSelectionShell({ eventName: 'workflow_run' })
  Assert.equal(Automatic.status, 0, Automatic.stderr)
  Assert.match(Automatic.stdout.trimEnd(), /selection=123456789\/2\/https:\/\/github.com\/OxiBelt\/OxiBelt\/actions\/runs\/123456789\/attempts\/2$/)
  Assert.equal(Automatic.ghCalls, undefined)
  for (const WorkflowRun of [null, ProducerRun({ head_sha: 'b'.repeat(40) })]) {
    const InvalidAutomatic = RunProducerSelectionShell({ eventName: 'workflow_run', workflowRun: WorkflowRun })
    Assert.notEqual(InvalidAutomatic.status, 0)
    Assert.match(InvalidAutomatic.stderr, /automatic producer workflow run|does not bind/)
    Assert.equal(InvalidAutomatic.ghCalls, undefined)
  }
})
