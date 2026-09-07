import * as Fs from 'node:fs'
import * as Path from 'node:path'
import * as Process from 'node:process'
import { pathToFileURL } from 'node:url'

/* oxlint-disable oxibelt/pascal-case -- GitHub and workflow-output fields use stable lower-camel-case names. */

type JsonRecord = Record<string, unknown>

export type RebuildProducerSelectionOptions = {
  eventName: 'workflow_dispatch' | 'workflow_run'
  releaseTag: string
  revision: string
  manualProducerRunId?: string
  manualProducerRunAttempt?: string
  producerRun?: unknown
}

export type RebuildProducerSelection = {
  producerRunId: number
  producerRunAttempt: number
  producerRunInvocationUri?: string
}

const CanonicalRepository = 'OxiBelt/OxiBelt'
const ReleaseWorkflowPath = '.github/workflows/release.yml'
const Revision = /^[0-9a-f]{40}$/
const StableTag = /^[0-9]+\.[0-9]+\.[0-9]+$/
const BetaTag = /^[0-9]+\.[0-9]+\.[0-9]+-beta\.[0-9]+$/
const BuildTag = /^[0-9]+\.[0-9]+\.[0-9]+-build\.[0-9a-f]{8}$/
const PositiveDecimal = /^[1-9][0-9]*$/
const MaximumMetadataBytes = 1024 * 1024

function IsRecord(Value: unknown): Value is JsonRecord {
  return typeof Value === 'object' && Value !== null && !Array.isArray(Value)
}

function StrictMatch(Value: string, Pattern: RegExp): boolean {
  return !Value.includes('\n') && !Value.includes('\r') && Pattern.test(Value)
}

function RecordValue(Value: unknown, Label: string): JsonRecord {
  if (!IsRecord(Value)) {
    throw new Error(`${Label} must be an object`)
  }
  return Value
}

function PositiveSafeInteger(Value: unknown, Label: string): number {
  if (!Number.isSafeInteger(Value) || Number(Value) < 1) {
    throw new Error(`${Label} must be a positive safe integer`)
  }
  return Number(Value)
}

function CanonicalPositiveDecimal(Value: string, Label: string): number {
  if (!StrictMatch(Value, PositiveDecimal)) {
    throw new Error(`${Label} must be a canonical positive decimal integer`)
  }
  const NumberValue = Number(Value)
  if (!Number.isSafeInteger(NumberValue) || String(NumberValue) !== Value) {
    throw new Error(`${Label} must be a canonical positive decimal safe integer`)
  }
  return NumberValue
}

function FullName(Value: unknown, Label: string): string {
  const Repository = RecordValue(Value, Label)
  if (Repository.full_name !== CanonicalRepository) {
    throw new Error(`${Label} is not ${CanonicalRepository}`)
  }
  return CanonicalRepository
}

function ProducerEventsForTag(Tag: string): readonly ('release' | 'push' | 'workflow_dispatch')[] {
  if (StrictMatch(Tag, StableTag) || StrictMatch(Tag, BetaTag)) return ['release', 'workflow_dispatch']
  if (StrictMatch(Tag, BuildTag)) return ['push', 'workflow_dispatch']
  throw new Error(`release tag is invalid: ${Tag}`)
}

function AssertProducerRun(
  Value: unknown,
  ExpectedRunId: number,
  ExpectedRunAttempt: number,
  ReleaseTag: string,
  RevisionValue: string,
  ExpectedEvents: readonly ('release' | 'push' | 'workflow_dispatch')[],
  RequireTagBranch: boolean
): void {
  const Run = RecordValue(Value, 'producer workflow run')
  if (
    PositiveSafeInteger(Run.id, 'producer workflow run id') !== ExpectedRunId ||
    PositiveSafeInteger(Run.run_attempt, 'producer workflow run attempt') !== ExpectedRunAttempt ||
    Run.path !== ReleaseWorkflowPath ||
    !ExpectedEvents.includes(Run.event as 'release' | 'push' | 'workflow_dispatch') ||
    Run.status !== 'completed' ||
    Run.conclusion !== 'success' ||
    Run.head_sha !== RevisionValue ||
    (RequireTagBranch && Run.head_branch !== ReleaseTag)
  ) {
    throw new Error('producer workflow run does not bind the selected release identity')
  }
  FullName(Run.repository, 'producer workflow repository')
  FullName(Run.head_repository, 'producer workflow head repository')
}

function InvocationUri(RunId: number, RunAttempt: number): string {
  return `https://github.com/${CanonicalRepository}/actions/runs/${RunId}/attempts/${RunAttempt}`
}

export function ResolveRebuildProducerSelection(Options: RebuildProducerSelectionOptions): RebuildProducerSelection {
  if (!StrictMatch(Options.revision, Revision)) {
    throw new Error('release revision must be a full lowercase Git commit')
  }
  const ExpectedEvents = ProducerEventsForTag(Options.releaseTag)
  const ManualId = Options.manualProducerRunId === '' ? undefined : Options.manualProducerRunId
  const ManualAttempt = Options.manualProducerRunAttempt === '' ? undefined : Options.manualProducerRunAttempt
  const ManualSelection = ManualId !== undefined || ManualAttempt !== undefined

  if (Options.eventName === 'workflow_run') {
    if (ManualSelection) {
      throw new Error('automatic rebuild verification cannot accept manual producer inputs')
    }
    if (!ExpectedEvents.includes('release')) {
      throw new Error('automatic rebuild verification requires a stable or beta release tag')
    }
    const Run = RecordValue(Options.producerRun, 'automatic producer workflow run')
    const RunId = PositiveSafeInteger(Run.id, 'automatic producer workflow run id')
    const RunAttempt = PositiveSafeInteger(Run.run_attempt, 'automatic producer workflow run attempt')
    AssertProducerRun(Run, RunId, RunAttempt, Options.releaseTag, Options.revision, ['release'], false)
    return {
      producerRunId: RunId,
      producerRunAttempt: RunAttempt,
      producerRunInvocationUri: InvocationUri(RunId, RunAttempt)
    }
  }

  if (Options.eventName !== 'workflow_dispatch') {
    throw new Error('unsupported rebuild event')
  }
  if (!ManualSelection) {
    return { producerRunId: 0, producerRunAttempt: 0 }
  }
  if (ManualId === undefined || ManualAttempt === undefined) {
    throw new Error('manual producer run id and attempt must be supplied together')
  }
  const RunId = CanonicalPositiveDecimal(ManualId, 'manual producer run id')
  const RunAttempt = CanonicalPositiveDecimal(ManualAttempt, 'manual producer run attempt')
  AssertProducerRun(Options.producerRun, RunId, RunAttempt, Options.releaseTag, Options.revision, ExpectedEvents, true)
  return {
    producerRunId: RunId,
    producerRunAttempt: RunAttempt,
    producerRunInvocationUri: InvocationUri(RunId, RunAttempt)
  }
}

function ReadJson(PathValue: string): unknown {
  const Resolved = Path.resolve(PathValue)
  let Descriptor: number
  try {
    Descriptor = Fs.openSync(Resolved, Fs.constants.O_RDONLY | Fs.constants.O_NOFOLLOW)
  } catch {
    throw new Error('producer workflow metadata must be a regular non-symlink file')
  }
  try {
    const Metadata = Fs.fstatSync(Descriptor)
    if (!Metadata.isFile() || Metadata.size < 1 || Metadata.size > MaximumMetadataBytes) {
      throw new Error('producer workflow metadata must be a bounded non-empty regular file')
    }
    return JSON.parse(Fs.readFileSync(Descriptor, 'utf8')) as unknown
  } catch (ErrorValue) {
    if (ErrorValue instanceof SyntaxError) {
      throw new Error('producer workflow metadata is not valid JSON')
    }
    throw ErrorValue
  } finally {
    Fs.closeSync(Descriptor)
  }
}

function RunCli(): void {
  const Arguments = Process.argv.slice(2)
  if (Arguments[0] !== 'resolve') {
    throw new Error('usage: rebuild_producer.ts resolve --event-name <workflow_dispatch|workflow_run> --release-tag <tag> --revision <sha> [--manual-producer-run-id <id> --manual-producer-run-attempt <attempt>] [--producer-run <metadata.json>]')
  }
  const Values = new Map<string, string>()
  for (let Index = 1; Index < Arguments.length; Index += 2) {
    const Option = Arguments[Index]
    const Value = Arguments[Index + 1]
    if (!['--event-name', '--release-tag', '--revision', '--manual-producer-run-id', '--manual-producer-run-attempt', '--producer-run'].includes(Option) ||
        Value === undefined || Values.has(Option)) {
      throw new Error('rebuild producer resolver received invalid arguments')
    }
    Values.set(Option, Value)
  }
  const EventName = Values.get('--event-name')
  if (EventName !== 'workflow_dispatch' && EventName !== 'workflow_run') {
    throw new Error('rebuild producer resolver requires a supported event name')
  }
  const ReleaseTag = Values.get('--release-tag')
  const RevisionValue = Values.get('--revision')
  if (ReleaseTag === undefined || RevisionValue === undefined) {
    throw new Error('rebuild producer resolver requires release tag and revision')
  }
  const ProducerRunPath = Values.get('--producer-run')
  const Selection = ResolveRebuildProducerSelection({
    eventName: EventName,
    releaseTag: ReleaseTag,
    revision: RevisionValue,
    manualProducerRunId: Values.get('--manual-producer-run-id'),
    manualProducerRunAttempt: Values.get('--manual-producer-run-attempt'),
    producerRun: ProducerRunPath === undefined ? undefined : ReadJson(ProducerRunPath)
  })
  Process.stdout.write(`${JSON.stringify(Selection)}\n`)
}

const Entrypoint = Process.argv[1]
if (Entrypoint !== undefined && import.meta.url === pathToFileURL(Path.resolve(Entrypoint)).href) {
  try {
    RunCli()
  } catch (ErrorValue) {
    const Message = ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)
    console.error(`rebuild producer resolver error: ${Message}`)
    process.exitCode = 1
  }
}
