import * as Crypto from 'node:crypto'
import * as Fs from 'node:fs'
import * as Path from 'node:path'
import * as Process from 'node:process'
import { pathToFileURL } from 'node:url'
import {
  CanonicalJson,
  FeatureGraduationPolicyDefinitionSha256,
  LoadFeatureGraduationPolicy,
  ValidateFeatureGraduationEvidenceObject,
  ValidateFeatureGraduationEvidenceSet,
  type FeatureGraduationEvidenceReceipt,
  type FeatureGraduationPolicy
} from './feature_graduation.js'
import {
  KubernetesGraduationPolicyDefinitionSha256,
  LoadKubernetesGraduationPolicy,
  ValidateKubernetesGraduationEvidenceObject,
  ValidateKubernetesGraduationEvidenceSet,
  type KubernetesGraduationPolicyValidationOptions,
  type KubernetesGraduationEvidenceReceipt,
  type KubernetesGraduationPolicy
} from './kubernetes_graduation.js'

/* oxlint-disable oxibelt/pascal-case -- This file defines stable sealed-attestation JSON wire keys. */
type JsonObject = Record<string, unknown>

export const FeatureGraduationPredicateType = 'https://oxibelt.dev/attestations/feature-graduation/v1'
export const FeatureGraduationSubjectName = 'feature-graduation-subject.json'

const MaximumFileBytes = 1024 * 1024
const MaximumFiles = 256
const MaximumJsonDepth = 64
const MaximumJsonNodes = 10000
const MaximumJsonStringBytes = 64 * 1024
const MaximumJsonArrayItems = 1024
const MaximumJsonObjectKeys = 256
const FullRevision = /^[0-9a-f]{40}$/
const FeatureWorkflowPath = '.github/workflows/feature-graduation.yml'

type Scope = 'features' | 'kubernetes'
type Phase = 'candidate' | 'official_beta'

export type GraduationExpectations = {
  schemaVersion: 1
  predicateType: typeof FeatureGraduationPredicateType
  result: 'zero_supported' | 'supported'
  policies: Array<{
    scope: Scope
    repository: string
    targetVersion: string
    policyDefinitionSha256: string
  }>
  features: Array<{
    scope: Scope
    featureId: string
    qualifiedPlatforms: string[]
    gates: Array<{
      id: string
      platforms: string[]
    }>
  }>
}

export type RunMetadata = {
  schemaVersion: 1
  repository: string
  workflowPath: typeof FeatureWorkflowPath
  workflowRef: string
  runId: number
  runAttempt: number
  sourceRef: string
  sourceRevision: string
  status: 'in_progress' | 'completed'
  conclusion: null | 'success'
}

export type JobsMetadata = {
  schemaVersion: 1
  repository: string
  runId: number
  runAttempt: number
  jobs: Array<{
    id: number
    name: string
    conclusion: 'success'
  }>
}

export type SealedFeatureGraduation = {
  subject: {
    schemaVersion: 1
    subjectName: typeof FeatureGraduationSubjectName
    repository: string
    sourceRef: string
    sourceRevision: string
    phase: Phase
    predicateSha256: string
  }
  predicate: {
    schemaVersion: 1
    predicateType: typeof FeatureGraduationPredicateType
    repository: string
    sourceRef: string
    sourceRevision: string
    phase: Phase
    run: {
      id: number
      attempt: number
      workflowPath: typeof FeatureWorkflowPath
      workflowRef: string
      status: 'in_progress'
      conclusion: null
    }
    expectations: GraduationExpectations
    inventory: {
      receipts: Array<{ scope: Scope, path: string, sha256: string, featureId: string }>
      reports: Array<{ name: string, sha256: string }>
      logs: Array<{ jobId: number, sha256: string }>
    }
  }
  subjectText: string
  predicateText: string
  subjectSha256: string
}

type ParsedCli = {
  mode: 'expectations' | 'seal' | 'attestation-verify'
  values: Map<string, string[]>
}

function IsObject(Value: unknown): Value is JsonObject {
  return typeof Value === 'object' && Value !== null && !Array.isArray(Value)
}

function CanonicalDigest(Value: string | Buffer): string {
  return `sha256:${Crypto.createHash('sha256').update(Value).digest('hex')}`
}

function AssertExactKeys(Value: JsonObject, Keys: string[], Label: string): void {
  const Actual = Object.keys(Value).sort()
  const Expected = [...Keys].sort()
  if (CanonicalJson(Actual) !== CanonicalJson(Expected)) {
    throw new Error(`${Label} contains unexpected or missing fields`)
  }
}

function AssertExactSet(Label: string, Actual: Iterable<string>, Expected: Iterable<string>): void {
  const ActualValues = [...Actual].sort()
  const ExpectedValues = [...Expected].sort()
  if (CanonicalJson(ActualValues) !== CanonicalJson(ExpectedValues)) {
    throw new Error(`${Label} must be exactly [${ExpectedValues.join(', ')}], found [${ActualValues.join(', ')}]`)
  }
}

function RequireString(Value: unknown, Label: string): string {
  if (typeof Value !== 'string' || Value === '') {
    throw new Error(`${Label} must be a non-empty string`)
  }
  return Value
}

function RequireInteger(Value: unknown, Label: string): number {
  if (!Number.isSafeInteger(Value) || (Value as number) < 1) {
    throw new Error(`${Label} must be a positive safe integer`)
  }
  return Value as number
}

function RequireRevision(Value: string, Label: string): string {
  if (!FullRevision.test(Value)) {
    throw new Error(`${Label} must be a full lowercase Git commit`)
  }
  return Value
}

function RequirePhase(Value: string): Phase {
  if (Value !== 'candidate' && Value !== 'official_beta') {
    throw new Error('phase must be candidate or official_beta')
  }
  return Value
}

function ValidatePhaseRef(PhaseValue: Phase, Ref: string): void {
  if (PhaseValue === 'candidate' && Ref !== 'refs/heads/main') {
    throw new Error('candidate phase requires refs/heads/main')
  }
  if (PhaseValue === 'official_beta' && !/^refs\/tags\/0\.8\.0-beta\.[1-9][0-9]*$/.test(Ref)) {
    throw new Error('official_beta phase requires a 0.8.0 beta tag ref')
  }
}

function ResolveWorkspace(WorkspacePath: string): string {
  const Root = Fs.realpathSync(WorkspacePath)
  if (!Fs.statSync(Root).isDirectory()) {
    throw new Error(`workspace path is not a directory: ${WorkspacePath}`)
  }
  return Root
}

function IsPathWithin(Parent: string, Candidate: string): boolean {
  const Relative = Path.relative(Parent, Candidate)
  return Relative === '' || (!Relative.startsWith(`..${Path.sep}`) && Relative !== '..' && !Path.isAbsolute(Relative))
}

function ResolveExistingPath(Root: string, RelativePath: string): string {
  if (Path.isAbsolute(RelativePath)) {
    throw new Error(`path must be relative to the workspace: ${RelativePath}`)
  }
  const Candidate = Path.resolve(Root, RelativePath)
  if (!IsPathWithin(Root, Candidate)) {
    throw new Error(`path escapes the workspace: ${RelativePath}`)
  }
  let Current = Root
  for (const Component of Path.relative(Root, Candidate).split(Path.sep)) {
    if (Component === '') continue
    Current = Path.join(Current, Component)
    const Stat = Fs.lstatSync(Current)
    if (Stat.isSymbolicLink()) {
      throw new Error(`path must not traverse a symlink: ${RelativePath}`)
    }
  }
  if (Fs.realpathSync(Candidate) !== Candidate) {
    throw new Error(`path resolves differently from its checked path: ${RelativePath}`)
  }
  return Candidate
}

function ReadBoundedBuffer(Root: string, RelativePath: string): Buffer {
  const Candidate = ResolveExistingPath(Root, RelativePath)
  const Descriptor = Fs.openSync(Candidate, Fs.constants.O_RDONLY | Fs.constants.O_NOFOLLOW)
  try {
    const Stat = Fs.fstatSync(Descriptor)
    if (!Stat.isFile() || Stat.size > MaximumFileBytes) {
      throw new Error(`input must be a regular file within ${MaximumFileBytes} bytes: ${RelativePath}`)
    }
    return Fs.readFileSync(Descriptor)
  } finally {
    Fs.closeSync(Descriptor)
  }
}

function ReadBoundedFile(Root: string, RelativePath: string): string {
  const Content = ReadBoundedBuffer(Root, RelativePath)
  const Text = Content.toString('utf8')
  if (Text.includes('\0')) throw new Error(`input contains a NUL byte: ${RelativePath}`)
  if (!Content.equals(Buffer.from(Text, 'utf8'))) throw new Error(`input must be valid UTF-8 text: ${RelativePath}`)
  return Text
}

function ValidateJsonComplexity(Value: unknown, Label: string, Depth = 0, State = { nodes: 0 }): void {
  if (Depth > MaximumJsonDepth) throw new Error(`${Label} exceeds JSON nesting limit`)
  State.nodes += 1
  if (State.nodes > MaximumJsonNodes) throw new Error(`${Label} exceeds JSON node limit`)
  if (typeof Value === 'string') {
    if (Buffer.byteLength(Value, 'utf8') > MaximumJsonStringBytes) throw new Error(`${Label} exceeds JSON string limit`)
    return
  }
  if (Array.isArray(Value)) {
    if (Value.length > MaximumJsonArrayItems) throw new Error(`${Label} exceeds JSON array-item limit`)
    Value.forEach((Item, Index) => ValidateJsonComplexity(Item, `${Label}[${Index}]`, Depth + 1, State))
    return
  }
  if (IsObject(Value)) {
    const Keys = Object.keys(Value)
    if (Keys.length > MaximumJsonObjectKeys) throw new Error(`${Label} exceeds JSON object-key limit`)
    for (const Key of Keys) {
      if (Buffer.byteLength(Key, 'utf8') > MaximumJsonStringBytes) throw new Error(`${Label} contains oversized JSON key`)
      ValidateJsonComplexity(Value[Key], `${Label}.${Key}`, Depth + 1, State)
    }
  }
}

function ReadCanonicalJson(Root: string, RelativePath: string): { value: unknown, text: string } {
  const Text = ReadBoundedFile(Root, RelativePath)
  let Value: unknown
  try {
    Value = JSON.parse(Text) as unknown
  } catch (ErrorValue) {
    throw new Error(`${RelativePath} is not valid JSON: ${ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)}`)
  }
  ValidateJsonComplexity(Value, RelativePath)
  if (Text !== CanonicalJson(Value)) {
    throw new Error(`${RelativePath} must contain canonical JSON without duplicate keys or whitespace`)
  }
  return { value: Value, text: Text }
}

function ReadJson(Root: string, RelativePath: string): unknown {
  const Text = ReadBoundedFile(Root, RelativePath)
  let Value: unknown
  try {
    Value = JSON.parse(Text) as unknown
  } catch (ErrorValue) {
    throw new Error(`${RelativePath} is not valid JSON: ${ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)}`)
  }
  ValidateJsonComplexity(Value, RelativePath)
  return Value
}

function ReadDirectoryEntries(Root: string, RelativePath: string): Fs.Dirent[] {
  const Directory = ResolveExistingPath(Root, RelativePath)
  const Stat = Fs.lstatSync(Directory)
  if (!Stat.isDirectory()) throw new Error(`${RelativePath} must be a directory`)
  const Entries = Fs.readdirSync(Directory, { withFileTypes: true })
  if (Entries.length > MaximumFiles) throw new Error(`${RelativePath} exceeds file-entry limit ${MaximumFiles}`)
  return Entries.sort((Left, Right) => Left.name.localeCompare(Right.name))
}

function RelativeJoin(...Components: string[]): string {
  return Path.posix.join(...Components.map(Component => Component.replaceAll(Path.sep, '/')))
}

function DirectCanonicalReceiptFiles(Root: string, RelativePath: string): string[] {
  const Entries = ReadDirectoryEntries(Root, RelativePath)
  const Result: string[] = []
  for (const Entry of Entries) {
    if (!Entry.isFile() || Entry.isSymbolicLink() || !Entry.name.endsWith('.json')) {
      throw new Error(`${RelativePath} contains an unsafe or unexpected entry: ${Entry.name}`)
    }
    Result.push(RelativeJoin(RelativePath, Entry.name))
  }
  return Result
}

function ValidateEvidenceRoot(Root: string, RelativeRoot: string): { featureReceipts: string[], kubernetesReceipts: string[] } {
  const RootEntries = ReadDirectoryEntries(Root, RelativeRoot)
  AssertExactSet(`${RelativeRoot} entries`, RootEntries.map(Entry => Entry.name), ['receipts', 'reports', 'logs'])
  if (RootEntries.some(Entry => !Entry.isDirectory() || Entry.isSymbolicLink())) {
    throw new Error(`${RelativeRoot} entries must be non-symlink directories`)
  }
  const ReceiptRoot = RelativeJoin(RelativeRoot, 'receipts')
  const ReceiptEntries = ReadDirectoryEntries(Root, ReceiptRoot)
  AssertExactSet(`${ReceiptRoot} entries`, ReceiptEntries.map(Entry => Entry.name), ['features', 'kubernetes'])
  if (ReceiptEntries.some(Entry => !Entry.isDirectory() || Entry.isSymbolicLink())) {
    throw new Error(`${ReceiptRoot} entries must be non-symlink directories`)
  }
  return {
    featureReceipts: DirectCanonicalReceiptFiles(Root, RelativeJoin(ReceiptRoot, 'features')),
    kubernetesReceipts: DirectCanonicalReceiptFiles(Root, RelativeJoin(ReceiptRoot, 'kubernetes'))
  }
}

export function BuildFeatureGraduationExpectations(
  FeaturePolicy: FeatureGraduationPolicy,
  KubernetesPolicy: KubernetesGraduationPolicy
): GraduationExpectations {
  if (FeaturePolicy.repository !== KubernetesPolicy.repository || FeaturePolicy.targetVersion !== KubernetesPolicy.targetVersion) {
    throw new Error('feature graduation policies must bind one repository and target version')
  }
  const Features = [
    ...FeaturePolicy.features.filter(Feature => Feature.status === 'supported').map(Feature => ({
      scope: 'features' as const,
      featureId: Feature.id,
      qualifiedPlatforms: [...Feature.qualifiedPlatforms].sort(),
      gates: Feature.gateIds.map(Id => ({ id: Id, platforms: [...Feature.qualifiedPlatforms].sort() })).sort((Left, Right) => Left.id.localeCompare(Right.id))
    })),
    ...KubernetesPolicy.features.filter(Feature => Feature.status === 'supported').map(Feature => ({
      scope: 'kubernetes' as const,
      featureId: Feature.id,
      qualifiedPlatforms: [...Feature.qualifiedPlatforms].sort(),
      gates: Feature.gateIds.map(Id => ({ id: Id, platforms: [...Feature.qualifiedPlatforms].sort() })).sort((Left, Right) => Left.id.localeCompare(Right.id))
    }))
  ].sort((Left, Right) => `${Left.scope}/${Left.featureId}`.localeCompare(`${Right.scope}/${Right.featureId}`))
  return {
    schemaVersion: 1,
    predicateType: FeatureGraduationPredicateType,
    result: Features.length === 0 ? 'zero_supported' : 'supported',
    policies: [
      { scope: 'features', repository: FeaturePolicy.repository, targetVersion: FeaturePolicy.targetVersion, policyDefinitionSha256: FeatureGraduationPolicyDefinitionSha256(FeaturePolicy) },
      { scope: 'kubernetes', repository: KubernetesPolicy.repository, targetVersion: KubernetesPolicy.targetVersion, policyDefinitionSha256: KubernetesGraduationPolicyDefinitionSha256(KubernetesPolicy) }
    ],
    features: Features
  }
}

export function InspectFeatureGraduationPolicies(
  WorkspacePath: string,
  KubernetesValidationOptions: KubernetesGraduationPolicyValidationOptions = {}
): GraduationExpectations {
  const Root = ResolveWorkspace(WorkspacePath)
  return BuildFeatureGraduationExpectations(
    LoadFeatureGraduationPolicy(Root),
    LoadKubernetesGraduationPolicy(Root, KubernetesValidationOptions)
  )
}

export function WriteFeatureGraduationExpectations(
  WorkspacePath: string,
  OutputPath: string,
  KubernetesValidationOptions: KubernetesGraduationPolicyValidationOptions = {}
): void {
  const Root = ResolveWorkspace(WorkspacePath)
  WriteCanonicalOutput(
    Root,
    OutputPath,
    CanonicalJson(InspectFeatureGraduationPolicies(Root, KubernetesValidationOptions))
  )
}

function ParseRunMetadata(Value: unknown): RunMetadata {
  if (!IsObject(Value)) throw new Error('run metadata must be an object')
  AssertExactKeys(Value, ['schemaVersion', 'repository', 'workflowPath', 'workflowRef', 'runId', 'runAttempt', 'sourceRef', 'sourceRevision', 'status', 'conclusion'], 'run metadata')
  if (
    Value.schemaVersion !== 1 || Value.workflowPath !== FeatureWorkflowPath ||
    !((Value.status === 'in_progress' && Value.conclusion === null) || (Value.status === 'completed' && Value.conclusion === 'success'))
  ) {
    throw new Error('run metadata must preserve an exact in-progress/null or completed/success state')
  }
  return {
    schemaVersion: 1,
    repository: RequireString(Value.repository, 'run metadata repository'),
    workflowPath: FeatureWorkflowPath,
    workflowRef: RequireRevision(RequireString(Value.workflowRef, 'run metadata workflowRef'), 'run metadata workflowRef'),
    runId: RequireInteger(Value.runId, 'run metadata runId'),
    runAttempt: RequireInteger(Value.runAttempt, 'run metadata runAttempt'),
    sourceRef: RequireString(Value.sourceRef, 'run metadata sourceRef'),
    sourceRevision: RequireRevision(RequireString(Value.sourceRevision, 'run metadata sourceRevision'), 'run metadata sourceRevision'),
    status: Value.status as 'in_progress' | 'completed',
    conclusion: Value.conclusion as null | 'success'
  }
}

function ParseJobsMetadata(Value: unknown): JobsMetadata {
  if (!IsObject(Value)) throw new Error('jobs metadata must be an object')
  AssertExactKeys(Value, ['schemaVersion', 'repository', 'runId', 'runAttempt', 'jobs'], 'jobs metadata')
  if (Value.schemaVersion !== 1 || !Array.isArray(Value.jobs)) throw new Error('jobs metadata has invalid schemaVersion or jobs')
  if (Value.jobs.length === 0 || Value.jobs.length > MaximumFiles) throw new Error('jobs metadata must contain bounded producer jobs')
  const SeenIds = new Set<number>()
  const SeenNames = new Set<string>()
  const Jobs = Value.jobs.map((RawJob, Index) => {
    if (!IsObject(RawJob)) throw new Error(`jobs metadata job ${Index} must be an object`)
    AssertExactKeys(RawJob, ['id', 'name', 'conclusion'], `jobs metadata job ${Index}`)
    const Id = RequireInteger(RawJob.id, `jobs metadata job ${Index} id`)
    const Name = RequireString(RawJob.name, `jobs metadata job ${Index} name`)
    if (RawJob.conclusion !== 'success') throw new Error(`jobs metadata job ${Index} must conclude success`)
    if (SeenIds.has(Id) || SeenNames.has(Name)) throw new Error('jobs metadata repeats producer job id or name')
    SeenIds.add(Id); SeenNames.add(Name)
    return { id: Id, name: Name, conclusion: 'success' as const }
  })
  return {
    schemaVersion: 1,
    repository: RequireString(Value.repository, 'jobs metadata repository'),
    runId: RequireInteger(Value.runId, 'jobs metadata runId'),
    runAttempt: RequireInteger(Value.runAttempt, 'jobs metadata runAttempt'),
    jobs: Jobs
  }
}

function ValidateMetadata(Run: RunMetadata, Jobs: JobsMetadata, Repository: string, Revision: string, Ref: string, PhaseValue: Phase): void {
  ValidatePhaseRef(PhaseValue, Ref)
  if (Run.repository !== Repository || Jobs.repository !== Repository || Run.sourceRevision !== Revision || Run.workflowRef !== Revision || Run.sourceRef !== Ref) {
    throw new Error('authenticated run/jobs metadata does not bind the expected repository, ref, and revision')
  }
  if (Run.runId !== Jobs.runId || Run.runAttempt !== Jobs.runAttempt) {
    throw new Error('authenticated run/jobs metadata does not bind one exact attempt')
  }
}

function RequireInProgressRun(Run: RunMetadata): asserts Run is RunMetadata & { status: 'in_progress', conclusion: null } {
  if (Run.status !== 'in_progress' || Run.conclusion !== null) {
    throw new Error('seal requires authenticated current run metadata status in_progress with null conclusion')
  }
}

function ValidateReceiptMetadata(
  Receipts: Array<{ receipt: FeatureGraduationEvidenceReceipt | KubernetesGraduationEvidenceReceipt }>,
  Run: RunMetadata,
  Jobs: JobsMetadata
): Set<number> {
  const ReceiptJobsById = new Map<number, { id: number, name: string, conclusion: 'success' }>()
  const ReceiptJobsByName = new Map<string, { id: number, name: string, conclusion: 'success' }>()
  for (const { receipt: Receipt } of Receipts) {
    if (Receipt.workflow.runId !== Run.runId || Receipt.workflow.runAttempt !== Run.runAttempt || Receipt.workflow.path !== Run.workflowPath || Receipt.workflow.ref !== Run.workflowRef) {
      throw new Error(`receipt ${Receipt.featureId} does not bind the authenticated workflow attempt`)
    }
    for (const ReceiptJob of Receipt.workflow.jobs) {
      const ExistingId = ReceiptJobsById.get(ReceiptJob.id)
      const ExistingName = ReceiptJobsByName.get(ReceiptJob.name)
      if (
        (ExistingId !== undefined && (ExistingId.name !== ReceiptJob.name || ExistingId.conclusion !== ReceiptJob.conclusion)) ||
        (ExistingName !== undefined && (ExistingName.id !== ReceiptJob.id || ExistingName.conclusion !== ReceiptJob.conclusion))
      ) {
        throw new Error('receipts contain a conflicting producer job id/name mapping')
      }
      ReceiptJobsById.set(ReceiptJob.id, ReceiptJob)
      ReceiptJobsByName.set(ReceiptJob.name, ReceiptJob)
    }
  }
  const ReceiptJobKeys = new Set([...ReceiptJobsById.values()].map(Job => CanonicalJson([Job.id, Job.name, Job.conclusion])))
  const AuthenticatedJobKeys = new Set(Jobs.jobs.map(Job => CanonicalJson([Job.id, Job.name, Job.conclusion])))
  AssertExactSet('authenticated producer jobs', AuthenticatedJobKeys, ReceiptJobKeys)
  return new Set(ReceiptJobsById.keys())
}

function ValidateReportAndLogFiles(
  Root: string,
  EvidenceRoot: string,
  Receipts: Array<{ scope: Scope, path: string, text: string, receipt: FeatureGraduationEvidenceReceipt | KubernetesGraduationEvidenceReceipt }>,
  AuthenticatedJobIds: Set<number>
): SealedFeatureGraduation['predicate']['inventory'] {
  const ReportExpectations = new Map<string, string>()
  const LogExpectations = new Map<number, string>()
  for (const Item of Receipts) {
    for (const Report of Item.receipt.reportHashes) {
      if (
        Path.posix.isAbsolute(Report.name) || Report.name.split('/').some(Component =>
          Component === '' || Component === '.' || Component === '..'
        )
      ) {
        throw new Error(`receipt ${Item.receipt.featureId} contains an unsafe report artifact path`)
      }
      if (ReportExpectations.has(Report.name)) throw new Error(`receipts repeat report artifact ${Report.name}`)
      ReportExpectations.set(Report.name, Report.sha256)
    }
    for (const Log of Item.receipt.logHashes) {
      const Existing = LogExpectations.get(Log.jobId)
      if (Existing !== undefined && Existing !== Log.sha256) throw new Error(`receipts conflict on log hash for job ${Log.jobId}`)
      LogExpectations.set(Log.jobId, Log.sha256)
    }
  }
  const ReportsRoot = RelativeJoin(EvidenceRoot, 'reports')
  const ActualReports = EnumerateRelativeFiles(Root, ReportsRoot)
  AssertExactSet('report artifact paths', ActualReports, ReportExpectations.keys())
  const Reports = [...ReportExpectations].map(([Name, Expected]) => {
    const Actual = CanonicalDigest(ReadBoundedBuffer(Root, RelativeJoin(ReportsRoot, Name))).slice('sha256:'.length)
    if (Actual !== Expected) throw new Error(`report artifact hash mismatch: ${Name}`)
    return { name: Name, sha256: `sha256:${Actual}` }
  }).sort((Left, Right) => Left.name.localeCompare(Right.name))
  const LogsRoot = RelativeJoin(EvidenceRoot, 'logs')
  AssertExactSet(
    'receipt log job ids',
    [...LogExpectations.keys()].map(JobId => String(JobId)),
    [...AuthenticatedJobIds].map(JobId => String(JobId))
  )
  const ActualLogs = DirectLogFiles(Root, LogsRoot)
  AssertExactSet('log artifact paths', ActualLogs.keys(), [...LogExpectations.keys()].map(Id => `${Id}.log`))
  const Logs = [...LogExpectations].map(([JobId, Expected]) => {
    const Actual = CanonicalDigest(ReadBoundedBuffer(Root, RelativeJoin(LogsRoot, `${JobId}.log`))).slice('sha256:'.length)
    if (Actual !== Expected) throw new Error(`authenticated log hash mismatch for job ${JobId}`)
    return { jobId: JobId, sha256: `sha256:${Actual}` }
  }).sort((Left, Right) => Left.jobId - Right.jobId)
  return {
    receipts: Receipts.map(Item => ({
      scope: Item.scope,
      path: EvidenceRelativePath(EvidenceRoot, Item.path),
      sha256: CanonicalDigest(Item.text),
      featureId: Item.receipt.featureId
    })).sort((Left, Right) => Left.path.localeCompare(Right.path)),
    reports: Reports,
    logs: Logs
  }
}

function EvidenceRelativePath(EvidenceRoot: string, InputPath: string): string {
  const RelativePath = Path.posix.relative(EvidenceRoot, InputPath)
  if (
    RelativePath === '' || Path.posix.isAbsolute(RelativePath) ||
    RelativePath.split('/').some(Component => Component === '' || Component === '.' || Component === '..')
  ) {
    throw new Error(`receipt path is outside the bounded evidence directory: ${InputPath}`)
  }
  return RelativePath
}

function EnumerateRelativeFiles(Root: string, RelativeDirectory: string, Prefix = '', Depth = 0): string[] {
  if (Depth > 8) throw new Error(`${RelativeDirectory} exceeds report directory depth limit`)
  const Result: string[] = []
  for (const Entry of ReadDirectoryEntries(Root, RelativeJoin(RelativeDirectory, Prefix))) {
    const RelativeName = RelativeJoin(Prefix, Entry.name)
    if (Entry.isSymbolicLink()) throw new Error(`${RelativeDirectory} contains a symlink: ${RelativeName}`)
    if (Entry.isFile()) Result.push(RelativeName)
    else if (Entry.isDirectory()) Result.push(...EnumerateRelativeFiles(Root, RelativeDirectory, RelativeName, Depth + 1))
    else throw new Error(`${RelativeDirectory} contains a special file: ${RelativeName}`)
  }
  return Result.sort()
}

function DirectLogFiles(Root: string, RelativeDirectory: string): Map<string, string> {
  const Result = new Map<string, string>()
  for (const Entry of ReadDirectoryEntries(Root, RelativeDirectory)) {
    if (!Entry.isFile() || Entry.isSymbolicLink() || !/^[1-9][0-9]*\.log$/.test(Entry.name)) {
      throw new Error(`${RelativeDirectory} contains an unsafe or unexpected entry: ${Entry.name}`)
    }
    Result.set(Entry.name, RelativeJoin(RelativeDirectory, Entry.name))
  }
  return Result
}

export function SealFeatureGraduationEvidence(Options: {
  workspacePath: string
  evidenceDirectory: string
  runMetadataPath: string
  jobsMetadataPath: string
  sourceRevision: string
  sourceRef: string
  phase: Phase
}): SealedFeatureGraduation {
  const Root = ResolveWorkspace(Options.workspacePath)
  const Revision = RequireRevision(Options.sourceRevision, 'expected source revision')
  ValidatePhaseRef(Options.phase, Options.sourceRef)
  const FeaturePolicy = LoadFeatureGraduationPolicy(Root)
  const KubernetesPolicy = LoadKubernetesGraduationPolicy(Root)
  const Expectations = BuildFeatureGraduationExpectations(FeaturePolicy, KubernetesPolicy)
  if (Expectations.result !== 'supported') throw new Error('seal requires at least one supported feature row')
  const Run = ParseRunMetadata(ReadCanonicalJson(Root, Options.runMetadataPath).value)
  RequireInProgressRun(Run)
  const Jobs = ParseJobsMetadata(ReadCanonicalJson(Root, Options.jobsMetadataPath).value)
  ValidateMetadata(Run, Jobs, FeaturePolicy.repository, Revision, Options.sourceRef, Options.phase)
  const Layout = ValidateEvidenceRoot(Root, Options.evidenceDirectory)
  const FeatureSchema = ReadJson(Root, FeaturePolicy.evidenceSchema)
  const KubernetesSchema = ReadJson(Root, KubernetesPolicy.evidenceSchema)
  const FeatureReceipts = Layout.featureReceipts.map(PathValue => {
    const Input = ReadCanonicalJson(Root, PathValue)
    return { scope: 'features' as const, path: PathValue, text: Input.text, receipt: ValidateFeatureGraduationEvidenceObject(Input.value, FeatureSchema, FeaturePolicy, Revision, Options.sourceRef, Options.phase, PathValue) }
  })
  const KubernetesReceipts = Layout.kubernetesReceipts.map(PathValue => {
    const Input = ReadCanonicalJson(Root, PathValue)
    return { scope: 'kubernetes' as const, path: PathValue, text: Input.text, receipt: ValidateKubernetesGraduationEvidenceObject(Input.value, KubernetesSchema, KubernetesPolicy, Revision, Options.sourceRef, Options.phase, PathValue) }
  })
  if (FeaturePolicy.features.some(Feature => Feature.status === 'supported')) ValidateFeatureGraduationEvidenceSet(FeaturePolicy, FeatureReceipts.map(Item => Item.receipt))
  else if (FeatureReceipts.length !== 0) throw new Error('feature receipt directory is nonempty without supported feature rows')
  if (KubernetesPolicy.features.some(Feature => Feature.status === 'supported')) ValidateKubernetesGraduationEvidenceSet(KubernetesPolicy, KubernetesReceipts.map(Item => Item.receipt))
  else if (KubernetesReceipts.length !== 0) throw new Error('Kubernetes receipt directory is nonempty without supported feature rows')
  const Receipts = [...FeatureReceipts, ...KubernetesReceipts]
  const AuthenticatedJobIds = ValidateReceiptMetadata(Receipts, Run, Jobs)
  const Inventory = ValidateReportAndLogFiles(Root, Options.evidenceDirectory, Receipts, AuthenticatedJobIds)
  const Predicate: SealedFeatureGraduation['predicate'] = {
    schemaVersion: 1,
    predicateType: FeatureGraduationPredicateType,
    repository: FeaturePolicy.repository,
    sourceRef: Options.sourceRef,
    sourceRevision: Revision,
    phase: Options.phase,
    run: { id: Run.runId, attempt: Run.runAttempt, workflowPath: FeatureWorkflowPath, workflowRef: Run.workflowRef, status: 'in_progress', conclusion: null },
    expectations: Expectations,
    inventory: Inventory
  }
  const PredicateText = CanonicalJson(Predicate)
  const Subject: SealedFeatureGraduation['subject'] = {
    schemaVersion: 1,
    subjectName: FeatureGraduationSubjectName,
    repository: FeaturePolicy.repository,
    sourceRef: Options.sourceRef,
    sourceRevision: Revision,
    phase: Options.phase,
    predicateSha256: CanonicalDigest(PredicateText)
  }
  const SubjectText = CanonicalJson(Subject)
  return { subject: Subject, predicate: Predicate, subjectText: SubjectText, predicateText: PredicateText, subjectSha256: CanonicalDigest(SubjectText) }
}

function CertificateValue(Certificate: JsonObject, Names: string[]): string {
  for (const Name of Names) if (typeof Certificate[Name] === 'string' && Certificate[Name] !== '') return String(Certificate[Name])
  throw new Error('attestation certificate is missing a required identity field')
}

export function VerifyFeatureGraduationAttestationReadback(Options: {
  attestations: unknown
  subject: unknown
  predicate: unknown
  runMetadata: unknown
  verificationContext: 'in_run' | 'canonical_consumer'
  signerWorkflow: string
  sourceRepository: string
  sourceRef: string
  sourceRevision: string
}): void {
  if (!IsObject(Options.subject) || !IsObject(Options.predicate)) throw new Error('sealed subject and predicate must be objects')
  AssertExactKeys(Options.subject, ['schemaVersion', 'subjectName', 'repository', 'sourceRef', 'sourceRevision', 'phase', 'predicateSha256'], 'sealed subject')
  AssertExactKeys(Options.predicate, ['schemaVersion', 'predicateType', 'repository', 'sourceRef', 'sourceRevision', 'phase', 'run', 'expectations', 'inventory'], 'sealed predicate')
  const SubjectText = CanonicalJson(Options.subject)
  const PredicateText = CanonicalJson(Options.predicate)
  const SubjectName = RequireString(Options.subject.subjectName, 'sealed subjectName')
  const SubjectDigest = CanonicalDigest(SubjectText)
  const SourceRevision = RequireRevision(Options.sourceRevision, 'source revision')
  if (
    Options.subject.schemaVersion !== 1 || SubjectName !== FeatureGraduationSubjectName ||
    Options.subject.repository !== Options.sourceRepository || Options.subject.sourceRef !== Options.sourceRef ||
    Options.subject.sourceRevision !== SourceRevision || Options.subject.predicateSha256 !== CanonicalDigest(PredicateText) ||
    Options.predicate.schemaVersion !== 1 || Options.predicate.predicateType !== FeatureGraduationPredicateType ||
    Options.predicate.repository !== Options.sourceRepository || Options.predicate.sourceRef !== Options.sourceRef ||
    Options.predicate.sourceRevision !== SourceRevision || Options.predicate.phase !== Options.subject.phase
  ) {
    throw new Error('sealed subject and predicate do not bind one exact source and predicate digest')
  }
  ValidatePhaseRef(RequirePhase(RequireString(Options.subject.phase, 'sealed subject phase')), Options.sourceRef)
  const ExpectedSignerWorkflow = `${Options.sourceRepository}/${FeatureWorkflowPath}@${Options.sourceRef}`
  const ExpectedCertificateSigner = `https://github.com/${ExpectedSignerWorkflow}`
  if (Options.signerWorkflow !== ExpectedSignerWorkflow) throw new Error('signer workflow must be the exact feature graduation workflow at source revision')
  const CurrentRun = ParseRunMetadata(Options.runMetadata)
  if (
    CurrentRun.repository !== Options.sourceRepository || CurrentRun.sourceRef !== Options.sourceRef ||
    CurrentRun.sourceRevision !== SourceRevision || CurrentRun.workflowRef !== SourceRevision
  ) {
    throw new Error('current authenticated run metadata has unexpected source identity')
  }
  if (
    (Options.verificationContext === 'in_run' && (CurrentRun.status !== 'in_progress' || CurrentRun.conclusion !== null)) ||
    (Options.verificationContext === 'canonical_consumer' && (CurrentRun.status !== 'completed' || CurrentRun.conclusion !== 'success'))
  ) {
    throw new Error(`current authenticated run metadata does not satisfy ${Options.verificationContext} state`)
  }
  if (!Array.isArray(Options.attestations) || Options.attestations.length === 0 || Options.attestations.length > MaximumFiles) {
    throw new Error('gh attestation verify JSON must contain bounded results')
  }
  const ExactSubjects: unknown[] = []
  for (const RawResult of Options.attestations) {
    if (!IsObject(RawResult) || !IsObject(RawResult.verificationResult)) throw new Error('gh attestation verify contains malformed attestation result')
    const Verification = RawResult.verificationResult
    if (!IsObject(Verification.statement) || !Array.isArray(Verification.statement.subject)) throw new Error('gh attestation verify contains malformed attestation statement')
    const Subjects = Verification.statement.subject
    if (Subjects.length !== 1 || !IsObject(Subjects[0]) || !IsObject(Subjects[0].digest)) throw new Error('gh attestation verify contains malformed attestation subject')
    if (Subjects[0].name === SubjectName && Subjects[0].digest.sha256 === SubjectDigest.slice('sha256:'.length)) ExactSubjects.push(RawResult)
  }
  if (ExactSubjects.length === 0) throw new Error('gh attestation verify returned no exact feature-graduation subject')
  const Predicates = new Set<string>()
  for (const RawResult of ExactSubjects) {
    const Result = RawResult as JsonObject
    const Verification = Result.verificationResult as JsonObject
    if (!IsObject(Verification.signature) || !IsObject(Verification.signature.certificate)) throw new Error('exact subject has malformed attestation signature')
    const Certificate = Verification.signature.certificate
    if (CertificateValue(Certificate, ['subjectAlternativeName', 'SubjectAlternativeName']) !== ExpectedCertificateSigner) throw new Error('exact subject attestation has an unexpected signer workflow')
    const Repository = CertificateValue(Certificate, ['sourceRepository', 'SourceRepository', 'sourceRepositoryURI', 'SourceRepositoryURI'])
    if (Repository !== Options.sourceRepository && Repository !== `https://github.com/${Options.sourceRepository}`) throw new Error('exact subject attestation has an unexpected source repository')
    if (CertificateValue(Certificate, ['sourceRepositoryRef', 'SourceRepositoryRef']) !== Options.sourceRef || CertificateValue(Certificate, ['sourceRepositoryDigest', 'SourceRepositoryDigest']) !== SourceRevision || CertificateValue(Certificate, ['buildSignerDigest', 'BuildSignerDigest']) !== SourceRevision) {
      throw new Error('exact subject attestation has unexpected source ref or revision')
    }
    if (CertificateValue(Certificate, ['runnerEnvironment', 'RunnerEnvironment']) !== 'github-hosted' || !Array.isArray(Verification.verifiedTimestamps) || Verification.verifiedTimestamps.length === 0) throw new Error('exact subject attestation lacks verified GitHub-hosted identity')
    const Statement = Verification.statement as JsonObject
    if (Statement.predicateType !== FeatureGraduationPredicateType || CanonicalJson(Statement.predicate) !== PredicateText) throw new Error('exact subject attestation has a conflicting predicate')
    if (!IsObject(Statement.predicate) || Statement.predicate.repository !== Options.sourceRepository || Statement.predicate.sourceRef !== Options.sourceRef || Statement.predicate.sourceRevision !== SourceRevision || Statement.predicate.run === undefined || !IsObject(Statement.predicate.run) || Statement.predicate.run.workflowPath !== FeatureWorkflowPath) {
      throw new Error('exact subject attestation predicate has unexpected source or workflow path')
    }
    const PredicateRun = Statement.predicate.run
    if (PredicateRun.id !== CurrentRun.runId || PredicateRun.attempt !== CurrentRun.runAttempt || PredicateRun.workflowRef !== CurrentRun.workflowRef || PredicateRun.status !== 'in_progress' || PredicateRun.conclusion !== null) {
      throw new Error('exact subject attestation predicate does not bind the authenticated producer run')
    }
    Predicates.add(CanonicalJson(Statement.predicate))
  }
  if (Predicates.size !== 1) throw new Error('exact subject attestations contain conflicting predicates')
}

function ResolveOutputPath(Root: string, OutputPath: string): string {
  const Output = Path.isAbsolute(OutputPath) ? Path.resolve(OutputPath) : Path.resolve(Root, OutputPath)
  if (Path.basename(Output) === '' || Path.basename(Output) === '.') {
    throw new Error(`output path is invalid: ${OutputPath}`)
  }
  const Parent = Path.dirname(Output)
  const ParentStat = Fs.lstatSync(Parent)
  if (!ParentStat.isDirectory() || ParentStat.isSymbolicLink() || Fs.realpathSync(Parent) !== Parent) {
    throw new Error(`output parent must be a concrete directory: ${OutputPath}`)
  }
  if (Fs.existsSync(Output)) {
    const OutputStat = Fs.lstatSync(Output)
    if (!OutputStat.isFile() || OutputStat.isSymbolicLink()) throw new Error(`output must be a regular non-symlink file: ${OutputPath}`)
  }
  return Output
}

function WriteCanonicalOutput(Root: string, OutputPath: string, Text: string): void {
  const Output = ResolveOutputPath(Root, OutputPath)
  const Descriptor = Fs.openSync(Output, Fs.constants.O_WRONLY | Fs.constants.O_CREAT | Fs.constants.O_TRUNC | Fs.constants.O_NOFOLLOW, 0o600)
  try {
    if (!Fs.fstatSync(Descriptor).isFile()) throw new Error(`output must be a regular file: ${OutputPath}`)
    Fs.writeFileSync(Descriptor, Text, 'utf8')
  } finally {
    Fs.closeSync(Descriptor)
  }
}

function AssertOutputsOutsideEvidence(Root: string, EvidenceDirectory: string, Outputs: string[]): void {
  const EvidenceRoot = Path.resolve(Root, EvidenceDirectory)
  for (const Output of Outputs) {
    if (IsPathWithin(EvidenceRoot, Path.resolve(Root, Output))) {
      throw new Error(`sealed output must be outside the evidence directory: ${Output}`)
    }
  }
}

function ParseCli(Argv: string[]): ParsedCli {
  const Mode = Argv[2]
  if (Mode !== 'expectations' && Mode !== 'seal' && Mode !== 'attestation-verify') throw new Error('usage: feature_graduation_attestation.ts <expectations|seal|attestation-verify> [options]')
  const Values = new Map<string, string[]>()
  for (let Index = 3; Index < Argv.length; Index += 2) {
    const Option = Argv[Index]; const Value = Argv[Index + 1]
    if (!Option.startsWith('--') || Value === undefined || Value.startsWith('--')) throw new Error(`invalid or missing value for ${Option}`)
    Values.set(Option, [...(Values.get(Option) ?? []), Value])
  }
  return { mode: Mode, values: Values }
}

function CliValue(Parsed: ParsedCli, Name: string): string {
  const Values = Parsed.values.get(Name)
  if (Values === undefined || Values.length !== 1) throw new Error(`${Name} must be supplied exactly once`)
  return Values[0]
}

function AssertKnownOptions(Parsed: ParsedCli, Names: string[]): void {
  for (const Name of Parsed.values.keys()) if (!Names.includes(Name)) throw new Error(`unknown option: ${Name}`)
}

function RunCli(): void {
  const Parsed = ParseCli(Process.argv)
  const Root = ResolveWorkspace(CliValue(Parsed, '--workspace-path'))
  if (Parsed.mode === 'expectations') {
    AssertKnownOptions(Parsed, [
      '--workspace-path',
      '--output',
      '--allow-previous-helm-compatibility'
    ])
    const AllowPreviousHelmCompatibilityValue =
      Parsed.values.get('--allow-previous-helm-compatibility')
    if (
      AllowPreviousHelmCompatibilityValue !== undefined &&
      (
        AllowPreviousHelmCompatibilityValue.length !== 1 ||
        AllowPreviousHelmCompatibilityValue[0] !== 'true'
      )
    ) {
      throw new Error('--allow-previous-helm-compatibility must be exactly true when supplied')
    }
    WriteFeatureGraduationExpectations(
      Root,
      CliValue(Parsed, '--output'),
      { AllowPreviousHelmCompatibility: AllowPreviousHelmCompatibilityValue !== undefined }
    )
    return
  }
  if (Parsed.mode === 'seal') {
    AssertKnownOptions(Parsed, ['--workspace-path', '--evidence-dir', '--run-metadata', '--jobs-metadata', '--expected-source-revision', '--expected-source-ref', '--phase', '--subject-output', '--predicate-output'])
    const EvidenceDirectory = CliValue(Parsed, '--evidence-dir')
    const PredicateOutput = CliValue(Parsed, '--predicate-output')
    const SubjectOutput = CliValue(Parsed, '--subject-output')
    AssertOutputsOutsideEvidence(Root, EvidenceDirectory, [PredicateOutput, SubjectOutput])
    const Sealed = SealFeatureGraduationEvidence({ workspacePath: Root, evidenceDirectory: EvidenceDirectory, runMetadataPath: CliValue(Parsed, '--run-metadata'), jobsMetadataPath: CliValue(Parsed, '--jobs-metadata'), sourceRevision: CliValue(Parsed, '--expected-source-revision'), sourceRef: CliValue(Parsed, '--expected-source-ref'), phase: RequirePhase(CliValue(Parsed, '--phase')) })
    WriteCanonicalOutput(Root, PredicateOutput, Sealed.predicateText)
    WriteCanonicalOutput(Root, SubjectOutput, Sealed.subjectText)
    return
  }
  AssertKnownOptions(Parsed, ['--workspace-path', '--attestations', '--subject', '--predicate', '--run-metadata', '--verification-context', '--signer-workflow', '--source-repository', '--source-ref', '--source-revision'])
  const Context = CliValue(Parsed, '--verification-context')
  if (Context !== 'in_run' && Context !== 'canonical_consumer') throw new Error('--verification-context must be in_run or canonical_consumer')
  VerifyFeatureGraduationAttestationReadback({
    attestations: ReadJson(Root, CliValue(Parsed, '--attestations')),
    subject: ReadCanonicalJson(Root, CliValue(Parsed, '--subject')).value,
    predicate: ReadCanonicalJson(Root, CliValue(Parsed, '--predicate')).value,
    runMetadata: ReadCanonicalJson(Root, CliValue(Parsed, '--run-metadata')).value,
    verificationContext: Context as 'in_run' | 'canonical_consumer',
    signerWorkflow: CliValue(Parsed, '--signer-workflow'), sourceRepository: CliValue(Parsed, '--source-repository'), sourceRef: CliValue(Parsed, '--source-ref'), sourceRevision: CliValue(Parsed, '--source-revision')
  })
}

if (Process.argv[1] !== undefined && import.meta.url === pathToFileURL(Path.resolve(Process.argv[1])).href) {
  try { RunCli() } catch (ErrorValue) {
    console.error(`feature graduation attestation error: ${ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)}`)
    process.exitCode = 1
  }
}
