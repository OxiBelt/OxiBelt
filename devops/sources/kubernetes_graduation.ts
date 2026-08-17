import * as Crypto from 'node:crypto'
import * as Fs from 'node:fs'
import * as Path from 'node:path'
import * as Process from 'node:process'
import { execFileSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

const PolicyPath = 'devops/config/kubernetes-feature-graduation.json'
const SchemaPath = 'devops/config/kubernetes-feature-graduation.schema.json'
const SupportDocumentPath = 'docs/KubernetesSupport.md'
const FeatureStatusPath = 'docs/FeatureStatus.md'
const MaximumInputBytes = 1024 * 1024
const MaximumEvidenceFiles = 64
const MaximumJsonDepth = 64
const MaximumJsonNodes = 10000
const MaximumJsonStringBytes = 64 * 1024
const MaximumJsonArrayItems = 1024
const MaximumJsonObjectKeys = 256
const GeneratedStart = '<!-- BEGIN KUBERNETES GRADUATION GENERATED -->'
const GeneratedEnd = '<!-- END KUBERNETES GRADUATION GENERATED -->'
const FullRevision = /^[0-9a-f]{40}$/

export const KubernetesGraduationFeatureIds = [
  'gateway-controller',
  'gateway-api-httproute',
  'gateway-api-grpcroute',
  'gateway-api-tlsroute',
  'gateway-api-tcproute',
  'gateway-api-udproute',
  'gateway-api-backendtlspolicy',
  'gateway-api-weighted-discovery',
  'gateway-api-standard-filters-backend-tls',
  'gateway-api-route-policy',
  'gateway-controller-multi-target',
  'gateway-controller-explain',
  'supply-chain-admission-bundle',
  'helm-data-plane',
  'helm-gateway-controller'
] as const

export const KubernetesGraduationPhases = ['candidate', 'official_beta'] as const

const RequiredCadences = [
  'pull_request',
  'nightly',
  'release_candidate',
  'stable'
] as const

const SupplyChainArtifactRequirements = [
  'image-standalone|oci-image|ghcr.io/oxibelt/oxibelt',
  'image-dataplane|oci-image|ghcr.io/oxibelt/oxibelt-dataplane',
  'image-dataplane-strict|oci-image|ghcr.io/oxibelt/oxibelt-dataplane-strict',
  'image-controller|oci-image|ghcr.io/oxibelt/oxibelt-gateway-controller',
  'image-tools|oci-image|ghcr.io/oxibelt/oxibelt-tools',
  'image-keysigner|oci-image|ghcr.io/oxibelt/oxibelt-keysigner',
  'chart-oxibelt|helm-chart|ghcr.io/oxibelt/charts/oxibelt',
  'chart-gateway-controller|helm-chart|ghcr.io/oxibelt/charts/oxibelt-gateway-controller'
] as const

/* oxlint-disable oxibelt/pascal-case -- Parsed policy and JSON Schema keys are stable lower-camel-case wire names. */
type JsonObject = Record<string, unknown>

type JsonSchema = {
  type?: 'object' | 'array' | 'string' | 'integer' | 'boolean'
  const?: unknown
  enum?: unknown[]
  required?: string[]
  additionalProperties?: boolean
  properties?: Record<string, JsonSchema>
  items?: JsonSchema
  minItems?: number
  uniqueItems?: boolean
  pattern?: string
  minLength?: number
  minimum?: number
  maximum?: number
}

export type KubernetesGraduationPolicy = {
  $schema: string
  schemaVersion: 2
  policyVersion: number
  lifecycleAuthority: string
  evidenceSchema: string
  repository: 'OxiBelt/OxiBelt'
  targetVersion: '0.8.0'
  supportContract: {
    kubernetes: {
      range: string
      minors: Array<{
        minor: string
        ciVersion: string
        kindNodeImage: string
      }>
    }
    helm: {
      versions: string[]
      upgradeCompatibility: string
    }
    gatewayApi: {
      version: string
      channel: string
      servedVersion: string
      standardInstallUrl: string
      standardInstallSha256: string
    }
    crdLifecycle: {
      owner: string
      chartInstalls: boolean
      chartConverts: boolean
      chartDeletes: boolean
      supportedUpgradeOrder: string[]
    }
    controllerDataPlaneSkew: {
      defaultMode: string
      rollingMode: string
      maximumRollingHours: number
      upgradeOrder: string[]
      rollbackOrder: string[]
    }
    architectures: Array<{
      name: string
      nativeClusterRequired: boolean
      qualification: 'pending' | 'blocked'
    }>
    networking: {
      ipFamilies: string[]
      networkPolicyCnis: string[]
    }
    podSecurity: {
      standard: string
      mode: string
      version: string
    }
  }
  cadences: Array<{
    id: string
    purpose: string
  }>
  blockers: Array<{
    id: string
    reason: string
  }>
  gates: Array<{
    id: string
    objective: string
    cadence: 'pull_request' | 'nightly' | 'release_candidate'
    mandatory: true
    appliesTo: string[]
  }>
  features: Array<{
    id: (typeof KubernetesGraduationFeatureIds)[number]
    status: 'experimental' | 'supported'
    lastValidatedVersion: string
    qualifiedPlatforms: Array<'linux/amd64' | 'linux/arm64' | 'linux/riscv64'>
    requiredArtifacts: Array<{
      name: string
      kind: 'oci-image' | 'helm-chart'
      repository: string
    }>
    gateIds: string[]
    blockerIds: string[]
  }>
}

export type KubernetesGraduationEvidenceReceipt = {
  schemaVersion: 2
  policyVersion: number
  policyDefinitionSha256: string
  featureId: (typeof KubernetesGraduationFeatureIds)[number]
  intendedStatus: 'supported'
  phase: (typeof KubernetesGraduationPhases)[number]
  targetVersion: string
  repository: string
  sourceRef: string
  sourceRevision: string
  generatedAt: string
  qualifiedPlatforms: Array<'linux/amd64' | 'linux/arm64' | 'linux/riscv64'>
  workflow: {
    repository: string
    path: '.github/workflows/feature-graduation.yml'
    ref: string
    runId: number
    runAttempt: number
    jobs: Array<{
      id: number
      name: string
      conclusion: 'success'
    }>
  }
  toolVersions: Array<{
    name: string
    version: string
  }>
  artifactSubjects: Array<{
    name: string
    kind: 'oci-image' | 'helm-chart'
    reference: string
    digest: string
  }>
  reportHashes: Array<{
    name: string
    sha256: string
  }>
  logHashes: Array<{
    jobId: number
    sha256: string
  }>
  gateResults: Array<{
    id: string
    platformResults: Array<{
      platform: 'linux/amd64' | 'linux/arm64' | 'linux/riscv64'
      jobId: number
      reportName: string
      reportSha256: string
      result: 'pass'
    }>
  }>
  result: 'pass'
}

type CliParameters = {
  workspacePath?: string
  expectedSourceRevision?: string
  expectedSourceRef?: string
  phase?: (typeof KubernetesGraduationPhases)[number]
  evidenceDirectory?: string
}

type IdRecord = {
  id: string
}

type NamedRecord = {
  name: string
}

type ParsedCli = {
  command: 'check' | 'render' | 'verify'
  parameters: CliParameters
}
/* oxlint-enable oxibelt/pascal-case */

function IsObject(Value: unknown): Value is JsonObject {
  return typeof Value === 'object' && Value !== null && !Array.isArray(Value)
}

function IsPathWithin(Parent: string, Candidate: string): boolean {
  const Relative = Path.relative(Parent, Candidate)
  return Relative === '' ||
    (!Relative.startsWith(`..${Path.sep}`) && Relative !== '..' && !Path.isAbsolute(Relative))
}

function ResolveWorkspace(WorkspacePath: string): string {
  const Root = Fs.realpathSync(WorkspacePath)
  if (!Fs.statSync(Root).isDirectory()) {
    throw new Error(`workspace path is not a directory: ${WorkspacePath}`)
  }
  return Root
}

function ValidateSourceRevision(Value: string, Label: string): string {
  if (!FullRevision.test(Value)) {
    throw new Error(`${Label} must be a full lowercase Git commit`)
  }
  return Value
}

function ValidateSourceRef(Value: string, Label: string): string {
  if (!/^refs\/(heads|tags)\/[A-Za-z0-9._/-]+$/.test(Value)) {
    throw new Error(`${Label} must be an exact Git branch or tag ref`)
  }
  return Value
}

function ResolveWorkspaceRevision(Root: string): string {
  let Revision: string
  try {
    Revision = execFileSync(
      'git',
      ['-C', Root, 'rev-parse', '--verify', 'HEAD^{commit}'],
      {
        encoding: 'utf8',
        maxBuffer: 1024,
        stdio: ['ignore', 'pipe', 'pipe']
      }
    ).trim()
  } catch {
    throw new Error('could not resolve the checked-out Git source revision')
  }
  return ValidateSourceRevision(Revision, 'checked-out Git source revision')
}

function ResolveRepositoryPath(Root: string, RelativePath: string): string {
  if (Path.isAbsolute(RelativePath)) {
    throw new Error(`repository input must be a relative path: ${RelativePath}`)
  }
  const Candidate = Path.resolve(Root, RelativePath)
  if (!IsPathWithin(Root, Candidate)) {
    throw new Error(`repository input escapes the workspace: ${RelativePath}`)
  }
  const Relative = Path.relative(Root, Candidate)
  let Current = Root
  for (const Component of Relative.split(Path.sep)) {
    if (Component === '') {
      continue
    }
    Current = Path.join(Current, Component)
    const Stat = Fs.lstatSync(Current)
    if (Stat.isSymbolicLink()) {
      throw new Error(`repository input must not traverse a symlink: ${RelativePath}`)
    }
  }
  const RealCandidate = Fs.realpathSync(Candidate)
  if (!IsPathWithin(Root, RealCandidate) || RealCandidate !== Candidate) {
    throw new Error(`repository input resolves outside its checked path: ${RelativePath}`)
  }
  return Candidate
}

function ReadBoundedFile(Root: string, RelativePath: string): string {
  const Candidate = ResolveRepositoryPath(Root, RelativePath)
  const Descriptor = Fs.openSync(Candidate, Fs.constants.O_RDONLY | Fs.constants.O_NOFOLLOW)
  try {
    const Stat = Fs.fstatSync(Descriptor)
    if (!Stat.isFile()) {
      throw new Error(`repository input must be a regular file: ${RelativePath}`)
    }
    if (Stat.size > MaximumInputBytes) {
      throw new Error(`repository input exceeds ${MaximumInputBytes} bytes: ${RelativePath}`)
    }
    const Content = Fs.readFileSync(Descriptor, 'utf8')
    if (Content.includes('\0')) {
      throw new Error(`repository input contains a NUL byte: ${RelativePath}`)
    }
    return Content
  } finally {
    Fs.closeSync(Descriptor)
  }
}

function ParseJson(Content: string, Label: string): unknown {
  try {
    return JSON.parse(Content) as unknown
  } catch (ErrorValue) {
    const Message = ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)
    throw new Error(`${Label} is not valid JSON: ${Message}`)
  }
}

function StableValue(Value: unknown): string {
  if (Array.isArray(Value)) {
    return `[${Value.map(Item => StableValue(Item)).join(',')}]`
  }
  if (IsObject(Value)) {
    return `{${Object.keys(Value).sort().map(Key =>
      `${JSON.stringify(Key)}:${StableValue(Value[Key])}`
    ).join(',')}}`
  }
  return JSON.stringify(Value)
}

function ValidateJsonComplexity(
  Value: unknown,
  Location: string,
  Depth = 0,
  State = { nodes: 0 }
): void {
  if (Depth > MaximumJsonDepth) {
    throw new Error(`${Location} exceeds JSON nesting limit ${MaximumJsonDepth}`)
  }
  State.nodes += 1
  if (State.nodes > MaximumJsonNodes) {
    throw new Error(`${Location} exceeds JSON node limit ${MaximumJsonNodes}`)
  }
  if (typeof Value === 'string') {
    if (Buffer.byteLength(Value, 'utf8') > MaximumJsonStringBytes) {
      throw new Error(`${Location} exceeds JSON string limit ${MaximumJsonStringBytes}`)
    }
    return
  }
  if (Array.isArray(Value)) {
    if (Value.length > MaximumJsonArrayItems) {
      throw new Error(`${Location} exceeds JSON array-item limit ${MaximumJsonArrayItems}`)
    }
    Value.forEach((Item, Index) =>
      ValidateJsonComplexity(Item, `${Location}[${Index}]`, Depth + 1, State)
    )
    return
  }
  if (IsObject(Value)) {
    const Keys = Object.keys(Value)
    if (Keys.length > MaximumJsonObjectKeys) {
      throw new Error(`${Location} exceeds JSON object-key limit ${MaximumJsonObjectKeys}`)
    }
    for (const Key of Keys) {
      if (Buffer.byteLength(Key, 'utf8') > MaximumJsonStringBytes) {
        throw new Error(`${Location} contains an oversized JSON key`)
      }
      ValidateJsonComplexity(Value[Key], `${Location}.${Key}`, Depth + 1, State)
    }
  }
}

function ValuesEqual(Left: unknown, Right: unknown): boolean {
  return StableValue(Left) === StableValue(Right)
}

function ValidateSchemaValue(Value: unknown, Schema: JsonSchema, Location: string): void {
  if (Schema.const !== undefined && !ValuesEqual(Value, Schema.const)) {
    throw new Error(`${Location} must equal ${JSON.stringify(Schema.const)}`)
  }
  if (Schema.enum !== undefined && !Schema.enum.some(Candidate => ValuesEqual(Value, Candidate))) {
    throw new Error(`${Location} must be one of ${Schema.enum.map(Item => JSON.stringify(Item)).join(', ')}`)
  }

  if (Schema.type === 'object') {
    if (!IsObject(Value)) {
      throw new Error(`${Location} must be an object`)
    }
    const Properties = Schema.properties ?? {}
    for (const RequiredKey of Schema.required ?? []) {
      if (!Object.hasOwn(Value, RequiredKey)) {
        throw new Error(`${Location} is missing required property ${RequiredKey}`)
      }
    }
    if (Schema.additionalProperties === false) {
      for (const Key of Object.keys(Value)) {
        if (!Object.hasOwn(Properties, Key)) {
          throw new Error(`${Location} contains unknown property ${Key}`)
        }
      }
    }
    for (const [Key, ChildSchema] of Object.entries(Properties)) {
      if (Object.hasOwn(Value, Key)) {
        ValidateSchemaValue(Value[Key], ChildSchema, `${Location}.${Key}`)
      }
    }
    return
  }

  if (Schema.type === 'array') {
    if (!Array.isArray(Value)) {
      throw new Error(`${Location} must be an array`)
    }
    if (Schema.minItems !== undefined && Value.length < Schema.minItems) {
      throw new Error(`${Location} must contain at least ${Schema.minItems} items`)
    }
    if (Schema.uniqueItems === true) {
      const Seen = new Set<string>()
      for (const Item of Value) {
        const Canonical = StableValue(Item)
        if (Seen.has(Canonical)) {
          throw new Error(`${Location} must not contain duplicate items`)
        }
        Seen.add(Canonical)
      }
    }
    if (Schema.items !== undefined) {
      Value.forEach((Item, Index) =>
        ValidateSchemaValue(Item, Schema.items as JsonSchema, `${Location}[${Index}]`)
      )
    }
    return
  }

  if (Schema.type === 'string') {
    if (typeof Value !== 'string') {
      throw new Error(`${Location} must be a string`)
    }
    if (Schema.minLength !== undefined && Value.length < Schema.minLength) {
      throw new Error(`${Location} must contain at least ${Schema.minLength} characters`)
    }
    if (Schema.pattern !== undefined && !new RegExp(Schema.pattern).test(Value)) {
      throw new Error(`${Location} does not match required pattern ${Schema.pattern}`)
    }
    return
  }

  if (Schema.type === 'integer') {
    if (!Number.isSafeInteger(Value)) {
      throw new Error(`${Location} must be a safe integer`)
    }
    if (Schema.minimum !== undefined && (Value as number) < Schema.minimum) {
      throw new Error(`${Location} must be at least ${Schema.minimum}`)
    }
    if (Schema.maximum !== undefined && (Value as number) > Schema.maximum) {
      throw new Error(`${Location} must be at most ${Schema.maximum}`)
    }
    return
  }

  if (Schema.type === 'boolean' && typeof Value !== 'boolean') {
    throw new Error(`${Location} must be a boolean`)
  }
}

function AssertExactSet(Label: string, Actual: Iterable<string>, Expected: readonly string[]): void {
  const ActualValues = [...Actual].sort()
  const ExpectedValues = [...Expected].sort()
  if (!ValuesEqual(ActualValues, ExpectedValues)) {
    throw new Error(
      `${Label} must be exactly [${ExpectedValues.join(', ')}], found [${ActualValues.join(', ')}]`
    )
  }
}

function AssertUniqueIds(Label: string, Values: IdRecord[]): Set<string> {
  const Ids = new Set<string>()
  for (const Value of Values) {
    if (Ids.has(Value.id)) {
      throw new Error(`${Label} repeats id ${Value.id}`)
    }
    Ids.add(Value.id)
  }
  return Ids
}

export function KubernetesGraduationPolicyDefinitionSha256(
  Policy: KubernetesGraduationPolicy
): string {
  return Crypto.createHash('sha256').update(StableValue(Policy), 'utf8').digest('hex')
}

function IsExactUtcSecond(Value: string): boolean {
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(Value)) {
    return false
  }
  const Parsed = new Date(Value)
  return !Number.isNaN(Parsed.valueOf()) &&
    Parsed.toISOString() === `${Value.slice(0, -1)}.000Z`
}

function ReadCanonicalReceipt(Root: string, RelativePath: string): unknown {
  const Content = ReadBoundedFile(Root, RelativePath)
  const Value = ParseJson(Content, RelativePath)
  ValidateJsonComplexity(Value, RelativePath)
  if (Content !== StableValue(Value)) {
    throw new Error(`${RelativePath} must contain canonical JSON without duplicate keys or whitespace`)
  }
  return Value
}

function ValidateNamedUnique(Label: string, Values: NamedRecord[]): void {
  const Seen = new Set<string>()
  for (const Value of Values) {
    if (Seen.has(Value.name)) {
      throw new Error(`${Label} repeats name ${Value.name}`)
    }
    Seen.add(Value.name)
  }
}

export function ValidateKubernetesGraduationEvidenceObject(
  Value: unknown,
  SchemaValue: unknown,
  Policy: KubernetesGraduationPolicy,
  ExpectedSourceRevision: string,
  ExpectedSourceRef: string,
  ExpectedPhase: (typeof KubernetesGraduationPhases)[number],
  Label = 'Kubernetes graduation evidence'
): KubernetesGraduationEvidenceReceipt {
  if (!IsObject(SchemaValue)) {
    throw new Error('Kubernetes graduation evidence schema must be an object')
  }
  ValidateSchemaValue(Value, SchemaValue as JsonSchema, Label)
  const Receipt = Value as KubernetesGraduationEvidenceReceipt
  const ExpectedRevision = ValidateSourceRevision(
    ExpectedSourceRevision,
    'expected source revision'
  )
  const ExpectedRef = ValidateSourceRef(ExpectedSourceRef, 'expected source ref')
  ValidateKubernetesGraduationPhaseRef(ExpectedPhase, ExpectedRef)
  if (Receipt.sourceRevision !== ExpectedRevision || Receipt.workflow.ref !== ExpectedRevision) {
    throw new Error(`${Label} does not bind the expected source revision`)
  }
  if (Receipt.sourceRef !== ExpectedRef) {
    throw new Error(`${Label} does not bind the expected source ref`)
  }
  if (Receipt.phase !== ExpectedPhase) {
    throw new Error(`${Label} does not bind the expected qualification phase`)
  }
  if (Receipt.targetVersion !== Policy.targetVersion) {
    throw new Error(`${Label} does not bind target version ${Policy.targetVersion}`)
  }
  if (Receipt.repository !== Policy.repository || Receipt.workflow.repository !== Policy.repository) {
    throw new Error(`${Label} does not bind the policy repository`)
  }
  if (
    Receipt.policyVersion !== Policy.policyVersion ||
    Receipt.policyDefinitionSha256 !== KubernetesGraduationPolicyDefinitionSha256(Policy)
  ) {
    throw new Error(`${Label} does not bind the current Kubernetes graduation policy`)
  }
  if (!IsExactUtcSecond(Receipt.generatedAt)) {
    throw new Error(`${Label}.generatedAt must be a real RFC3339 UTC timestamp`)
  }
  const Feature = Policy.features.find(Candidate => Candidate.id === Receipt.featureId)
  if (Feature === undefined) {
    throw new Error(`${Label} references unknown feature ${Receipt.featureId}`)
  }
  if (Feature.status !== 'supported' || Feature.lastValidatedVersion !== Policy.targetVersion) {
    throw new Error(`${Label} may only promote a supported feature at target version ${Policy.targetVersion}`)
  }
  AssertExactSet(`${Label} qualified platforms`, Receipt.qualifiedPlatforms, Feature.qualifiedPlatforms)

  const JobIds = new Set<number>()
  const JobNames = new Set<string>()
  for (const Job of Receipt.workflow.jobs) {
    if (JobIds.has(Job.id) || JobNames.has(Job.name)) {
      throw new Error(`${Label} repeats workflow job id or name`)
    }
    JobIds.add(Job.id)
    JobNames.add(Job.name)
  }
  ValidateNamedUnique(`${Label} tool versions`, Receipt.toolVersions)
  ValidateNamedUnique(`${Label} artifact subjects`, Receipt.artifactSubjects)
  const ArtifactReferences = new Set<string>()
  for (const Subject of Receipt.artifactSubjects) {
    if (ArtifactReferences.has(Subject.reference)) {
      throw new Error(`${Label} repeats artifact reference ${Subject.reference}`)
    }
    ArtifactReferences.add(Subject.reference)
    if (!Subject.reference.endsWith(`@${Subject.digest}`)) {
      throw new Error(`${Label} artifact ${Subject.name} must bind an immutable digest reference`)
    }
  }
  AssertExactSet(
    `${Label} artifact subject names`,
    Receipt.artifactSubjects.map(Subject => Subject.name),
    Feature.requiredArtifacts.map(Requirement => Requirement.name)
  )
  for (const Requirement of Feature.requiredArtifacts) {
    const Subject = Receipt.artifactSubjects.find(Candidate => Candidate.name === Requirement.name)
    if (
      Subject === undefined ||
      Subject.kind !== Requirement.kind ||
      Subject.reference !== `${Requirement.repository}@${Subject.digest}`
    ) {
      throw new Error(
        `${Label} artifact ${Requirement.name} must bind exact ${Requirement.kind} repository ${Requirement.repository}`
      )
    }
  }
  ValidateNamedUnique(`${Label} report hashes`, Receipt.reportHashes)
  const LogJobIds = new Set<number>()
  for (const Log of Receipt.logHashes) {
    if (LogJobIds.has(Log.jobId)) {
      throw new Error(`${Label} repeats log hash for job ${Log.jobId}`)
    }
    LogJobIds.add(Log.jobId)
  }
  if (!ValuesEqual(
    [...JobIds].sort((Left, Right) => Left - Right),
    [...LogJobIds].sort((Left, Right) => Left - Right)
  )) {
    throw new Error(`${Label} must bind one log hash for every exact workflow job`)
  }
  const ResultIds = new Set<string>()
  for (const Result of Receipt.gateResults) {
    if (ResultIds.has(Result.id)) {
      throw new Error(`${Label} repeats gate result ${Result.id}`)
    }
    ResultIds.add(Result.id)
    AssertExactSet(
      `${Label} gate result ${Result.id} platforms`,
      Result.platformResults.map(PlatformResult => PlatformResult.platform),
      Feature.qualifiedPlatforms
    )
    const ProducingJobIds = new Set<number>()
    const PlatformReportNames = new Set<string>()
    const PlatformReportHashes = new Set<string>()
    for (const PlatformResult of Result.platformResults) {
      if (ProducingJobIds.has(PlatformResult.jobId)) {
        throw new Error(`${Label} gate result ${Result.id} must use a distinct job for every platform`)
      }
      ProducingJobIds.add(PlatformResult.jobId)
      if (
        PlatformReportNames.has(PlatformResult.reportName) ||
        PlatformReportHashes.has(PlatformResult.reportSha256)
      ) {
        throw new Error(`${Label} gate result ${Result.id} must use a distinct report for every platform`)
      }
      PlatformReportNames.add(PlatformResult.reportName)
      PlatformReportHashes.add(PlatformResult.reportSha256)
      if (!JobIds.has(PlatformResult.jobId)) {
        throw new Error(`${Label} gate result ${Result.id} references an unknown producing job`)
      }
      if (!Receipt.reportHashes.some(Report =>
        Report.name === PlatformResult.reportName && Report.sha256 === PlatformResult.reportSha256
      )) {
        throw new Error(`${Label} gate result ${Result.id} does not bind its exact report hash`)
      }
    }
  }
  AssertExactSet(`${Label} gate results`, ResultIds, Feature.gateIds)
  return Receipt
}

export function LoadKubernetesGraduationEvidenceDirectory(
  WorkspacePath: string,
  RelativeDirectoryPath: string
): string[] {
  const Root = ResolveWorkspace(WorkspacePath)
  const Directory = ResolveRepositoryPath(Root, RelativeDirectoryPath)
  const Stat = Fs.lstatSync(Directory)
  if (!Stat.isDirectory() || Stat.isSymbolicLink()) {
    throw new Error(`evidence directory must be a non-symlink directory: ${RelativeDirectoryPath}`)
  }
  const Entries = Fs.readdirSync(Directory, { withFileTypes: true })
  if (Entries.length === 0 || Entries.length > MaximumEvidenceFiles) {
    throw new Error(`evidence directory must contain between 1 and ${MaximumEvidenceFiles} receipt files`)
  }
  const RelativePaths: string[] = []
  for (const Entry of Entries) {
    if (!Entry.isFile() || Entry.isSymbolicLink() || !Entry.name.endsWith('.json')) {
      throw new Error(`evidence directory contains an unsafe or unsupported entry: ${Entry.name}`)
    }
    RelativePaths.push(Path.posix.join(
      RelativeDirectoryPath.replaceAll(Path.sep, '/'),
      Entry.name
    ))
  }
  return RelativePaths.sort()
}

export function ValidateKubernetesGraduationEvidenceFiles(
  WorkspacePath: string,
  ReceiptPaths: string[],
  ExpectedSourceRevision: string,
  ExpectedSourceRef: string,
  ExpectedPhase: (typeof KubernetesGraduationPhases)[number]
): KubernetesGraduationEvidenceReceipt[] {
  const Root = ResolveWorkspace(WorkspacePath)
  if (ReceiptPaths.length === 0 || ReceiptPaths.length > MaximumEvidenceFiles) {
    throw new Error(`verify requires between 1 and ${MaximumEvidenceFiles} explicit receipt paths`)
  }
  const CanonicalPaths = new Set<string>()
  for (const ReceiptPath of ReceiptPaths) {
    const CanonicalPath = Path.posix.normalize(ReceiptPath.replaceAll(Path.sep, '/'))
    if (CanonicalPaths.has(CanonicalPath)) {
      throw new Error(`verify repeats receipt path ${ReceiptPath}`)
    }
    CanonicalPaths.add(CanonicalPath)
  }
  const Policy = LoadKubernetesGraduationPolicy(Root)
  const EvidenceSchema = ParseJson(ReadBoundedFile(Root, Policy.evidenceSchema), Policy.evidenceSchema)
  const Receipts = ReceiptPaths.map(ReceiptPath => ValidateKubernetesGraduationEvidenceObject(
    ReadCanonicalReceipt(Root, ReceiptPath),
    EvidenceSchema,
    Policy,
    ExpectedSourceRevision,
    ExpectedSourceRef,
    ExpectedPhase,
    ReceiptPath
  ))
  return ValidateKubernetesGraduationEvidenceSet(Policy, Receipts)
}

export function ValidateKubernetesGraduationEvidenceSet(
  Policy: KubernetesGraduationPolicy,
  Receipts: KubernetesGraduationEvidenceReceipt[]
): KubernetesGraduationEvidenceReceipt[] {
  const SupportedFeatureIds = Policy.features
    .filter(Feature => Feature.status === 'supported')
    .map(Feature => Feature.id)
  if (SupportedFeatureIds.length === 0) {
    throw new Error('verify requires at least one supported feature row')
  }
  const ReceiptsByFeature = new Map<string, KubernetesGraduationEvidenceReceipt>()
  for (const Receipt of Receipts) {
    if (ReceiptsByFeature.has(Receipt.featureId)) {
      throw new Error(`verify receives duplicate evidence for feature ${Receipt.featureId}`)
    }
    const Feature = Policy.features.find(Candidate => Candidate.id === Receipt.featureId)
    if (Feature?.status !== 'supported' || Feature.lastValidatedVersion !== Policy.targetVersion) {
      throw new Error(`verify rejects evidence for experimental or unvalidated feature ${Receipt.featureId}`)
    }
    ReceiptsByFeature.set(Receipt.featureId, Receipt)
  }
  AssertExactSet('verify receipt feature ids', ReceiptsByFeature.keys(), SupportedFeatureIds)
  return Receipts
}

export function ValidateKubernetesGraduationEvidenceDirectory(
  WorkspacePath: string,
  RelativeDirectoryPath: string,
  ExpectedSourceRevision: string,
  ExpectedSourceRef: string,
  ExpectedPhase: (typeof KubernetesGraduationPhases)[number]
): KubernetesGraduationEvidenceReceipt[] {
  return ValidateKubernetesGraduationEvidenceFiles(
    WorkspacePath,
    LoadKubernetesGraduationEvidenceDirectory(WorkspacePath, RelativeDirectoryPath),
    ExpectedSourceRevision,
    ExpectedSourceRef,
    ExpectedPhase
  )
}

export type KubernetesGraduationPolicyValidationOptions = {
  AllowPreviousHelmCompatibility?: boolean
}

const CurrentHelmCompatibilityVersions = ['3.21.3', '4.2.4'] as const
const PreviousHelmCompatibilityVersions = ['3.21.3', '4.2.3'] as const

function ValidatePolicySemantics(
  Policy: KubernetesGraduationPolicy,
  Options: KubernetesGraduationPolicyValidationOptions = {}
): void {
  AssertExactSet(
    'Kubernetes graduation feature ids',
    Policy.features.map(Feature => Feature.id),
    KubernetesGraduationFeatureIds
  )
  AssertExactSet(
    'Kubernetes graduation cadence ids',
    Policy.cadences.map(Cadence => Cadence.id),
    RequiredCadences
  )
  AssertExactSet(
    'Kubernetes support minors',
    Policy.supportContract.kubernetes.minors.map(Minor => Minor.minor),
    ['1.34', '1.35', '1.36']
  )
  const HelmCompatibilityVersions = [...Policy.supportContract.helm.versions].sort()
  const AcceptedHelmCompatibilityVersions = [
    CurrentHelmCompatibilityVersions,
    ...(Options.AllowPreviousHelmCompatibility ? [PreviousHelmCompatibilityVersions] : [])
  ]
  if (!AcceptedHelmCompatibilityVersions.some(Versions =>
    ValuesEqual(HelmCompatibilityVersions, [...Versions].sort())
  )) {
    const Expected = AcceptedHelmCompatibilityVersions
      .map(Versions => `[${Versions.join(', ')}]`)
      .join(' or ')
    throw new Error(
      `Helm compatibility versions must be exactly ${Expected}, found [${HelmCompatibilityVersions.join(', ')}]`
    )
  }
  AssertExactSet(
    'Kubernetes architectures',
    Policy.supportContract.architectures.map(Architecture => Architecture.name),
    ['linux/amd64', 'linux/arm64', 'linux/riscv64']
  )
  AssertExactSet(
    'NetworkPolicy CNIs',
    Policy.supportContract.networking.networkPolicyCnis,
    ['Calico', 'Cilium']
  )

  for (const Minor of Policy.supportContract.kubernetes.minors) {
    if (!Minor.ciVersion.startsWith(`v${Minor.minor}.`)) {
      throw new Error(
        `Kubernetes ${Minor.minor} representative ${Minor.ciVersion} must use the same minor`
      )
    }
    if (!Minor.kindNodeImage.startsWith(`kindest/node:${Minor.ciVersion}@sha256:`)) {
      throw new Error(
        `Kubernetes ${Minor.minor} Kind image must bind ${Minor.ciVersion} to an immutable digest`
      )
    }
  }

  const BlockerIds = AssertUniqueIds('Kubernetes graduation blockers', Policy.blockers)
  const GateIds = AssertUniqueIds('Kubernetes graduation gates', Policy.gates)
  AssertUniqueIds('Kubernetes graduation features', Policy.features)
  const FeatureIds = new Set<string>(KubernetesGraduationFeatureIds)

  for (const Gate of Policy.gates) {
    if (!Gate.mandatory) {
      throw new Error(`graduation gate ${Gate.id} must remain mandatory`)
    }
    for (const FeatureId of Gate.appliesTo) {
      if (!FeatureIds.has(FeatureId)) {
        throw new Error(`graduation gate ${Gate.id} references unknown feature ${FeatureId}`)
      }
    }
  }

  const GateById = new Map(Policy.gates.map(Gate => [Gate.id, Gate]))
  for (const Feature of Policy.features) {
    for (const GateId of Feature.gateIds) {
      if (!GateIds.has(GateId)) {
        throw new Error(`feature ${Feature.id} references unknown gate ${GateId}`)
      }
      const Gate = GateById.get(GateId)
      if (Gate === undefined || !Gate.appliesTo.includes(Feature.id)) {
        throw new Error(`feature ${Feature.id} and gate ${GateId} do not reference each other`)
      }
    }
    for (const BlockerId of Feature.blockerIds) {
      if (!BlockerIds.has(BlockerId)) {
        throw new Error(`feature ${Feature.id} references unknown blocker ${BlockerId}`)
      }
    }
    const ApplicableGateIds = Policy.gates
      .filter(Gate => Gate.appliesTo.includes(Feature.id))
      .map(Gate => Gate.id)
    AssertExactSet(`feature ${Feature.id} gate ids`, Feature.gateIds, ApplicableGateIds)
    AssertExactSet(
      `feature ${Feature.id} qualified platforms`,
      Feature.qualifiedPlatforms,
      Feature.id === 'supply-chain-admission-bundle'
        ? ['linux/amd64', 'linux/arm64']
        : ['linux/amd64', 'linux/arm64', 'linux/riscv64']
    )
    const RequiresRiscvQualification = Feature.id !== 'supply-chain-admission-bundle'
    if (
      Feature.gateIds.includes('native-riscv64') !== RequiresRiscvQualification ||
      Feature.blockerIds.includes('native-riscv64-cluster-runner') !==
        (RequiresRiscvQualification && Feature.status === 'experimental')
    ) {
      throw new Error(
        `feature ${Feature.id} has an invalid native RISC-V qualification gate or blocker relationship`
      )
    }
    AssertExactSet(
      `feature ${Feature.id} required artifacts`,
      Feature.requiredArtifacts.map(Requirement =>
        `${Requirement.name}|${Requirement.kind}|${Requirement.repository}`
      ),
      Feature.id === 'supply-chain-admission-bundle'
        ? SupplyChainArtifactRequirements
        : []
    )
    if (Feature.status === 'experimental' && Feature.lastValidatedVersion !== 'unvalidated') {
      throw new Error(`experimental feature ${Feature.id} must remain unvalidated`)
    }
    if (Feature.status === 'supported') {
      if (Feature.lastValidatedVersion !== Policy.targetVersion) {
        throw new Error(`supported feature ${Feature.id} must bind target version ${Policy.targetVersion}`)
      }
      if (Feature.blockerIds.length !== 0) {
        throw new Error(`supported feature ${Feature.id} must not retain blockers`)
      }
    }
  }
}

export function ValidateKubernetesGraduationPolicyObject(
  PolicyValue: unknown,
  SchemaValue: unknown,
  Options: KubernetesGraduationPolicyValidationOptions = {}
): KubernetesGraduationPolicy {
  if (!IsObject(SchemaValue)) {
    throw new Error('Kubernetes graduation schema must be an object')
  }
  ValidateSchemaValue(PolicyValue, SchemaValue as JsonSchema, 'policy')
  const Policy = PolicyValue as KubernetesGraduationPolicy
  ValidatePolicySemantics(Policy, Options)
  return Policy
}

export function LoadKubernetesGraduationPolicy(
  WorkspacePath: string,
  Options: KubernetesGraduationPolicyValidationOptions = {}
): KubernetesGraduationPolicy {
  const Root = ResolveWorkspace(WorkspacePath)
  const PolicyValue = ParseJson(ReadBoundedFile(Root, PolicyPath), PolicyPath)
  const SchemaValue = ParseJson(ReadBoundedFile(Root, SchemaPath), SchemaPath)
  return ValidateKubernetesGraduationPolicyObject(PolicyValue, SchemaValue, Options)
}

function MarkdownCode(Value: string): string {
  return `\`${Value.replace(/`/g, '')}\``
}

export function RenderKubernetesGraduationTables(
  Policy: KubernetesGraduationPolicy
): string {
  const Lines: string[] = [
    GeneratedStart,
    '',
    '> Generated from `devops/config/kubernetes-feature-graduation.json` by',
    '> `pnpm run kubernetes-graduation:render`. Do not edit this block directly.',
    '',
    '### Graduation target Kubernetes matrix',
    '',
    '| Kubernetes minor | CI representative | Immutable Kind node image |',
    '| --- | --- | --- |'
  ]
  for (const Minor of Policy.supportContract.kubernetes.minors) {
    Lines.push(
      `| ${MarkdownCode(Minor.minor)} | ${MarkdownCode(Minor.ciVersion)} | ${MarkdownCode(Minor.kindNodeImage)} |`
    )
  }

  Lines.push(
    '',
    '### Governed feature states',
    '',
    '| Feature ID | State | Last validated version | Qualification platforms | Required artifacts | Mandatory gates | Active blockers |',
    '| --- | --- | --- | --- | --- | ---: | --- |'
  )
  const BlockerById = new Map(Policy.blockers.map(Blocker => [Blocker.id, Blocker]))
  for (const Feature of Policy.features) {
    const Blockers = Feature.blockerIds.length === 0
      ? 'None'
      : Feature.blockerIds.map(BlockerId => {
        if (!BlockerById.has(BlockerId)) {
          throw new Error(`feature ${Feature.id} references unknown blocker ${BlockerId}`)
        }
        return MarkdownCode(BlockerId)
      }).join(', ')
    const RequiredArtifacts = Feature.requiredArtifacts.length === 0
      ? 'None'
      : Feature.requiredArtifacts.map(Requirement => MarkdownCode(Requirement.name)).join(', ')
    Lines.push(
      `| ${MarkdownCode(Feature.id)} | ${MarkdownCode(Feature.status)} | ${MarkdownCode(Feature.lastValidatedVersion)} | ${Feature.qualifiedPlatforms.map(MarkdownCode).join(', ')} | ${RequiredArtifacts} | ${Feature.gateIds.length} | ${Blockers} |`
    )
  }

  Lines.push(
    '',
    '### Mandatory graduation gates',
    '',
    '| Gate ID | Earliest cadence | Applies to |',
    '| --- | --- | --- |'
  )
  for (const Gate of Policy.gates) {
    Lines.push(
      `| ${MarkdownCode(Gate.id)} | ${MarkdownCode(Gate.cadence)} | ${Gate.appliesTo.map(MarkdownCode).join(', ')} |`
    )
  }
  Lines.push('', GeneratedEnd)
  return Lines.join('\n')
}

function AssertGeneratedDocument(
  Content: string,
  ExpectedBlock: string
): void {
  const Start = Content.indexOf(GeneratedStart)
  const End = Content.indexOf(GeneratedEnd)
  if (Start === -1 || End === -1 || End < Start) {
    throw new Error(
      `${SupportDocumentPath} must contain one ${GeneratedStart}/${GeneratedEnd} block`
    )
  }
  if (
    Content.indexOf(GeneratedStart, Start + GeneratedStart.length) !== -1 ||
    Content.indexOf(GeneratedEnd, End + GeneratedEnd.length) !== -1
  ) {
    throw new Error(`${SupportDocumentPath} must contain exactly one generated policy block`)
  }
  const ActualBlock = Content.slice(Start, End + GeneratedEnd.length)
  if (ActualBlock !== ExpectedBlock) {
    throw new Error(
      `${SupportDocumentPath} generated policy block is stale; run pnpm run kubernetes-graduation:render`
    )
  }
}

function FeatureStatusRows(Content: string): Map<string, string> {
  const Rows = new Map<string, string>()
  for (const Match of Content.matchAll(/^\| `([^`]+)` \| `([^`]+)` \|/gm)) {
    if (Rows.has(Match[1])) {
      throw new Error(`${FeatureStatusPath} repeats feature id ${Match[1]}`)
    }
    Rows.set(Match[1], Match[2])
  }
  return Rows
}

export function ValidateKubernetesGraduationWorkspace(
  WorkspacePath: string,
  ExpectedSourceRevision?: string
): KubernetesGraduationPolicy {
  const Root = ResolveWorkspace(WorkspacePath)
  if (ExpectedSourceRevision !== undefined) {
    const Revision = ValidateSourceRevision(ExpectedSourceRevision, 'expected source revision')
    if (ResolveWorkspaceRevision(Root) !== Revision) {
      throw new Error('expected source revision does not match the checked-out Git source revision')
    }
  }
  const Policy = LoadKubernetesGraduationPolicy(Root)
  AssertGeneratedDocument(
    ReadBoundedFile(Root, SupportDocumentPath),
    RenderKubernetesGraduationTables(Policy)
  )
  const StatusRows = FeatureStatusRows(ReadBoundedFile(Root, FeatureStatusPath))
  for (const Feature of Policy.features) {
    const DocumentedStatus = StatusRows.get(Feature.id)
    if (DocumentedStatus !== Feature.status) {
      throw new Error(
        `${FeatureStatusPath} status for ${Feature.id} must be ${Feature.status}, found ${DocumentedStatus ?? 'no row'}`
      )
    }
  }
  return Policy
}

function ParseCli(Argv: string[]): ParsedCli {
  const Command = Argv[2]
  if (Command !== 'check' && Command !== 'render' && Command !== 'verify') {
    throw new Error('usage: kubernetes_graduation.ts <check|render|verify> [options]')
  }
  const Parameters: CliParameters = {}
  for (let Index = 3; Index < Argv.length; Index += 1) {
    const Option = Argv[Index]
    const Value = Argv[Index + 1]
    if (!Option.startsWith('--')) {
      throw new Error(`unexpected argument: ${Option}`)
    }
    if (Value === undefined || Value.startsWith('--')) {
      throw new Error(`missing value for ${Option}`)
    }
    Index += 1
    switch (Option) {
      case '--workspace-path':
        Parameters.workspacePath = Value
        break
      case '--expected-source-revision':
        Parameters.expectedSourceRevision = Value
        break
      case '--expected-source-ref':
        Parameters.expectedSourceRef = Value
        break
      case '--phase':
        if (Value !== 'candidate' && Value !== 'official_beta') {
          throw new Error(`unsupported qualification phase: ${Value}`)
        }
        Parameters.phase = Value
        break
      case '--evidence-dir':
        Parameters.evidenceDirectory = Value
        break
      default:
        throw new Error(`unknown option: ${Option}`)
    }
  }
  return { command: Command, parameters: Parameters }
}

export function ResolveKubernetesGraduationGitRefRevision(Root: string, Ref: string): string {
  const ValidRef = ValidateSourceRef(Ref, 'expected source ref')
  try {
    return ValidateSourceRevision(execFileSync(
      'git',
      ['-C', Root, 'rev-parse', '--verify', `${ValidRef}^{commit}`],
      { encoding: 'utf8', maxBuffer: 1024, stdio: ['ignore', 'pipe', 'pipe'] }
    ).trim(), 'expected source ref revision')
  } catch {
    throw new Error(`could not resolve expected source ref ${ValidRef}`)
  }
}

export function ValidateKubernetesGraduationPhaseRef(
  Phase: (typeof KubernetesGraduationPhases)[number],
  Ref: string
): void {
  if (Phase === 'candidate' && Ref !== 'refs/heads/main') {
    throw new Error('candidate qualification requires source ref refs/heads/main')
  }
  if (Phase === 'official_beta' && !/^refs\/tags\/0\.8\.0-beta\.[1-9][0-9]*$/.test(Ref)) {
    throw new Error('official_beta qualification requires an exact 0.8.0 beta tag ref')
  }
}

function RunCli(): void {
  const { command: Command, parameters: Parameters } = ParseCli(Process.argv)
  const Root = ResolveWorkspace(Parameters.workspacePath ?? '.')
  if (Command === 'check') {
    if (
      Parameters.expectedSourceRef !== undefined ||
      Parameters.phase !== undefined ||
      Parameters.evidenceDirectory !== undefined
    ) {
      throw new Error('check accepts only --workspace-path and --expected-source-revision')
    }
    ValidateKubernetesGraduationWorkspace(Root, Parameters.expectedSourceRevision)
    return
  }
  if (Command === 'render') {
    if (
      Parameters.expectedSourceRevision !== undefined ||
      Parameters.expectedSourceRef !== undefined ||
      Parameters.phase !== undefined ||
      Parameters.evidenceDirectory !== undefined
    ) {
      throw new Error('render accepts only --workspace-path')
    }
    Process.stdout.write(`${RenderKubernetesGraduationTables(LoadKubernetesGraduationPolicy(Root))}\n`)
    return
  }
  if (
    Parameters.expectedSourceRevision === undefined ||
    Parameters.expectedSourceRef === undefined ||
    Parameters.phase === undefined ||
    Parameters.evidenceDirectory === undefined
  ) {
    throw new Error('verify requires --expected-source-revision, --expected-source-ref, --phase, and --evidence-dir')
  }
  const Revision = ValidateSourceRevision(
    Parameters.expectedSourceRevision,
    'expected source revision'
  )
  if (ResolveWorkspaceRevision(Root) !== Revision) {
    throw new Error('expected source revision does not match the checked-out Git source revision')
  }
  ValidateKubernetesGraduationPhaseRef(Parameters.phase, Parameters.expectedSourceRef)
  if (ResolveKubernetesGraduationGitRefRevision(Root, Parameters.expectedSourceRef) !== Revision) {
    throw new Error('expected source ref does not resolve to the expected checked-out Git source revision')
  }
  ValidateKubernetesGraduationEvidenceDirectory(
    Root,
    Parameters.evidenceDirectory,
    Revision,
    Parameters.expectedSourceRef,
    Parameters.phase
  )
}

const Entrypoint = Process.argv[1]
if (
  Entrypoint !== undefined &&
  import.meta.url === pathToFileURL(Path.resolve(Entrypoint)).href
) {
  try {
    RunCli()
  } catch (ErrorValue) {
    const Message = ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)
    console.error(`Kubernetes graduation policy error: ${Message}`)
    process.exitCode = 1
  }
}
