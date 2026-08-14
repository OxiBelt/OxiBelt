import * as Crypto from 'node:crypto'
import * as Fs from 'node:fs'
import * as Path from 'node:path'
import * as Process from 'node:process'
import { execFileSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

/* eslint-disable @typescript-eslint/naming-convention -- Stable policy and receipt keys are external JSON wire names. */
const PolicyPath = 'devops/config/feature-graduation.json'
const SchemaPath = 'devops/config/feature-graduation.schema.json'
const FeatureStatusPath = 'docs/FeatureStatus.md'
const MaximumInputBytes = 1024 * 1024
const MaximumEvidenceFiles = 64
const MaximumJsonDepth = 64
const MaximumJsonNodes = 10000
const MaximumJsonStringBytes = 64 * 1024
const MaximumJsonArrayItems = 1024
const MaximumJsonObjectKeys = 256
const FullRevision = /^[0-9a-f]{40}$/

export const FeatureGraduationFeatureIds = [
  'config-activation-planner',
  'runtime-confinement-contract',
  'owned-embedded-runtime-api',
  'compio-direct-h1-io',
  'crlite',
  'tls-upstream-revocation',
  'root-netport-switcher',
  'client-identity-asn',
  'sybil-rate-limit-identities',
  'admin-staged-membership'
] as const

export const FeatureGraduationPhases = ['candidate', 'official_beta'] as const

const FeatureDependencies: Readonly<Record<(typeof FeatureGraduationFeatureIds)[number], readonly string[]>> = {
  'config-activation-planner': [],
  'runtime-confinement-contract': [],
  'owned-embedded-runtime-api': [],
  'compio-direct-h1-io': [],
  crlite: [],
  'tls-upstream-revocation': [],
  'root-netport-switcher': [],
  'client-identity-asn': [],
  'sybil-rate-limit-identities': ['client-identity-asn'],
  'admin-staged-membership': []
}

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

export type FeatureGraduationPolicy = {
  $schema: string
  schemaVersion: 1
  policyVersion: number
  lifecycleAuthority: string
  evidenceSchema: string
  repository: string
  targetVersion: '0.8.0'
  gates: Array<{
    id: string
    objective: string
    appliesTo: string[]
  }>
  features: Array<{
    id: (typeof FeatureGraduationFeatureIds)[number]
    status: 'experimental' | 'supported'
    lastValidatedVersion: string
    qualifiedPlatforms: Array<'linux/amd64' | 'linux/arm64'>
    dependsOn: string[]
    gateIds: string[]
  }>
}

export type FeatureGraduationEvidenceReceipt = {
  schemaVersion: 1
  policyVersion: number
  policyDefinitionSha256: string
  featureId: (typeof FeatureGraduationFeatureIds)[number]
  intendedStatus: 'supported'
  phase: (typeof FeatureGraduationPhases)[number]
  targetVersion: string
  repository: string
  sourceRef: string
  sourceRevision: string
  generatedAt: string
  qualifiedPlatforms: Array<'linux/amd64' | 'linux/arm64'>
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
      platform: 'linux/amd64' | 'linux/arm64'
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
  phase?: (typeof FeatureGraduationPhases)[number]
  evidenceDirectory?: string
}

type ParsedCli = {
  command: 'check' | 'verify'
  parameters: CliParameters
}

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

export function CanonicalJson(Value: unknown): string {
  if (Array.isArray(Value)) {
    return `[${Value.map(Item => CanonicalJson(Item)).join(',')}]`
  }
  if (IsObject(Value)) {
    return `{${Object.keys(Value).sort().map(Key =>
      `${JSON.stringify(Key)}:${CanonicalJson(Value[Key])}`
    ).join(',')}}`
  }
  return JSON.stringify(Value)
}

function ValidateJsonComplexity(Value: unknown, Location: string, Depth = 0, State = { nodes: 0 }): void {
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
    Value.forEach((Item, Index) => ValidateJsonComplexity(Item, `${Location}[${Index}]`, Depth + 1, State))
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
  return CanonicalJson(Left) === CanonicalJson(Right)
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
        const Canonical = CanonicalJson(Item)
        if (Seen.has(Canonical)) {
          throw new Error(`${Location} must not contain duplicate items`)
        }
        Seen.add(Canonical)
      }
    }
    if (Schema.items !== undefined) {
      Value.forEach((Item, Index) => ValidateSchemaValue(Item, Schema.items as JsonSchema, `${Location}[${Index}]`))
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
    throw new Error(`${Label} must be exactly [${ExpectedValues.join(', ')}], found [${ActualValues.join(', ')}]`)
  }
}

function AssertUniqueIds(Label: string, Values: Array<{ id: string }>): Set<string> {
  const Ids = new Set<string>()
  for (const Value of Values) {
    if (Ids.has(Value.id)) {
      throw new Error(`${Label} repeats id ${Value.id}`)
    }
    Ids.add(Value.id)
  }
  return Ids
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

export function FeatureGraduationPolicyDefinitionSha256(Policy: FeatureGraduationPolicy): string {
  return Crypto.createHash('sha256').update(CanonicalJson(Policy), 'utf8').digest('hex')
}

function ValidatePolicySemantics(Policy: FeatureGraduationPolicy): void {
  AssertExactSet('feature graduation feature ids', Policy.features.map(Feature => Feature.id), FeatureGraduationFeatureIds)
  const GateIds = AssertUniqueIds('feature graduation gates', Policy.gates)
  AssertUniqueIds('feature graduation features', Policy.features)
  const FeatureIds = new Set<string>(FeatureGraduationFeatureIds)
  for (const Gate of Policy.gates) {
    for (const FeatureId of Gate.appliesTo) {
      if (!FeatureIds.has(FeatureId)) {
        throw new Error(`feature graduation gate ${Gate.id} references unknown feature ${FeatureId}`)
      }
    }
  }
  for (const Feature of Policy.features) {
    AssertExactSet(
      `feature ${Feature.id} qualified platforms`,
      Feature.qualifiedPlatforms,
      Feature.id === 'compio-direct-h1-io' ? ['linux/amd64'] : ['linux/amd64', 'linux/arm64']
    )
    const ApplicableGateIds = Policy.gates.filter(Gate => Gate.appliesTo.includes(Feature.id)).map(Gate => Gate.id)
    AssertExactSet(`feature ${Feature.id} gate ids`, Feature.gateIds, ApplicableGateIds)
    for (const GateId of Feature.gateIds) {
      if (!GateIds.has(GateId)) {
        throw new Error(`feature ${Feature.id} references unknown gate ${GateId}`)
      }
    }
    AssertExactSet(`feature ${Feature.id} dependencies`, Feature.dependsOn, FeatureDependencies[Feature.id])
    for (const DependencyId of Feature.dependsOn) {
      if (!FeatureIds.has(DependencyId)) {
        throw new Error(`feature ${Feature.id} depends on unknown feature ${DependencyId}`)
      }
      if (DependencyId === Feature.id) {
        throw new Error(`feature ${Feature.id} must not depend on itself`)
      }
    }
    if (Feature.status === 'experimental' && Feature.lastValidatedVersion !== 'unvalidated') {
      throw new Error(`experimental feature ${Feature.id} must remain unvalidated`)
    }
    if (Feature.status === 'supported' && Feature.lastValidatedVersion !== Policy.targetVersion) {
      throw new Error(`supported feature ${Feature.id} must bind target version ${Policy.targetVersion}`)
    }
  }
  const FeatureById = new Map<string, FeatureGraduationPolicy['features'][number]>()
  for (const Feature of Policy.features) {
    FeatureById.set(Feature.id, Feature)
  }
  for (const Feature of Policy.features.filter(Candidate => Candidate.status === 'supported')) {
    for (const DependencyId of Feature.dependsOn) {
      if (FeatureById.get(DependencyId)?.status !== 'supported') {
        throw new Error(`supported feature ${Feature.id} requires supported dependency ${DependencyId}`)
      }
    }
  }
}

export function ValidateFeatureGraduationPolicyObject(
  PolicyValue: unknown,
  SchemaValue: unknown
): FeatureGraduationPolicy {
  if (!IsObject(SchemaValue)) {
    throw new Error('feature graduation schema must be an object')
  }
  ValidateSchemaValue(PolicyValue, SchemaValue as JsonSchema, 'policy')
  const Policy = PolicyValue as FeatureGraduationPolicy
  ValidatePolicySemantics(Policy)
  return Policy
}

function ReadCanonicalReceipt(Root: string, RelativePath: string): unknown {
  const Content = ReadBoundedFile(Root, RelativePath)
  const Value = ParseJson(Content, RelativePath)
  ValidateJsonComplexity(Value, RelativePath)
  if (Content !== CanonicalJson(Value)) {
    throw new Error(`${RelativePath} must contain canonical JSON without duplicate keys or whitespace`)
  }
  return Value
}

function ValidateNamedUnique(Label: string, Values: Array<{ name: string }>): void {
  const Seen = new Set<string>()
  for (const Value of Values) {
    if (Seen.has(Value.name)) {
      throw new Error(`${Label} repeats name ${Value.name}`)
    }
    Seen.add(Value.name)
  }
}

function IsExactUtcSecond(Value: string): boolean {
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(Value)) {
    return false
  }
  const Parsed = new Date(Value)
  return !Number.isNaN(Parsed.valueOf()) && Parsed.toISOString() === `${Value.slice(0, -1)}.000Z`
}

export function ValidateFeatureGraduationEvidenceObject(
  Value: unknown,
  SchemaValue: unknown,
  Policy: FeatureGraduationPolicy,
  ExpectedSourceRevision: string,
  ExpectedSourceRef: string,
  ExpectedPhase: (typeof FeatureGraduationPhases)[number],
  Label = 'feature graduation evidence'
): FeatureGraduationEvidenceReceipt {
  if (!IsObject(SchemaValue)) {
    throw new Error('feature graduation evidence schema must be an object')
  }
  ValidateSchemaValue(Value, SchemaValue as JsonSchema, Label)
  const Receipt = Value as FeatureGraduationEvidenceReceipt
  const ExpectedRevision = ValidateSourceRevision(ExpectedSourceRevision, 'expected source revision')
  const ExpectedRef = ValidateSourceRef(ExpectedSourceRef, 'expected source ref')
  if (Receipt.repository !== Policy.repository || Receipt.workflow.repository !== Policy.repository) {
    throw new Error(`${Label} does not bind the policy repository`)
  }
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
  if (
    Receipt.policyVersion !== Policy.policyVersion ||
    Receipt.policyDefinitionSha256 !== FeatureGraduationPolicyDefinitionSha256(Policy)
  ) {
    throw new Error(`${Label} does not bind the current feature graduation policy`)
  }
  const Feature = Policy.features.find(Candidate => Candidate.id === Receipt.featureId)
  if (Feature === undefined) {
    throw new Error(`${Label} references unknown feature ${Receipt.featureId}`)
  }
  if (Feature.status !== 'supported' || Feature.lastValidatedVersion !== Policy.targetVersion) {
    throw new Error(`${Label} may only promote a supported feature at target version ${Policy.targetVersion}`)
  }
  AssertExactSet(`${Label} qualified platforms`, Receipt.qualifiedPlatforms, Feature.qualifiedPlatforms)
  if (!IsExactUtcSecond(Receipt.generatedAt)) {
    throw new Error(`${Label}.generatedAt must be a real RFC3339 UTC timestamp`)
  }
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
  ValidateNamedUnique(`${Label} report hashes`, Receipt.reportHashes)
  const LogIds = new Set<number>()
  for (const Log of Receipt.logHashes) {
    if (LogIds.has(Log.jobId)) {
      throw new Error(`${Label} repeats log hash for job ${Log.jobId}`)
    }
    LogIds.add(Log.jobId)
  }
  if (!ValuesEqual([...JobIds].sort((Left, Right) => Left - Right), [...LogIds].sort((Left, Right) => Left - Right))) {
    throw new Error(`${Label} must bind one log hash for every exact workflow job`)
  }
  const GateResults = new Set<string>()
  for (const Result of Receipt.gateResults) {
    if (GateResults.has(Result.id)) {
      throw new Error(`${Label} repeats gate result ${Result.id}`)
    }
    GateResults.add(Result.id)
    const PlatformIds = new Set<string>()
    const PlatformJobIds = new Set<number>()
    const PlatformReportNames = new Set<string>()
    const PlatformReportHashes = new Set<string>()
    for (const PlatformResult of Result.platformResults) {
      if (PlatformIds.has(PlatformResult.platform)) {
        throw new Error(`${Label} gate result ${Result.id} repeats platform ${PlatformResult.platform}`)
      }
      if (PlatformJobIds.has(PlatformResult.jobId)) {
        throw new Error(`${Label} gate result ${Result.id} reuses producing job ${PlatformResult.jobId} across platforms`)
      }
      if (
        PlatformReportNames.has(PlatformResult.reportName) ||
        PlatformReportHashes.has(PlatformResult.reportSha256)
      ) {
        throw new Error(`${Label} gate result ${Result.id} reuses a report across platforms`)
      }
      PlatformIds.add(PlatformResult.platform)
      PlatformJobIds.add(PlatformResult.jobId)
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
    AssertExactSet(`${Label} gate result ${Result.id} platforms`, PlatformIds, Feature.qualifiedPlatforms)
  }
  AssertExactSet(`${Label} gate results`, GateResults, Feature.gateIds)
  return Receipt
}

export function LoadFeatureGraduationEvidenceDirectory(
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
    RelativePaths.push(Path.posix.join(RelativeDirectoryPath.replaceAll(Path.sep, '/'), Entry.name))
  }
  return RelativePaths.sort()
}

export function ValidateFeatureGraduationEvidenceFiles(
  WorkspacePath: string,
  ReceiptPaths: string[],
  ExpectedSourceRevision: string,
  ExpectedSourceRef: string,
  ExpectedPhase: (typeof FeatureGraduationPhases)[number]
): FeatureGraduationEvidenceReceipt[] {
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
  const Policy = LoadFeatureGraduationPolicy(Root)
  const EvidenceSchema = ParseJson(ReadBoundedFile(Root, Policy.evidenceSchema), Policy.evidenceSchema)
  const Receipts = ReceiptPaths.map(ReceiptPath => ValidateFeatureGraduationEvidenceObject(
    ReadCanonicalReceipt(Root, ReceiptPath),
    EvidenceSchema,
    Policy,
    ExpectedSourceRevision,
    ExpectedSourceRef,
    ExpectedPhase,
    ReceiptPath
  ))
  return ValidateFeatureGraduationEvidenceSet(Policy, Receipts)
}

export function ValidateFeatureGraduationEvidenceSet(
  Policy: FeatureGraduationPolicy,
  Receipts: FeatureGraduationEvidenceReceipt[]
): FeatureGraduationEvidenceReceipt[] {
  const SupportedFeatureIds = Policy.features
    .filter(Feature => Feature.status === 'supported')
    .map(Feature => Feature.id)
  if (SupportedFeatureIds.length === 0) {
    throw new Error('verify requires at least one supported feature row')
  }
  const ReceiptsByFeature = new Map<string, FeatureGraduationEvidenceReceipt>()
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
  for (const FeatureId of SupportedFeatureIds) {
    const Feature = Policy.features.find(Candidate => Candidate.id === FeatureId)
    if (Feature?.lastValidatedVersion !== Policy.targetVersion) {
      throw new Error(`supported feature ${FeatureId} must bind target version ${Policy.targetVersion}`)
    }
  }
  return Receipts
}

export function ValidateFeatureGraduationEvidenceDirectory(
  WorkspacePath: string,
  RelativeDirectoryPath: string,
  ExpectedSourceRevision: string,
  ExpectedSourceRef: string,
  ExpectedPhase: (typeof FeatureGraduationPhases)[number]
): FeatureGraduationEvidenceReceipt[] {
  return ValidateFeatureGraduationEvidenceFiles(
    WorkspacePath,
    LoadFeatureGraduationEvidenceDirectory(WorkspacePath, RelativeDirectoryPath),
    ExpectedSourceRevision,
    ExpectedSourceRef,
    ExpectedPhase
  )
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

export function LoadFeatureGraduationPolicy(WorkspacePath: string): FeatureGraduationPolicy {
  const Root = ResolveWorkspace(WorkspacePath)
  const PolicyValue = ParseJson(ReadBoundedFile(Root, PolicyPath), PolicyPath)
  const SchemaValue = ParseJson(ReadBoundedFile(Root, SchemaPath), SchemaPath)
  return ValidateFeatureGraduationPolicyObject(PolicyValue, SchemaValue)
}

export function ValidateFeatureGraduationWorkspace(WorkspacePath: string): FeatureGraduationPolicy {
  const Root = ResolveWorkspace(WorkspacePath)
  const Policy = LoadFeatureGraduationPolicy(Root)
  const StatusRows = FeatureStatusRows(ReadBoundedFile(Root, FeatureStatusPath))
  for (const Feature of Policy.features) {
    const DocumentedStatus = StatusRows.get(Feature.id)
    if (DocumentedStatus !== Feature.status) {
      throw new Error(`${FeatureStatusPath} status for ${Feature.id} must be ${Feature.status}, found ${DocumentedStatus ?? 'no row'}`)
    }
  }
  return Policy
}

function ResolveWorkspaceRevision(Root: string): string {
  let Revision: string
  try {
    Revision = execFileSync('git', ['-C', Root, 'rev-parse', '--verify', 'HEAD^{commit}'], {
      encoding: 'utf8', maxBuffer: 1024, stdio: ['ignore', 'pipe', 'pipe']
    }).trim()
  } catch {
    throw new Error('could not resolve the checked-out Git source revision')
  }
  return ValidateSourceRevision(Revision, 'checked-out Git source revision')
}

function ResolveGitRefRevision(Root: string, Ref: string): string {
  const ValidRef = ValidateSourceRef(Ref, 'expected source ref')
  try {
    return ValidateSourceRevision(execFileSync(
      'git', ['-C', Root, 'rev-parse', '--verify', `${ValidRef}^{commit}`], {
        encoding: 'utf8', maxBuffer: 1024, stdio: ['ignore', 'pipe', 'pipe']
      }
    ).trim(), `Git ref ${ValidRef}`)
  } catch {
    throw new Error(`could not resolve ${ValidRef} to a Git commit`)
  }
}

function ValidatePhaseRef(Phase: (typeof FeatureGraduationPhases)[number], Ref: string): void {
  if (Phase === 'candidate' && Ref !== 'refs/heads/main') {
    throw new Error('candidate qualification requires refs/heads/main')
  }
  if (Phase === 'official_beta' && !/^refs\/tags\/0\.8\.0-beta\.[1-9][0-9]*$/.test(Ref)) {
    throw new Error('official_beta qualification requires a 0.8.0 beta tag ref')
  }
}

function ParseCli(Argv: string[]): ParsedCli {
  const Command = Argv[2]
  if (Command !== 'check' && Command !== 'verify') {
    throw new Error('usage: feature_graduation.ts <check|verify> [options]')
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
      case '--workspace-path': Parameters.workspacePath = Value; break
      case '--expected-source-revision': Parameters.expectedSourceRevision = Value; break
      case '--expected-source-ref': Parameters.expectedSourceRef = Value; break
      case '--phase':
        if (!(FeatureGraduationPhases as readonly string[]).includes(Value)) {
          throw new Error(`unknown qualification phase: ${Value}`)
        }
        Parameters.phase = Value as (typeof FeatureGraduationPhases)[number]
        break
      case '--evidence-dir': Parameters.evidenceDirectory = Value; break
      default: throw new Error(`unknown option: ${Option}`)
    }
  }
  return { command: Command, parameters: Parameters }
}

function RunCli(): void {
  const { command: Command, parameters: Parameters } = ParseCli(Process.argv)
  const Root = ResolveWorkspace(Parameters.workspacePath ?? '.')
  if (Command === 'check') {
    if (Parameters.expectedSourceRevision !== undefined || Parameters.expectedSourceRef !== undefined || Parameters.phase !== undefined || Parameters.evidenceDirectory !== undefined) {
      throw new Error('check accepts only --workspace-path and uses the checked-in policy and schema')
    }
    ValidateFeatureGraduationWorkspace(Root)
    return
  }
  if (Parameters.expectedSourceRevision === undefined || Parameters.expectedSourceRef === undefined || Parameters.phase === undefined || Parameters.evidenceDirectory === undefined) {
    throw new Error('verify requires --expected-source-revision, --expected-source-ref, --phase, and --evidence-dir')
  }
  const Revision = ValidateSourceRevision(Parameters.expectedSourceRevision, 'expected source revision')
  const HeadRevision = ResolveWorkspaceRevision(Root)
  if (Revision !== HeadRevision) {
    throw new Error('expected source revision does not match the checked-out Git source revision')
  }
  ValidatePhaseRef(Parameters.phase, Parameters.expectedSourceRef)
  if (ResolveGitRefRevision(Root, Parameters.expectedSourceRef) !== Revision) {
    throw new Error('expected source ref does not resolve to the expected checked-out Git source revision')
  }
  ValidateFeatureGraduationEvidenceDirectory(
    Root,
    Parameters.evidenceDirectory,
    Revision,
    Parameters.expectedSourceRef,
    Parameters.phase
  )
}

const Entrypoint = Process.argv[1]
if (Entrypoint !== undefined && import.meta.url === pathToFileURL(Path.resolve(Entrypoint)).href) {
  try {
    RunCli()
  } catch (ErrorValue) {
    const Message = ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)
    console.error(`feature graduation policy error: ${Message}`)
    process.exitCode = 1
  }
}
