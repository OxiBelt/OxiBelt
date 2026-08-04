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
const GeneratedStart = '<!-- BEGIN KUBERNETES GRADUATION GENERATED -->'
const GeneratedEnd = '<!-- END KUBERNETES GRADUATION GENERATED -->'
const FullRevision = /^[0-9a-f]{40}$/
const ValidatedProductVersion = /^v[0-9]+\.[0-9]+\.[0-9]+$/
const UtcSecond = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/

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

const RequiredCadences = [
  'pull_request',
  'nightly',
  'release_candidate',
  'stable'
] as const

/* eslint-disable @typescript-eslint/naming-convention -- Parsed policy and JSON Schema keys are stable lower-camel-case wire names. */
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
  schemaVersion: 1
  policyVersion: number
  lifecycleAuthority: string
  evidenceSchema: string
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
    status: 'unmet' | 'passed'
    mandatory: true
    appliesTo: string[]
    evidenceReceipts: string[]
  }>
  features: Array<{
    id: string
    status: 'experimental' | 'supported'
    lastValidatedVersion: string
    gateIds: string[]
    blockerIds: string[]
  }>
}

export type KubernetesGraduationEvidenceReceipt = {
  schemaVersion: 1
  policyVersion: number
  policyDefinitionSha256: string
  sourceRevision: string
  validatedVersion: string
  runId: number
  runAttempt: number
  generatedAt: string
  jobIds: number[]
  artifactSubjects: Array<{
    name: string
    kind: 'oci-image' | 'helm-chart'
    reference: string
    digest: string
  }>
  reports: Array<{
    name: string
    sha256: string
  }>
  logs: Array<{
    jobId: number
    sha256: string
  }>
  gateResults: Array<{
    id: string
    result: 'passed'
  }>
}

type CliParameters = {
  workspacePath?: string
  policyPath?: string
  schemaPath?: string
  expectedSourceRevision?: string
  expectedValidatedVersion?: string
}

type IdRecord = {
  id: string
}

type ParsedCli = {
  command: 'check' | 'render'
  parameters: CliParameters
}
/* eslint-enable @typescript-eslint/naming-convention */

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

function ValidateProductVersion(Value: string, Label: string): string {
  if (!ValidatedProductVersion.test(Value)) {
    throw new Error(`${Label} must be a v-prefixed stable semantic version`)
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
  const Candidate = Path.resolve(Root, RelativePath)
  if (!IsPathWithin(Root, Candidate)) {
    throw new Error(`repository input escapes the workspace: ${RelativePath}`)
  }
  return Candidate
}

function ReadBoundedFile(Root: string, RelativePath: string): string {
  const Candidate = ResolveRepositoryPath(Root, RelativePath)
  const Stat = Fs.lstatSync(Candidate)
  if (!Stat.isFile() || Stat.isSymbolicLink()) {
    throw new Error(`repository input must be a regular non-symlink file: ${RelativePath}`)
  }
  if (Stat.size > MaximumInputBytes) {
    throw new Error(`repository input exceeds ${MaximumInputBytes} bytes: ${RelativePath}`)
  }
  const Content = Fs.readFileSync(Candidate, 'utf8')
  if (Content.includes('\0')) {
    throw new Error(`repository input contains a NUL byte: ${RelativePath}`)
  }
  return Content
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
  const Definition = {
    ...Policy,
    gates: Policy.gates.map(Gate => ({ ...Gate, evidenceReceipts: [] }))
  }
  return Crypto.createHash('sha256').update(StableValue(Definition), 'utf8').digest('hex')
}

function IsExactUtcSecond(Value: string): boolean {
  if (!UtcSecond.test(Value)) {
    return false
  }
  const Parsed = new Date(Value)
  return !Number.isNaN(Parsed.valueOf()) &&
    Parsed.toISOString() === `${Value.slice(0, -1)}.000Z`
}

export function ValidateKubernetesGraduationEvidenceObject(
  Value: unknown,
  SchemaValue: unknown,
  Policy: KubernetesGraduationPolicy,
  ExpectedSourceRevision: string,
  ExpectedValidatedVersion: string,
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
  if (Receipt.sourceRevision !== ExpectedRevision) {
    throw new Error(`${Label} does not bind the expected source revision`)
  }
  const ExpectedVersion = ValidateProductVersion(
    ExpectedValidatedVersion,
    'expected validated product version'
  )
  if (Receipt.validatedVersion !== ExpectedVersion) {
    throw new Error(`${Label} does not bind the expected validated product version`)
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

  const ArtifactNames = new Set<string>()
  const ArtifactReferences = new Set<string>()
  const ArtifactKinds = new Set<string>()
  for (const Subject of Receipt.artifactSubjects) {
    if (ArtifactNames.has(Subject.name) || ArtifactReferences.has(Subject.reference)) {
      throw new Error(`${Label} repeats an artifact name or reference`)
    }
    ArtifactNames.add(Subject.name)
    ArtifactReferences.add(Subject.reference)
    ArtifactKinds.add(Subject.kind)
    if (
      Subject.kind === 'oci-image' &&
      !Subject.reference.endsWith(`@${Subject.digest}`)
    ) {
      throw new Error(
        `${Label} OCI image ${Subject.name} reference must end with its immutable digest`
      )
    }
  }
  AssertExactSet(`${Label} artifact kinds`, ArtifactKinds, ['oci-image', 'helm-chart'])
  const ArtifactVersion = ExpectedVersion.slice(1)
  if (!Receipt.artifactSubjects.some(Subject =>
    Subject.kind === 'helm-chart' && Subject.reference.endsWith(`-${ArtifactVersion}.tgz`)
  )) {
    throw new Error(
      `${Label} must bind a Helm chart package for validated version ${ExpectedVersion}`
    )
  }

  const ReportNames = new Set<string>()
  for (const Report of Receipt.reports) {
    if (ReportNames.has(Report.name)) {
      throw new Error(`${Label} repeats report name ${Report.name}`)
    }
    ReportNames.add(Report.name)
  }

  const LogJobIds = new Set<number>()
  for (const Log of Receipt.logs) {
    if (LogJobIds.has(Log.jobId)) {
      throw new Error(`${Label} repeats log hash for job ${Log.jobId}`)
    }
    LogJobIds.add(Log.jobId)
  }
  const JobIds = new Set(Receipt.jobIds)
  if (
    JobIds.size !== Receipt.jobIds.length ||
    !ValuesEqual([...JobIds].sort((Left, Right) => Left - Right), [...LogJobIds].sort((Left, Right) => Left - Right))
  ) {
    throw new Error(`${Label} must bind one log hash for every exact job id`)
  }

  const PolicyGateIds = new Set(Policy.gates.map(Gate => Gate.id))
  const ResultIds = new Set<string>()
  for (const Result of Receipt.gateResults) {
    if (!PolicyGateIds.has(Result.id)) {
      throw new Error(`${Label} references unknown gate ${Result.id}`)
    }
    if (ResultIds.has(Result.id)) {
      throw new Error(`${Label} repeats gate result ${Result.id}`)
    }
    ResultIds.add(Result.id)
  }
  return Receipt
}

function ValidateEvidence(
  Root: string,
  Policy: KubernetesGraduationPolicy,
  ExpectedSourceRevision: string,
  ExpectedValidatedVersion: string,
  GateId: string,
  ReceiptPaths: string[]
): KubernetesGraduationEvidenceReceipt[] {
  if (ReceiptPaths.length === 0) {
    throw new Error(`passed gate ${GateId} must name at least one evidence receipt`)
  }
  const EvidenceSchema = ParseJson(
    ReadBoundedFile(Root, Policy.evidenceSchema),
    Policy.evidenceSchema
  )
  const Receipts: KubernetesGraduationEvidenceReceipt[] = []
  for (const ReceiptPath of ReceiptPaths) {
    const Receipt = ValidateKubernetesGraduationEvidenceObject(
      ParseJson(ReadBoundedFile(Root, ReceiptPath), ReceiptPath),
      EvidenceSchema,
      Policy,
      ExpectedSourceRevision,
      ExpectedValidatedVersion,
      ReceiptPath
    )
    if (!Receipt.gateResults.some(Result => Result.id === GateId && Result.result === 'passed')) {
      throw new Error(`${ReceiptPath} does not contain passed evidence for gate ${GateId}`)
    }
    Receipts.push(Receipt)
  }
  return Receipts
}

function ValidatePolicySemantics(
  Policy: KubernetesGraduationPolicy,
  Root?: string,
  ExpectedSourceRevision?: string,
  ExpectedValidatedVersion?: string
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
  AssertExactSet(
    'Helm compatibility versions',
    Policy.supportContract.helm.versions,
    ['3.21.3', '4.2.3']
  )
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

  const EvidenceByGate = new Map<string, KubernetesGraduationEvidenceReceipt[]>()
  for (const Gate of Policy.gates) {
    if (!Gate.mandatory) {
      throw new Error(`graduation gate ${Gate.id} must remain mandatory`)
    }
    for (const FeatureId of Gate.appliesTo) {
      if (!FeatureIds.has(FeatureId)) {
        throw new Error(`graduation gate ${Gate.id} references unknown feature ${FeatureId}`)
      }
    }
    if (Gate.status === 'unmet' && Gate.evidenceReceipts.length !== 0) {
      throw new Error(`unmet gate ${Gate.id} must not claim evidence receipts`)
    }
    if (Gate.status === 'passed') {
      if (Root === undefined) {
        throw new Error(
          `passed gate ${Gate.id} requires workspace evidence validation`
        )
      } else {
        if (ExpectedSourceRevision === undefined) {
          throw new Error(`passed gate ${Gate.id} requires an expected source revision`)
        }
        if (ExpectedValidatedVersion === undefined) {
          throw new Error(`passed gate ${Gate.id} requires an expected validated product version`)
        }
        EvidenceByGate.set(Gate.id, ValidateEvidence(
          Root,
          Policy,
          ExpectedSourceRevision,
          ExpectedValidatedVersion,
          Gate.id,
          Gate.evidenceReceipts
        ))
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
    const Incomplete = Feature.gateIds.filter(GateId => GateById.get(GateId)?.status !== 'passed')
    if (Feature.lastValidatedVersion !== 'unvalidated') {
      if (Incomplete.length !== 0) {
        throw new Error(
          `feature ${Feature.id} lastValidatedVersion requires complete mandatory gates: ${Incomplete.join(', ')}`
        )
      }
      if (Root !== undefined) {
        if (ExpectedValidatedVersion === undefined) {
          throw new Error(
            `feature ${Feature.id} lastValidatedVersion requires an expected validated product version`
          )
        }
        if (Feature.lastValidatedVersion !== ExpectedValidatedVersion) {
          throw new Error(
            `feature ${Feature.id} lastValidatedVersion does not match the expected validated product version`
          )
        }
      }
      for (const GateId of Feature.gateIds) {
        for (const Receipt of EvidenceByGate.get(GateId) ?? []) {
          if (Receipt.validatedVersion !== Feature.lastValidatedVersion) {
            throw new Error(
              `feature ${Feature.id} lastValidatedVersion does not match ${GateId} evidence`
            )
          }
        }
      }
    }
    if (Feature.status === 'supported') {
      if (Incomplete.length !== 0) {
        throw new Error(
          `supported feature ${Feature.id} has incomplete mandatory gates: ${Incomplete.join(', ')}`
        )
      }
      if (Feature.lastValidatedVersion === 'unvalidated') {
        throw new Error(`supported feature ${Feature.id} must name its validated product version`)
      }
      if (Feature.blockerIds.length !== 0) {
        throw new Error(`supported feature ${Feature.id} must not retain blockers`)
      }
    }
  }
}

export function ValidateKubernetesGraduationPolicyObject(
  PolicyValue: unknown,
  SchemaValue: unknown
): KubernetesGraduationPolicy {
  if (!IsObject(SchemaValue)) {
    throw new Error('Kubernetes graduation schema must be an object')
  }
  ValidateSchemaValue(PolicyValue, SchemaValue as JsonSchema, 'policy')
  const Policy = PolicyValue as KubernetesGraduationPolicy
  ValidatePolicySemantics(Policy)
  return Policy
}

function LoadPolicy(
  Root: string,
  RelativePolicyPath: string,
  RelativeSchemaPath: string,
  ExpectedSourceRevision?: string,
  ExpectedValidatedVersion?: string
): KubernetesGraduationPolicy {
  const PolicyValue = ParseJson(ReadBoundedFile(Root, RelativePolicyPath), RelativePolicyPath)
  const SchemaValue = ParseJson(ReadBoundedFile(Root, RelativeSchemaPath), RelativeSchemaPath)
  if (!IsObject(SchemaValue)) {
    throw new Error('Kubernetes graduation schema must be an object')
  }
  ValidateSchemaValue(PolicyValue, SchemaValue as JsonSchema, 'policy')
  const Policy = PolicyValue as KubernetesGraduationPolicy
  const RequestedRevision = ExpectedSourceRevision === undefined
    ? undefined
    : ValidateSourceRevision(ExpectedSourceRevision, 'expected source revision')
  let EvidenceRevision = RequestedRevision
  if (
    RequestedRevision !== undefined ||
    Policy.gates.some(Gate => Gate.status === 'passed')
  ) {
    const WorkspaceRevision = ResolveWorkspaceRevision(Root)
    if (RequestedRevision !== undefined && RequestedRevision !== WorkspaceRevision) {
      throw new Error('expected source revision does not match the checked-out Git source revision')
    }
    EvidenceRevision = RequestedRevision ?? WorkspaceRevision
  }
  const RequestedVersion = ExpectedValidatedVersion === undefined
    ? undefined
    : ValidateProductVersion(ExpectedValidatedVersion, 'expected validated product version')
  ValidatePolicySemantics(Policy, Root, EvidenceRevision, RequestedVersion)
  return Policy
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
    '| Feature ID | State | Last validated version | Mandatory gates | Active blockers |',
    '| --- | --- | --- | ---: | --- |'
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
    Lines.push(
      `| ${MarkdownCode(Feature.id)} | ${MarkdownCode(Feature.status)} | ${MarkdownCode(Feature.lastValidatedVersion)} | ${Feature.gateIds.length} | ${Blockers} |`
    )
  }

  Lines.push(
    '',
    '### Mandatory graduation gates',
    '',
    '| Gate ID | Earliest cadence | State | Applies to |',
    '| --- | --- | --- | --- |'
  )
  for (const Gate of Policy.gates) {
    Lines.push(
      `| ${MarkdownCode(Gate.id)} | ${MarkdownCode(Gate.cadence)} | ${MarkdownCode(Gate.status)} | ${Gate.appliesTo.map(MarkdownCode).join(', ')} |`
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
  RelativePolicyPath = PolicyPath,
  RelativeSchemaPath = SchemaPath,
  ExpectedSourceRevision?: string,
  ExpectedValidatedVersion?: string
): KubernetesGraduationPolicy {
  const Root = ResolveWorkspace(WorkspacePath)
  const Policy = LoadPolicy(
    Root,
    RelativePolicyPath,
    RelativeSchemaPath,
    ExpectedSourceRevision,
    ExpectedValidatedVersion
  )
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
  if (Command !== 'check' && Command !== 'render') {
    throw new Error('usage: kubernetes_graduation.ts <check|render> [options]')
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
      case '--policy-path':
        Parameters.policyPath = Value
        break
      case '--schema-path':
        Parameters.schemaPath = Value
        break
      case '--expected-source-revision':
        Parameters.expectedSourceRevision = Value
        break
      case '--expected-version':
        Parameters.expectedValidatedVersion = Value
        break
      default:
        throw new Error(`unknown option: ${Option}`)
    }
  }
  return { command: Command, parameters: Parameters }
}

function RunCli(): void {
  const { command: Command, parameters: Parameters } = ParseCli(Process.argv)
  const Root = ResolveWorkspace(Parameters.workspacePath ?? '.')
  const RelativePolicyPath = Parameters.policyPath ?? PolicyPath
  const RelativeSchemaPath = Parameters.schemaPath ?? SchemaPath
  if (Command === 'check') {
    ValidateKubernetesGraduationWorkspace(
      Root,
      RelativePolicyPath,
      RelativeSchemaPath,
      Parameters.expectedSourceRevision,
      Parameters.expectedValidatedVersion
    )
    return
  }
  const Policy = LoadPolicy(
    Root,
    RelativePolicyPath,
    RelativeSchemaPath,
    Parameters.expectedSourceRevision,
    Parameters.expectedValidatedVersion
  )
  Process.stdout.write(`${RenderKubernetesGraduationTables(Policy)}\n`)
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
