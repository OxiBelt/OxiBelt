import * as Crypto from 'node:crypto'
import * as Fs from 'node:fs'
import * as Process from 'node:process'
import { pathToFileURL } from 'node:url'

/* eslint-disable @typescript-eslint/naming-convention -- Rebuild predicates use stable lower-camel-case JSON keys. */
type JsonRecord = Record<string, unknown>

export const RebuildPredicateType = 'https://oxibelt.dev/attestations/rebuild/v1'

export type PlatformRecipeOptions = {
  imagePlan: unknown
  artifactContract: unknown
  binaryInventory: unknown
  sbom: unknown
  buildEnvironment: unknown
  role: string
  artifactArch: string
}

export type IndexRecipeOptions = {
  imagePlan: unknown
  indexMetadata: unknown
  indexSbom: unknown
  platformRecipes: unknown[]
  role: string
}

export type PredicateIdentity = {
  subjectName: string
  subjectDigest: string
  signerWorkflow: string
  sourceRepository: string
  sourceRef: string
  sourceRevision: string
  predicateType: string
}

type CliParameters = {
  mode: 'platform' | 'index' | 'extract' | 'digest'
  values: Map<string, string[]>
}
const Digest = /^sha256:[0-9a-f]{64}$/
const Revision = /^[0-9a-f]{40}$/
const MaximumPredicateBytes = 16 * 1024 * 1024
const ExpectedIndexArchs = ['amd64', 'arm64', 'riscv64'] as const
const NormalizedFields = [
  'outer-archive-order',
  'layer-compression',
  'filesystem-mtime',
  'oci-created-and-history-timestamps'
] as const

function IsRecord(Value: unknown): Value is JsonRecord {
  return typeof Value === 'object' && Value !== null && !Array.isArray(Value)
}

function RecordValue(Value: unknown, Description: string): JsonRecord {
  if (!IsRecord(Value)) {
    throw new Error(`${Description} must be a JSON object`)
  }
  return Value
}

function ArrayValue(Value: unknown, Description: string): unknown[] {
  if (!Array.isArray(Value)) {
    throw new Error(`${Description} must be an array`)
  }
  return Value
}

function StringValue(Value: unknown, Description: string): string {
  if (typeof Value !== 'string' || Value === '') {
    throw new Error(`${Description} must be a non-empty string`)
  }
  return Value
}

function DigestValue(Value: unknown, Description: string): string {
  const Result = StringValue(Value, Description)
  if (!Digest.test(Result)) {
    throw new Error(`${Description} must be a lowercase SHA-256 digest`)
  }
  return Result
}

function Exact(Value: unknown, Expected: unknown, Description: string): void {
  if (JSON.stringify(Value) !== JSON.stringify(Expected)) {
    throw new Error(`${Description} does not match the release contract`)
  }
}

function Canonical(Value: unknown): unknown {
  if (Array.isArray(Value)) {
    return Value.map(Canonical)
  }
  if (!IsRecord(Value)) {
    return Value
  }
  return Object.fromEntries(Object.keys(Value).sort().map(Key => [Key, Canonical(Value[Key])]))
}

function CanonicalText(Value: unknown): string {
  return JSON.stringify(Canonical(Value))
}

export function RebuildPredicateSha256(Value: unknown): string {
  return `sha256:${Crypto.createHash('sha256').update(CanonicalText(Value), 'utf8').digest('hex')}`
}

function AssertSize(Value: unknown): void {
  const Size = Buffer.byteLength(JSON.stringify(Value))
  if (Size > MaximumPredicateBytes) {
    throw new Error(`rebuild predicate exceeds the ${MaximumPredicateBytes} byte attestation limit`)
  }
}

function ReleaseContract(ImagePlan: unknown, Role: string, ArtifactArch?: string): {
  plan: JsonRecord
  role: JsonRecord
  artifact?: JsonRecord
} {
  const Plan = RecordValue(ImagePlan, 'image release plan')
  if (Plan.schemaVersion !== 8) {
    throw new Error('image release plan schemaVersion must be 8')
  }
  const RevisionValue = StringValue(Plan.revision, 'image release plan revision')
  if (!Revision.test(RevisionValue)) {
    throw new Error('image release plan revision must be a full lowercase Git commit')
  }
  Exact(Plan.sourceRef, `refs/tags/${StringValue(Plan.version, 'image release plan version')}`, 'image release plan sourceRef')
  Exact(Plan.sourceDirty, 'clean', 'image release plan sourceDirty')
  Exact(Plan.buildKind, 'official_release', 'image release plan buildKind')
  const Roles = ArrayValue(Plan.roles, 'image release plan roles')
    .map((Item, Index) => RecordValue(Item, `image release plan roles[${Index}]`))
    .filter(Item => Item.role === Role)
  if (Roles.length !== 1) {
    throw new Error(`image release plan must contain exactly one role ${Role}`)
  }
  if (ArtifactArch === undefined) {
    return { plan: Plan, role: Roles[0] }
  }
  const Artifacts = ArrayValue(Plan.artifacts, 'image release plan artifacts')
    .map((Item, Index) => RecordValue(Item, `image release plan artifacts[${Index}]`))
    .filter(Item => Item.role === Role && Item.artifactArch === ArtifactArch)
  if (Artifacts.length !== 1) {
    throw new Error(`image release plan must contain exactly one artifact ${Role}/${ArtifactArch}`)
  }
  return { plan: Plan, role: Roles[0], artifact: Artifacts[0] }
}

function ValidateBuildEnvironment(Value: unknown): JsonRecord {
  const Environment = RecordValue(Value, 'build environment')
  const ExpectedKeys = [
    'schemaVersion', 'rustc', 'cargo', 'node', 'pnpm', 'buildx', 'buildkit', 'trivy',
    'cc', 'ld', 'featureGraphSha256'
  ]
  if (Object.keys(Environment).sort().join('\n') !== [...ExpectedKeys].sort().join('\n')) {
    throw new Error('build environment has unexpected fields')
  }
  if (Environment.schemaVersion !== 1) {
    throw new Error('build environment schemaVersion must be 1')
  }
  for (const Key of ExpectedKeys.slice(1, -1)) {
    StringValue(Environment[Key], `build environment ${Key}`)
  }
  DigestValue(Environment.featureGraphSha256, 'build environment featureGraphSha256')
  return Environment
}

function ValidateSbom(Value: unknown, ImageDigest: string): JsonRecord {
  const Sbom = RecordValue(Value, 'CycloneDX SBOM')
  if (Sbom.bomFormat !== 'CycloneDX' || !['1.6', '1.7'].includes(String(Sbom.specVersion))) {
    throw new Error('SBOM must be CycloneDX 1.6 or 1.7')
  }
  const Metadata = RecordValue(Sbom.metadata, 'CycloneDX metadata')
  const Root = RecordValue(Metadata.component, 'CycloneDX metadata.component')
  const Properties = ArrayValue(Root.properties, 'CycloneDX root properties')
  const ImageProperties = Properties.filter(Item => IsRecord(Item) && Item.name === 'io.oxibelt.image.digest')
  if (ImageProperties.length !== 1 || RecordValue(ImageProperties[0], 'image digest property').value !== ImageDigest) {
    throw new Error('SBOM does not bind the artifact image digest')
  }
  return Sbom
}

function ValidateInventory(Value: unknown, ExpectedBinaries: unknown): JsonRecord {
  const Inventory = RecordValue(Value, 'binary inventory')
  if (Inventory.schemaVersion !== 1) {
    throw new Error('binary inventory schemaVersion must be 1')
  }
  const Binaries = ArrayValue(Inventory.binaries, 'binary inventory binaries')
    .map((Item, Index) => RecordValue(Item, `binary inventory binaries[${Index}]`))
  for (const Binary of Binaries) {
    if (!/^[0-9a-f]{64}$/.test(StringValue(Binary.sha256, 'binary inventory digest'))) {
      throw new Error('binary inventory digest must be 64 lowercase hexadecimal characters')
    }
  }
  const ActualNames = Binaries.map(Binary => StringValue(Binary.name, 'binary inventory name')).sort()
  const Names = ArrayValue(ExpectedBinaries, 'release artifact binaries').map(String).sort()
  Exact(ActualNames, Names, 'binary inventory names')
  return Inventory
}

export function BuildPlatformRebuildRecipe(Options: PlatformRecipeOptions): JsonRecord {
  const Release = ReleaseContract(Options.imagePlan, Options.role, Options.artifactArch)
  const Artifact = Release.artifact as JsonRecord
  const Contract = RecordValue(Options.artifactContract, 'artifact contract')
  if (Contract.schema !== 3) {
    throw new Error('artifact contract schema must be 3')
  }
  for (const [Key, Expected] of Object.entries({
    role: Options.role,
    artifact_arch: Options.artifactArch,
    revision: Release.plan.revision,
    source: Release.plan.source,
    source_ref: Release.plan.sourceRef,
    source_dirty: Release.plan.sourceDirty,
    build_kind: Release.plan.buildKind,
    platform: Artifact.platform,
    docker_architecture: Artifact.dockerArchitecture,
    target_cpu: Artifact.targetCpu ?? null,
    docker_target: Artifact.dockerTarget
  })) {
    Exact(Contract[Key], Expected, `artifact contract ${Key}`)
  }
  const ImageDigest = DigestValue(Contract.image_digest, 'artifact contract image_digest')
  Exact(Contract.descriptor_digest, ImageDigest, 'artifact descriptor digest')
  const SourceTree = StringValue(Contract.source_tree, 'artifact contract source_tree')
  if (!Revision.test(SourceTree)) {
    throw new Error('artifact contract source_tree must be a full lowercase Git tree')
  }
  const Inventory = ValidateInventory(Options.binaryInventory, Artifact.binaries)
  const Sbom = ValidateSbom(Options.sbom, ImageDigest)
  const Environment = ValidateBuildEnvironment(Options.buildEnvironment)
  const Recipe: JsonRecord = {
    schemaVersion: 1,
    predicateType: RebuildPredicateType,
    kind: 'platform',
    subject: {
      name: StringValue(Release.role.image, 'release image repository'),
      digest: ImageDigest
    },
    source: {
      repository: Release.plan.source,
      ref: `refs/tags/${StringValue(Release.plan.version, 'release version')}`,
      revision: Release.plan.revision,
      tree: SourceTree,
      releaseOverlaySha256: DigestValue(Contract.source_inputs_sha256, 'source input digest')
    },
    build: {
      role: Options.role,
      artifactArch: Options.artifactArch,
      platform: Contract.platform,
      dockerArchitecture: Contract.docker_architecture,
      rustTarget: Contract.rust_target,
      targetCpu: Contract.target_cpu,
      dockerTarget: Contract.docker_target,
      cargoBuilds: Contract.cargo_builds,
      parameters: Contract.build_parameters,
      environment: Environment,
      sourceInputs: Contract.source_inputs
    },
    output: {
      artifactContract: Contract,
      artifactContractSha256: RebuildPredicateSha256(Contract),
      binaryInventory: Inventory,
      binaryInventorySha256: RebuildPredicateSha256(Inventory),
      sbomSha256: RebuildPredicateSha256(Sbom)
    },
    comparison: { schemaVersion: 1, exactFirst: true, normalizedFields: NormalizedFields }
  }
  AssertSize(Recipe)
  return Recipe
}

export function BuildIndexRebuildRecipe(Options: IndexRecipeOptions): JsonRecord {
  const Release = ReleaseContract(Options.imagePlan, Options.role)
  const Metadata = RecordValue(Options.indexMetadata, 'index metadata')
  if (Metadata.schemaVersion !== 2 || Metadata.role !== Options.role || Metadata.image !== Release.role.image) {
    throw new Error('index metadata does not match the release role')
  }
  const IndexDigest = DigestValue(Metadata.digest, 'index metadata digest')
  const Children = ArrayValue(Metadata.children, 'index metadata children').map(Item => RecordValue(Item, 'index child'))
  const Recipes = Options.platformRecipes.map(Item => RecordValue(Item, 'platform rebuild recipe'))
  if (Children.length !== ExpectedIndexArchs.length || Recipes.length !== ExpectedIndexArchs.length) {
    throw new Error('index rebuild recipe requires exactly three platform children')
  }
  const BoundChildren = ExpectedIndexArchs.map((Arch, Index) => {
    const Child = Children[Index]
    const Recipe = Recipes.find(Item => IsRecord(Item.build) && RecordValue(Item.build, 'platform build').artifactArch === Arch)
    if (Child.artifactArch !== Arch || Recipe === undefined || Recipe.kind !== 'platform' || Recipe.predicateType !== RebuildPredicateType) {
      throw new Error(`index children and platform recipes must be ordered and complete for ${Arch}`)
    }
    const Subject = RecordValue(Recipe.subject, `platform ${Arch} subject`)
    Exact(Subject.digest, Child.digest, `platform ${Arch} subject digest`)
    return {
      artifactArch: Arch,
      digest: DigestValue(Child.digest, `platform ${Arch} digest`),
      recipeSha256: RebuildPredicateSha256(Recipe)
    }
  })
  const Sbom = ValidateSbom(Options.indexSbom, IndexDigest)
  const Recipe: JsonRecord = {
    schemaVersion: 1,
    predicateType: RebuildPredicateType,
    kind: 'index',
    subject: { name: Release.role.image, digest: IndexDigest },
    source: {
      repository: Release.plan.source,
      ref: `refs/tags/${StringValue(Release.plan.version, 'release version')}`,
      revision: Release.plan.revision
    },
    output: {
      indexMetadata: Metadata,
      indexMetadataSha256: RebuildPredicateSha256(Metadata),
      children: BoundChildren,
      sbomSha256: RebuildPredicateSha256(Sbom)
    }
  }
  AssertSize(Recipe)
  return Recipe
}

function CertificateValue(Certificate: JsonRecord, Names: string[], Description: string): string {
  for (const Name of Names) {
    if (typeof Certificate[Name] === 'string' && Certificate[Name] !== '') {
      return String(Certificate[Name])
    }
  }
  throw new Error(`verification certificate is missing ${Description}`)
}

function MatchingPredicate(Value: unknown, Identity: PredicateIdentity): unknown | undefined {
  try {
    const Result = RecordValue(Value, 'attestation result')
    const Verification = RecordValue(Result.verificationResult, 'verificationResult')
    const Signature = RecordValue(Verification.signature, 'verificationResult.signature')
    const Certificate = RecordValue(Signature.certificate, 'verification certificate')
    if (CertificateValue(Certificate, ['subjectAlternativeName', 'SubjectAlternativeName'], 'signer') !== Identity.signerWorkflow) return undefined
    const Source = CertificateValue(Certificate, ['sourceRepository', 'SourceRepository', 'sourceRepositoryURI', 'SourceRepositoryURI'], 'source repository')
    if (Source !== Identity.sourceRepository && Source !== `https://github.com/${Identity.sourceRepository}`) return undefined
    if (CertificateValue(Certificate, ['sourceRepositoryRef', 'SourceRepositoryRef'], 'source ref') !== Identity.sourceRef) return undefined
    if (CertificateValue(Certificate, ['sourceRepositoryDigest', 'SourceRepositoryDigest'], 'source digest') !== Identity.sourceRevision) return undefined
    if (CertificateValue(Certificate, ['buildSignerDigest', 'BuildSignerDigest'], 'signer digest') !== Identity.sourceRevision) return undefined
    if (CertificateValue(Certificate, ['runnerEnvironment', 'RunnerEnvironment'], 'runner environment') !== 'github-hosted') return undefined
    if (ArrayValue(Verification.verifiedTimestamps, 'verified timestamps').length === 0) return undefined
    const Statement = RecordValue(Verification.statement, 'attestation statement')
    if (Statement.predicateType !== Identity.predicateType) return undefined
    const Subjects = ArrayValue(Statement.subject, 'attestation subjects')
    if (Subjects.length !== 1) return undefined
    const Subject = RecordValue(Subjects[0], 'attestation subject')
    const SubjectDigest = RecordValue(Subject.digest, 'attestation subject digest')
    if (Subject.name !== Identity.subjectName || SubjectDigest.sha256 !== Identity.subjectDigest.slice('sha256:'.length)) return undefined
    return Statement.predicate
  } catch {
    return undefined
  }
}

export function ExtractVerifiedPredicate(Value: unknown, Identity: PredicateIdentity): unknown {
  DigestValue(Identity.subjectDigest, 'subject digest')
  if (!Revision.test(Identity.sourceRevision)) {
    throw new Error('source revision must be a full lowercase Git commit')
  }
  const Matches = ArrayValue(Value, 'gh attestation verify JSON')
    .map(Item => MatchingPredicate(Item, Identity))
    .filter(Item => Item !== undefined)
  if (Matches.length === 0) {
    throw new Error('no verified attestation exactly matches the requested identity')
  }
  const CanonicalMatches = new Set(Matches.map(CanonicalText))
  if (CanonicalMatches.size !== 1) {
    throw new Error('verified attestations contain conflicting predicates for one subject')
  }
  return Matches[0]
}

function ReadJson(Path: string): unknown {
  const Stat = Fs.statSync(Path)
  if (!Stat.isFile() || Stat.size > MaximumPredicateBytes) {
    throw new Error(`JSON input must be a regular file within the ${MaximumPredicateBytes} byte limit: ${Path}`)
  }
  return JSON.parse(Fs.readFileSync(Path, 'utf8')) as unknown
}

function ParseCli(Argv: string[]): CliParameters {
  const Mode = Argv[2]
  if (Mode !== 'platform' && Mode !== 'index' && Mode !== 'extract' && Mode !== 'digest') {
    throw new Error('first argument must be platform, index, extract, or digest')
  }
  const Values = new Map<string, string[]>()
  for (let Index = 3; Index < Argv.length; Index += 2) {
    const Option = Argv[Index]
    const Value = Argv[Index + 1]
    if (!Option.startsWith('--') || Value === undefined || Value.startsWith('--')) {
      throw new Error(`invalid or missing value for ${Option}`)
    }
    Values.set(Option, [...(Values.get(Option) ?? []), Value])
  }
  return { mode: Mode, values: Values }
}

function CliValue(Parameters: CliParameters, Name: string): string {
  const Values = Parameters.values.get(Name)
  if (Values === undefined || Values.length !== 1) {
    throw new Error(`${Name} must be supplied exactly once`)
  }
  return Values[0]
}

function RepeatedCliValue(Parameters: CliParameters, Name: string): string[] {
  const Values = Parameters.values.get(Name)
  if (Values === undefined || Values.length === 0) {
    throw new Error(`${Name} must be supplied at least once`)
  }
  return Values
}

function WriteOutput(Path: string, Value: unknown): void {
  Fs.writeFileSync(Path, `${JSON.stringify(Value, null, 2)}\n`)
}

function RunCli(): void {
  const Parameters = ParseCli(Process.argv)
  if (Parameters.mode === 'digest') {
    Process.stdout.write(`${RebuildPredicateSha256(ReadJson(CliValue(Parameters, '--input')))}\n`)
    return
  }
  const Output = CliValue(Parameters, '--output')
  if (Parameters.mode === 'platform') {
    WriteOutput(Output, BuildPlatformRebuildRecipe({
      imagePlan: ReadJson(CliValue(Parameters, '--image-plan')),
      artifactContract: ReadJson(CliValue(Parameters, '--artifact-contract')),
      binaryInventory: ReadJson(CliValue(Parameters, '--binary-inventory')),
      sbom: ReadJson(CliValue(Parameters, '--sbom')),
      buildEnvironment: ReadJson(CliValue(Parameters, '--build-environment')),
      role: CliValue(Parameters, '--role'),
      artifactArch: CliValue(Parameters, '--artifact-arch')
    }))
  } else if (Parameters.mode === 'index') {
    WriteOutput(Output, BuildIndexRebuildRecipe({
      imagePlan: ReadJson(CliValue(Parameters, '--image-plan')),
      indexMetadata: ReadJson(CliValue(Parameters, '--index-metadata')),
      indexSbom: ReadJson(CliValue(Parameters, '--index-sbom')),
      platformRecipes: RepeatedCliValue(Parameters, '--platform-recipe').map(ReadJson),
      role: CliValue(Parameters, '--role')
    }))
  } else {
    WriteOutput(Output, ExtractVerifiedPredicate(
      ReadJson(CliValue(Parameters, '--attestations')),
      {
        subjectName: CliValue(Parameters, '--subject-name'),
        subjectDigest: CliValue(Parameters, '--subject-digest'),
        signerWorkflow: CliValue(Parameters, '--signer-workflow'),
        sourceRepository: CliValue(Parameters, '--source-repository'),
        sourceRef: CliValue(Parameters, '--source-ref'),
        sourceRevision: CliValue(Parameters, '--source-revision'),
        predicateType: CliValue(Parameters, '--predicate-type')
      }
    ))
  }
}

function FormatError(Value: unknown): string {
  return Value instanceof Error ? Value.message : String(Value)
}

if (Process.argv[1] !== undefined && import.meta.url === pathToFileURL(Process.argv[1]).href) {
  try {
    RunCli()
  } catch (ErrorValue) {
    console.error(`Rebuild recipe failed: ${FormatError(ErrorValue)}`)
    Process.exit(1)
  }
}
