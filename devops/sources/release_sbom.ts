import * as Crypto from 'node:crypto'
import * as Fs from 'node:fs'
import * as Process from 'node:process'
import { pathToFileURL } from 'node:url'
import {
  BuildImageRoleContracts,
  type ImageRole,
  type ImageRoleContract
} from './docker_image_release.js'

export type JsonPrimitive = boolean | null | number | string
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[]
export type JsonObject = { [Key: string]: JsonValue }

export type ReleaseSbomKind = 'index' | 'platform'

export type PlatformSbomOptions = {
  Trivy: JsonObject
  BuildMetadata: JsonObject
  BuildInputs: JsonObject
  BinaryInventory: JsonObject
  Role: ImageRole
  Image: string
  Digest?: string
  Version: string
  Revision: string
  Source: string
  Created: string
  Generated: string
  Workflow: string
}

export type IndexSbomOptions = {
  PlatformSboms: JsonObject[]
  Role: ImageRole
  Image: string
  Digest?: string
  Version: string
  Revision: string
  Source: string
  Created: string
  Generated: string
  BuildStartedOn: string
  BuildFinishedOn: string
  Workflow: string
}

export type VerifySbomOptions = {
  Kind: ReleaseSbomKind
  Role?: ImageRole
  Digest?: string
  Revision?: string
  Workflow?: string
  Image?: string
  Version?: string
}

type CliParameters = {
  Mode: 'index' | 'platform' | 'verify'
  Values: Map<string, string[]>
}

type ReleaseIdentity = {
  Role: ImageRole
  Image: string
  Digest?: string
  Version: string
  Revision: string
  Source: string
  Created: string
  Workflow: string
}

type BuildInputDetails = {
  Role: ImageRole
  ArtifactArch: string
  Platform: string
  RustTarget: string
  TargetCpu?: string
  RustToolchainVersion: string
  BaseImages: Array<{
    BuildArgument: string
    Stage: string
    Reference: string
  }>
}

type Material = {
  Uri: string
  Digest: string
}

type BuildTimestamps = {
  StartedOn: string
  FinishedOn: string
}

const CycloneDxSpecVersion = '1.6'
const CycloneDxPredicateType = 'https://cyclonedx.org/bom'
const OfficialSource = 'https://github.com/OxiBelt/OxiBelt'
const PlatformBuilderWorkflow = 'OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml'
const IndexBuilderWorkflow = 'OxiBelt/OxiBelt/.github/workflows/release.yml'
const RequiredRustToolchain = '1.96.0'
const Sha256 = /^[0-9a-f]{64}$/
const Sha256Digest = /^sha256:[0-9a-f]{64}$/
const GitRevision = /^[0-9a-f]{40}$/
const CanonicalTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/
const Rfc3339Timestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/
const ImageName = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$/
const ReleaseValue = /^[A-Za-z0-9][A-Za-z0-9.+_-]*$/
const WorkflowIdentity = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/

const KnownBinaries = new Map<string, string>([
  ['oxibelt', '/usr/local/bin/oxibelt'],
  ['oxibelt-keysigner', '/usr/local/bin/oxibelt-keysigner'],
  ['oxibelt-netport-switcher', '/usr/local/bin/oxibelt-netport-switcher'],
  ['oxibeltctl', '/usr/local/bin/oxibeltctl'],
  ['oxibelt-gateway-controller', '/usr/local/bin/oxibelt-gateway-controller']
])

const KnownBaseStages = new Map<string, string>([
  ['builder', 'RUST_BUILDER_IMAGE'],
  ['person-proof-ui', 'OXIBELT_NODE_IMAGE'],
  ['runtime', 'OXIBELT_RUNTIME_IMAGE']
])

const OfficialRoles = new Map<ImageRole, ImageRoleContract>(
  BuildImageRoleContracts().map(Contract => [Contract.role, Contract])
)

const ArtifactPlatforms = new Map<string, { Platform: string; RustTarget: string; TargetCpu?: string }>([
  ['amd64v2', { Platform: 'linux/amd64', RustTarget: 'x86_64-unknown-linux-musl', TargetCpu: 'x86-64-v2' }],
  ['amd64', { Platform: 'linux/amd64', RustTarget: 'x86_64-unknown-linux-musl', TargetCpu: 'x86-64-v3' }],
  ['amd64v4', { Platform: 'linux/amd64', RustTarget: 'x86_64-unknown-linux-musl', TargetCpu: 'x86-64-v4' }],
  ['arm64', { Platform: 'linux/arm64', RustTarget: 'aarch64-unknown-linux-musl' }],
  ['riscv64', { Platform: 'linux/riscv64', RustTarget: 'riscv64gc-unknown-linux-musl' }]
])

const RequiredIndexArtifactArchs = ['amd64', 'arm64', 'riscv64']

function IsJsonValue(Value: unknown): Value is JsonValue {
  if (Value === null || ['boolean', 'number', 'string'].includes(typeof Value)) {
    return typeof Value !== 'number' || Number.isFinite(Value)
  }

  if (Array.isArray(Value)) {
    return Value.every(Item => IsJsonValue(Item))
  }

  if (typeof Value !== 'object') {
    return false
  }

  return Object.values(Value).every(Item => IsJsonValue(Item))
}

function AsObject(Value: JsonValue | undefined, Context: string): JsonObject {
  if (Value === null || Array.isArray(Value) || typeof Value !== 'object') {
    throw new Error(`${Context} must be a JSON object`)
  }

  return Value
}

function AsArray(Value: JsonValue | undefined, Context: string): JsonValue[] {
  if (!Array.isArray(Value)) {
    throw new Error(`${Context} must be a JSON array`)
  }

  return Value
}

function AsString(Value: JsonValue | undefined, Context: string): string {
  if (typeof Value !== 'string' || Value === '') {
    throw new Error(`${Context} must be a non-empty string`)
  }

  return Value
}

function AsOptionalString(Value: JsonValue | undefined, Context: string): string | undefined {
  if (Value === undefined || Value === null) {
    return undefined
  }

  return AsString(Value, Context)
}

function AsInteger(Value: JsonValue | undefined, Context: string): number {
  if (typeof Value !== 'number' || !Number.isSafeInteger(Value)) {
    throw new Error(`${Context} must be a safe integer`)
  }

  return Value
}

function AsImageRole(Value: JsonValue | undefined, Context: string): ImageRole {
  const Role = AsString(Value, Context)
  if (!OfficialRoles.has(Role as ImageRole)) {
    throw new Error(`${Context} must be standalone, dataplane, controller, tools, or keysigner`)
  }

  return Role as ImageRole
}

function RoleContract(Role: ImageRole): ImageRoleContract {
  const Contract = OfficialRoles.get(Role)
  if (Contract === undefined) {
    throw new Error(`unsupported release image role ${Role}`)
  }

  return Contract
}

function StringArray(Value: JsonValue | undefined, Context: string): string[] {
  return AsArray(Value, Context).map((Item, Index) => AsString(Item, `${Context}[${Index}]`))
}

function SameStrings(Actual: string[], Expected: string[]): boolean {
  return Actual.length === Expected.length && Actual.every((Value, Index) => Value === Expected[Index])
}

function ReadJson(Path: string): JsonObject {
  let Parsed: unknown

  try {
    Parsed = JSON.parse(Fs.readFileSync(Path, 'utf8'))
  } catch (ErrorValue) {
    throw new Error(`could not read JSON from ${Path}: ${FormatError(ErrorValue)}`)
  }

  if (!IsJsonValue(Parsed)) {
    throw new Error(`${Path} must contain finite JSON values`)
  }

  return AsObject(Parsed, Path)
}

function CloneObject(Value: JsonObject): JsonObject {
  return structuredClone(Value)
}

function StableValue(Value: JsonValue): JsonValue {
  if (Array.isArray(Value)) {
    return Value.map(Item => StableValue(Item))
  }

  if (Value !== null && typeof Value === 'object') {
    const Result: JsonObject = {}

    for (const Key of Object.keys(Value).sort()) {
      const Child = Value[Key]
      if (Child !== undefined) {
        Result[Key] = StableValue(Child)
      }
    }

    return Result
  }

  return Value
}

export function SerializeReleaseSbom(Document: JsonObject): string {
  return `${JSON.stringify(StableValue(Document), null, 2)}\n`
}

function FormatError(ErrorValue: unknown): string {
  return ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)
}

function Property(Name: string, Value: string): JsonObject {
  return { name: Name, value: Value }
}

function Properties(Value: JsonObject, Context: string): Map<string, string> {
  const Result = new Map<string, string>()
  const Entries = AsArray(Value.properties, `${Context}.properties`)

  for (const [Index, EntryValue] of Entries.entries()) {
    const Entry = AsObject(EntryValue, `${Context}.properties[${Index}]`)
    const Name = AsString(Entry.name, `${Context}.properties[${Index}].name`)
    const PropertyValue = AsString(Entry.value, `${Context}.properties[${Index}].value`)

    if (Result.has(Name)) {
      throw new Error(`${Context} contains duplicate property ${Name}`)
    }
    Result.set(Name, PropertyValue)
  }

  return Result
}

function AppendProperty(Value: JsonObject, Name: string, PropertyValue: string): void {
  const Existing = Value.properties
  const Entries = Existing === undefined ? [] : AsArray(Existing, 'component.properties')

  if (Entries.some(Entry => {
    const ObjectValue = AsObject(Entry, 'component property')
    return ObjectValue.name === Name
  })) {
    throw new Error(`component already contains property ${Name}`)
  }

  Value.properties = [...Entries, Property(Name, PropertyValue)]
}

function NormalizeDigest(Value: string, Context: string): string {
  const Normalized = Value.startsWith('sha256:') ? Value : `sha256:${Value}`

  if (!Sha256Digest.test(Normalized)) {
    throw new Error(`${Context} must be a lowercase sha256 digest`)
  }

  return Normalized
}

function HashForDigest(Digest: string): JsonObject {
  return { alg: 'SHA-256', content: Digest.slice('sha256:'.length) }
}

function ValidateIdentity(Identity: ReleaseIdentity, Kind: ReleaseSbomKind): void {
  const Contract = RoleContract(Identity.Role)
  if (!ImageName.test(Identity.Image) || Identity.Image.includes(':') || Identity.Image.includes('@')) {
    throw new Error('image must be a lowercase tagless and digestless OCI image name')
  }
  if (Identity.Image !== Contract.image) {
    throw new Error(`image for role ${Identity.Role} must be ${Contract.image}`)
  }
  if (!ReleaseValue.test(Identity.Version)) {
    throw new Error('version must be a non-empty release identifier')
  }
  if (!GitRevision.test(Identity.Revision)) {
    throw new Error('revision must be a 40-character lowercase Git commit')
  }
  if (Identity.Source !== OfficialSource) {
    throw new Error(`source must be ${OfficialSource}`)
  }
  if (!CanonicalTimestamp.test(Identity.Created) || Number.isNaN(Date.parse(Identity.Created))) {
    throw new Error('created must be an RFC 3339 UTC timestamp')
  }
  if (!WorkflowIdentity.test(Identity.Workflow)) {
    throw new Error('workflow must be an owner/repository GitHub Actions workflow identity')
  }

  const ExpectedWorkflow = Kind === 'platform' ? PlatformBuilderWorkflow : IndexBuilderWorkflow
  if (Identity.Workflow !== ExpectedWorkflow) {
    throw new Error(`${Kind} SBOM workflow must be ${ExpectedWorkflow}`)
  }

  if (Identity.Digest !== undefined) {
    NormalizeDigest(Identity.Digest, 'digest')
  } else {
    throw new Error(`${Kind} SBOM requires an immutable subject digest`)
  }
}

function ValidateCanonicalTimestamp(Value: string, Context: string): void {
  if (!CanonicalTimestamp.test(Value) || Number.isNaN(Date.parse(Value))) {
    throw new Error(`${Context} must be an RFC 3339 UTC timestamp`)
  }
}

function ValidateTimestampOrder(StartedOn: string, FinishedOn: string, Context: string): void {
  ValidateCanonicalTimestamp(StartedOn, `${Context} started_on`)
  ValidateCanonicalTimestamp(FinishedOn, `${Context} finished_on`)
  if (Date.parse(FinishedOn) < Date.parse(StartedOn)) {
    throw new Error(`${Context} timestamps are out of order`)
  }
}

function ValidateGeneratedTimestamp(Generated: string, NotBefore: string): void {
  ValidateCanonicalTimestamp(Generated, 'generated')
  if (Date.parse(Generated) < Date.parse(NotBefore)) {
    throw new Error('SBOM generation timestamp predates the subject build')
  }
}

function IdentitySeed(Identity: ReleaseIdentity, Kind: ReleaseSbomKind, Suffix: string): string {
  return [
    Kind,
    Identity.Role,
    Identity.Image,
    Identity.Digest ?? '',
    Identity.Version,
    Identity.Revision,
    Identity.Source,
    Identity.Created,
    Identity.Workflow,
    Suffix
  ].join('\0')
}

function DeterministicUuid(Seed: string): string {
  const Bytes = Crypto.createHash('sha256').update(Seed).digest().subarray(0, 16)
  Bytes[6] = (Bytes[6] & 0x0f) | 0x50
  Bytes[8] = (Bytes[8] & 0x3f) | 0x80
  const Hex = Bytes.toString('hex')

  return `${Hex.slice(0, 8)}-${Hex.slice(8, 12)}-${Hex.slice(12, 16)}-${Hex.slice(16, 20)}-${Hex.slice(20)}`
}

function RootProperties(Identity: ReleaseIdentity, Kind: ReleaseSbomKind): JsonObject[] {
  const Result = [
    Property('com.oxibelt.release.kind', Kind),
    Property('com.oxibelt.release.role', Identity.Role),
    Property('com.oxibelt.release.image', Identity.Image),
    Property('com.oxibelt.release.version', Identity.Version),
    Property('org.opencontainers.image.revision', Identity.Revision),
    Property('org.opencontainers.image.source', Identity.Source),
    Property('org.opencontainers.image.created', Identity.Created),
    Property('com.oxibelt.builder.workflow', Identity.Workflow),
    Property('com.oxibelt.attestation.predicate_type', CycloneDxPredicateType)
  ]

  if (Identity.Digest !== undefined) {
    Result.push(Property('com.oxibelt.oci.subject_digest', NormalizeDigest(Identity.Digest, 'digest')))
  }

  return Result
}

function RootComponent(Identity: ReleaseIdentity, Kind: ReleaseSbomKind, Suffix: string): JsonObject {
  const Seed = IdentitySeed(Identity, Kind, Suffix)
  const Root: JsonObject = {
    type: 'container',
    name: Identity.Image,
    version: Identity.Version,
    'bom-ref': `urn:uuid:${DeterministicUuid(Seed)}`,
    properties: RootProperties(Identity, Kind)
  }

  if (Identity.Digest !== undefined) {
    Root.hashes = [HashForDigest(NormalizeDigest(Identity.Digest, 'digest'))]
  }

  return Root
}

function HelperTools(Trivy: JsonObject | undefined): JsonObject {
  const Components: JsonValue[] = [{
    type: 'application',
    name: 'oxibelt-release-sbom',
    version: '1'
  }]

  if (Trivy !== undefined) {
    const MetadataValue = Trivy.metadata
    if (MetadataValue !== undefined) {
      const Metadata = AsObject(MetadataValue, 'Trivy metadata')
      if (Metadata.tools !== undefined) {
        const Tools = AsObject(Metadata.tools, 'Trivy metadata.tools')
        if (Tools.components !== undefined) {
          for (const [Index, ToolValue] of AsArray(Tools.components, 'Trivy metadata.tools.components').entries()) {
            Components.push(CloneObject(AsObject(ToolValue, `Trivy tool ${Index}`)))
          }
        }
      }
    }
  }

  return { components: Components }
}

function ParseBuildInputs(BuildInputs: JsonObject): BuildInputDetails {
  if (AsInteger(BuildInputs.schemaVersion, 'build inputs schemaVersion') !== 2) {
    throw new Error('build inputs schemaVersion must be 2')
  }

  const Role = AsImageRole(BuildInputs.role, 'build inputs role')
  const Contract = RoleContract(Role)
  const Image = AsString(BuildInputs.image, 'build inputs image')
  const DockerTarget = AsString(BuildInputs.dockerTarget, 'build inputs dockerTarget')
  const Binaries = StringArray(BuildInputs.binaries, 'build inputs binaries')
  const Entrypoint = StringArray(BuildInputs.entrypoint, 'build inputs entrypoint')
  const User = AsString(BuildInputs.user, 'build inputs user')
  const Ports = StringArray(BuildInputs.ports, 'build inputs ports')
  const EmbeddedAssets = BuildInputs.embeddedAssets
  if (
    Image !== Contract.image ||
    DockerTarget !== Contract.dockerTarget ||
    !SameStrings(Binaries, Contract.binaries) ||
    !SameStrings(Entrypoint, Contract.entrypoint) ||
    User !== Contract.user ||
    !SameStrings(Ports, Contract.ports) ||
    EmbeddedAssets !== Contract.embeddedAssets
  ) {
    throw new Error(`build inputs do not match the ${Role} role contract`)
  }
  const ArtifactArch = AsString(BuildInputs.artifactArch, 'build inputs artifactArch')
  const Platform = AsString(BuildInputs.platform, 'build inputs platform')
  if (typeof BuildInputs.rustTarget !== 'string') {
    throw new Error('build inputs rustTarget must be a string')
  }
  const RustTarget = BuildInputs.rustTarget
  const RustToolchainVersion = AsString(BuildInputs.rustToolchainVersion, 'build inputs rustToolchainVersion')
  const TargetCpu = AsOptionalString(BuildInputs.targetCpu, 'build inputs targetCpu')
  const ExpectedPlatform = ArtifactPlatforms.get(ArtifactArch)

  if (ExpectedPlatform === undefined) {
    throw new Error(`unsupported artifact architecture ${ArtifactArch}`)
  }
  if (
    Platform !== ExpectedPlatform.Platform ||
    RustTarget !== ExpectedPlatform.RustTarget ||
    TargetCpu !== ExpectedPlatform.TargetCpu
  ) {
    throw new Error(`artifact architecture ${ArtifactArch} does not match platform, Rust target, and target CPU`)
  }
  if (RustToolchainVersion !== RequiredRustToolchain) {
    throw new Error(`Rust toolchain must be ${RequiredRustToolchain}`)
  }

  const BaseImageValues = AsArray(BuildInputs.baseImages, 'build inputs baseImages')
  const RequiredStages = Role === 'standalone' || Role === 'dataplane'
    ? new Set(['builder', 'person-proof-ui', 'runtime'])
    : new Set(['builder', 'runtime'])
  if (BaseImageValues.length !== RequiredStages.size) {
    throw new Error(`build inputs for role ${Role} must contain exactly ${RequiredStages.size} base images`)
  }

  const SeenStages = new Set<string>()
  const BaseImages = BaseImageValues.map((BaseValue, Index) => {
    const Base = AsObject(BaseValue, `build inputs baseImages[${Index}]`)
    const BuildArgument = AsString(Base.buildArgument, `build inputs baseImages[${Index}].buildArgument`)
    const Stage = AsString(Base.stage, `build inputs baseImages[${Index}].stage`)
    const Reference = AsString(Base.reference, `build inputs baseImages[${Index}].reference`)
    const ExpectedBuildArgument = KnownBaseStages.get(Stage)

    if (!RequiredStages.has(Stage) || ExpectedBuildArgument === undefined || BuildArgument !== ExpectedBuildArgument) {
      throw new Error(`unexpected base-image stage or build argument ${Stage}/${BuildArgument}`)
    }
    if (SeenStages.has(Stage)) {
      throw new Error(`duplicate base-image stage ${Stage}`)
    }
    if (/\s|[\u0000-\u001f\u007f]/u.test(Reference)) {
      throw new Error(`base-image reference for ${Stage} contains unsafe characters`)
    }

    SeenStages.add(Stage)
    return { BuildArgument, Stage, Reference }
  })

  if (SeenStages.size !== RequiredStages.size) {
    throw new Error(`build inputs for role ${Role} are missing a required base-image stage`)
  }

  return { Role, ArtifactArch, Platform, RustTarget, TargetCpu, RustToolchainVersion, BaseImages }
}

function ProvenanceObject(BuildMetadata: JsonObject): JsonObject {
  const Raw = BuildMetadata['buildx.build.provenance']

  if (typeof Raw === 'string') {
    let Parsed: unknown
    try {
      Parsed = JSON.parse(Raw)
    } catch (ErrorValue) {
      throw new Error(`buildx provenance is not valid JSON: ${FormatError(ErrorValue)}`)
    }
    if (!IsJsonValue(Parsed)) {
      throw new Error('buildx provenance must contain finite JSON values')
    }
    return AsObject(Parsed, 'buildx provenance')
  }

  return AsObject(Raw, 'buildx provenance')
}

function MaterialFromValue(Value: JsonValue, Context: string): Material {
  const ObjectValue = AsObject(Value, Context)
  const Uri = AsString(ObjectValue.uri, `${Context}.uri`)
  const Digests = AsObject(ObjectValue.digest, `${Context}.digest`)
  const DigestValue = AsString(Digests.sha256, `${Context}.digest.sha256`)

  return { Uri, Digest: NormalizeDigest(DigestValue, `${Context}.digest.sha256`) }
}

function ProvenanceMaterials(BuildMetadata: JsonObject): Material[] {
  const Provenance = ProvenanceObject(BuildMetadata)
  const Candidates: Array<{ Value: JsonValue | undefined; Context: string }> = [
    { Value: Provenance.materials, Context: 'buildx provenance.materials' }
  ]
  const PredicateValue = Provenance.predicate

  if (PredicateValue !== undefined) {
    const Predicate = AsObject(PredicateValue, 'buildx provenance.predicate')
    Candidates.push({ Value: Predicate.materials, Context: 'buildx provenance.predicate.materials' })
    if (Predicate.buildDefinition !== undefined) {
      const Definition = AsObject(Predicate.buildDefinition, 'buildx provenance.predicate.buildDefinition')
      Candidates.push({
        Value: Definition.resolvedDependencies,
        Context: 'buildx provenance.predicate.buildDefinition.resolvedDependencies'
      })
    }
  }

  const MaterialByIdentity = new Map<string, Material>()
  for (const Candidate of Candidates) {
    if (Candidate.Value === undefined) {
      continue
    }
    for (const [Index, Value] of AsArray(Candidate.Value, Candidate.Context).entries()) {
      const MaterialValue = MaterialFromValue(Value, `${Candidate.Context}[${Index}]`)
      MaterialByIdentity.set(`${MaterialValue.Uri}\0${MaterialValue.Digest}`, MaterialValue)
    }
  }

  if (MaterialByIdentity.size === 0) {
    throw new Error('buildx provenance does not contain resolved materials')
  }

  return [...MaterialByIdentity.values()]
}

function ParseBuildTimestamps(Value: JsonValue, Context: string): BuildTimestamps {
  const Metadata = AsObject(Value, Context)
  const RawStartedOn = AsString(Metadata.buildStartedOn, `${Context}.buildStartedOn`)
  const RawFinishedOn = AsString(Metadata.buildFinishedOn, `${Context}.buildFinishedOn`)
  if (
    !Rfc3339Timestamp.test(RawStartedOn) ||
    !Rfc3339Timestamp.test(RawFinishedOn) ||
    Number.isNaN(Date.parse(RawStartedOn)) ||
    Number.isNaN(Date.parse(RawFinishedOn)) ||
    Date.parse(RawFinishedOn) < Date.parse(RawStartedOn)
  ) {
    throw new Error('BuildKit provenance timestamps are invalid or out of order')
  }

  const StartedOn = new Date(RawStartedOn).toISOString().replace('.000Z', 'Z')
  const FinishedOn = new Date(RawFinishedOn).toISOString().replace('.000Z', 'Z')

  return { StartedOn, FinishedOn }
}

function ProvenanceBuildTimestamps(BuildMetadata: JsonObject): BuildTimestamps {
  const Provenance = ProvenanceObject(BuildMetadata)
  const Candidates: BuildTimestamps[] = []
  if (Provenance.metadata !== undefined) {
    Candidates.push(ParseBuildTimestamps(Provenance.metadata, 'buildx provenance.metadata'))
  }
  if (Provenance.predicate !== undefined) {
    const Predicate = AsObject(Provenance.predicate, 'buildx provenance.predicate')
    if (Predicate.metadata !== undefined) {
      Candidates.push(ParseBuildTimestamps(Predicate.metadata, 'buildx provenance.predicate.metadata'))
    }
  }
  const Unique = new Map(Candidates.map(Value => [`${Value.StartedOn}\0${Value.FinishedOn}`, Value]))
  if (Unique.size !== 1) {
    throw new Error('BuildKit provenance must contain exactly one consistent build timestamp pair')
  }

  return [...Unique.values()][0]
}

function ValidateBuildDescriptor(
  BuildMetadata: JsonObject,
  Inputs: BuildInputDetails,
  ExpectedDigest: string | undefined
): string {
  const BuildDigest = NormalizeDigest(
    AsString(BuildMetadata['containerimage.digest'], 'build metadata containerimage.digest'),
    'build metadata containerimage.digest'
  )
  const Descriptor = AsObject(BuildMetadata['containerimage.descriptor'], 'build metadata containerimage.descriptor')
  const DescriptorDigest = NormalizeDigest(
    AsString(Descriptor.digest, 'build metadata containerimage.descriptor.digest'),
    'build metadata containerimage.descriptor.digest'
  )
  const DescriptorPlatform = AsObject(
    Descriptor.platform,
    'build metadata containerimage.descriptor.platform'
  )
  const [ExpectedOs, ExpectedArchitecture] = Inputs.Platform.split('/', 2)

  if (BuildDigest !== DescriptorDigest) {
    throw new Error('BuildKit image digest does not match its descriptor digest')
  }
  if (
    DescriptorPlatform.os !== ExpectedOs ||
    DescriptorPlatform.architecture !== ExpectedArchitecture
  ) {
    throw new Error('BuildKit image descriptor platform does not match the release build inputs')
  }
  if (ExpectedDigest !== undefined && BuildDigest !== NormalizeDigest(ExpectedDigest, 'digest')) {
    throw new Error('requested subject digest does not match the BuildKit image digest')
  }

  return BuildDigest
}

function ReferenceParts(Reference: string): { Name: string; Qualifier: string; PinnedDigest?: string } {
  const AtIndex = Reference.indexOf('@')
  const WithoutDigest = AtIndex === -1 ? Reference : Reference.slice(0, AtIndex)
  const LastSlash = WithoutDigest.lastIndexOf('/')
  const LastColon = WithoutDigest.lastIndexOf(':')

  if (LastColon <= LastSlash) {
    throw new Error(`base-image reference must include an explicit tag: ${Reference}`)
  }

  return {
    Name: WithoutDigest.slice(LastSlash + 1, LastColon),
    Qualifier: WithoutDigest.slice(LastColon + 1),
    PinnedDigest: AtIndex === -1
      ? undefined
      : NormalizeDigest(Reference.slice(AtIndex + 1), `pinned base-image reference ${Reference}`)
  }
}

function NormalizeDockerRepository(Value: string): string {
  const Segments = Value.toLowerCase().split('/')
  if (Segments.some(Segment => Segment.length === 0)) {
    throw new Error(`invalid Docker repository ${Value}`)
  }
  const First = Segments[0]
  const HasRegistry = First.includes('.') || First.includes(':') || First === 'localhost'
  const Registry = HasRegistry ? (First === 'index.docker.io' ? 'docker.io' : First) : 'docker.io'
  const Path = HasRegistry ? Segments.slice(1) : Segments

  if (Path.length === 1 && Registry === 'docker.io') {
    Path.unshift('library')
  }

  return `${Registry}/${Path.join('/')}`
}

function ParseDockerReference(Reference: string): { Repository: string; Qualifier: string } {
  const Parts = ReferenceParts(Reference)
  const RepositoryWithTag = Reference.slice(0, Reference.lastIndexOf(`:${Parts.Qualifier}`))
  const Repository = RepositoryWithTag.includes('@')
    ? RepositoryWithTag.slice(0, RepositoryWithTag.indexOf('@'))
    : RepositoryWithTag

  return { Repository: NormalizeDockerRepository(Repository), Qualifier: Parts.Qualifier.toLowerCase() }
}

function ParseDockerPurl(Uri: string): { Repository: string; Qualifier: string } | undefined {
  if (!Uri.toLowerCase().startsWith('pkg:docker/')) {
    return undefined
  }
  let Decoded: string
  try {
    Decoded = decodeURIComponent(Uri.slice('pkg:docker/'.length).split(/[?#]/u, 1)[0])
  } catch {
    throw new Error(`buildx material URI is not valid percent-encoding: ${Uri}`)
  }
  const Separator = Decoded.lastIndexOf('@')
  if (Separator <= 0 || Separator === Decoded.length - 1) {
    throw new Error(`buildx material URI is not a versioned Docker PURL: ${Uri}`)
  }

  return {
    Repository: NormalizeDockerRepository(Decoded.slice(0, Separator)),
    Qualifier: Decoded.slice(Separator + 1).toLowerCase()
  }
}

function MaterialMatchesReference(MaterialValue: Material, Reference: string): boolean {
  const Expected = ParseDockerReference(Reference)
  const Actual = ParseDockerPurl(MaterialValue.Uri)

  return Actual !== undefined &&
    Actual.Repository === Expected.Repository &&
    Actual.Qualifier === Expected.Qualifier
}

function ResolveBaseMaterials(Inputs: BuildInputDetails, BuildMetadata: JsonObject): Array<{
  Stage: string
  BuildArgument: string
  Reference: string
  Digest: string
}> {
  const Materials = ProvenanceMaterials(BuildMetadata)

  return Inputs.BaseImages.map(Base => {
    const Reference = ReferenceParts(Base.Reference)
    const Matches = Materials.filter(MaterialValue => MaterialMatchesReference(MaterialValue, Base.Reference))
    const Digests = [...new Set(Matches.map(MaterialValue => MaterialValue.Digest))]

    if (Digests.length !== 1) {
      throw new Error(`base image ${Base.Reference} must resolve to exactly one provenance digest`)
    }
    if (Reference.PinnedDigest !== undefined && Digests[0] !== Reference.PinnedDigest) {
      throw new Error(`base image ${Base.Reference} does not match its provenance digest`)
    }

    return { ...Base, Digest: Digests[0] }
  })
}

function BinaryComponents(Inventory: JsonObject, Version: string, Contract: ImageRoleContract): JsonObject[] {
  if (AsInteger(Inventory.schemaVersion, 'binary inventory schemaVersion') !== 1) {
    throw new Error('binary inventory schemaVersion must be 1')
  }

  const BinaryValues = AsArray(Inventory.binaries, 'binary inventory binaries')
  if (BinaryValues.length !== Contract.binaries.length) {
    throw new Error(`binary inventory for role ${Contract.role} must contain exactly ${Contract.binaries.length} binaries`)
  }

  const Seen = new Set<string>()
  const Result = BinaryValues.map((BinaryValue, Index) => {
    const Binary = AsObject(BinaryValue, `binary inventory binaries[${Index}]`)
    const Name = AsString(Binary.name, `binary inventory binaries[${Index}].name`)
    const Path = AsString(Binary.path, `binary inventory binaries[${Index}].path`)
    const BinaryVersion = AsString(Binary.version, `binary inventory binaries[${Index}].version`)
    const Hash = AsString(Binary.sha256, `binary inventory binaries[${Index}].sha256`)
    const ExpectedPath = KnownBinaries.get(Name)

    if (ExpectedPath === undefined || Path !== ExpectedPath || !Contract.binaries.includes(Name)) {
      throw new Error(`unexpected release binary or path ${Name}/${Path}`)
    }
    if (Seen.has(Name)) {
      throw new Error(`duplicate release binary ${Name}`)
    }
    if (BinaryVersion !== Version) {
      throw new Error(`release binary ${Name} version must be ${Version}`)
    }
    if (!Sha256.test(Hash)) {
      throw new Error(`release binary ${Name} sha256 must be 64 lowercase hexadecimal characters`)
    }

    Seen.add(Name)
    return {
      type: 'application',
      name: Name,
      version: BinaryVersion,
      'bom-ref': `urn:oxibelt:binary:${Name}:${Hash}`,
      hashes: [{ alg: 'SHA-256', content: Hash }],
      properties: [
        Property('com.oxibelt.release.binary.path', Path),
        Property('com.oxibelt.release.binary.name', Name)
      ]
    }
  })

  if (!SameStrings([...Seen].sort(), [...Contract.binaries].sort())) {
    throw new Error(`binary inventory does not match the ${Contract.role} role contract`)
  }

  return Result.sort((Left, Right) => AsString(Left.name, 'binary name').localeCompare(AsString(Right.name, 'binary name')))
}

function BaseComponents(BaseMaterials: ReturnType<typeof ResolveBaseMaterials>): JsonObject[] {
  return BaseMaterials.map(Base => ({
    type: 'container',
    name: Base.Reference,
    version: Base.Reference,
    'bom-ref': `urn:oxibelt:base:${Base.Stage}:${Base.Digest}`,
    hashes: [HashForDigest(Base.Digest)],
    properties: [
      Property('com.oxibelt.release.base.stage', Base.Stage),
      Property('com.oxibelt.release.base.build_argument', Base.BuildArgument),
      Property('com.oxibelt.release.base.reference', Base.Reference),
      Property('com.oxibelt.release.base.digest', Base.Digest)
    ]
  })).sort((Left, Right) => AsString(Left['bom-ref'], 'base bom-ref').localeCompare(AsString(Right['bom-ref'], 'base bom-ref')))
}

function PrefixComponent(ComponentValue: JsonObject, Prefix: string, RefMap: Map<string, string>): JsonObject {
  const Component = CloneObject(ComponentValue)
  const OriginalRef = AsString(Component['bom-ref'], 'component bom-ref')
  const NewRef = `${Prefix}${OriginalRef}`

  if (RefMap.has(OriginalRef)) {
    throw new Error(`duplicate component bom-ref ${OriginalRef}`)
  }
  RefMap.set(OriginalRef, NewRef)
  Component['bom-ref'] = NewRef

  if (Component.components !== undefined) {
    Component.components = AsArray(Component.components, `component ${OriginalRef}.components`).map(Child =>
      PrefixComponent(AsObject(Child, `child of ${OriginalRef}`), Prefix, RefMap)
    )
  }

  return Component
}

function RewriteDependencies(
  DependencyValues: JsonValue[],
  RefMap: Map<string, string>,
  OriginalRootRef: string | undefined,
  NewRootRef: string,
  Prefix: string
): JsonObject[] {
  return DependencyValues.map((DependencyValue, Index) => {
    const Dependency = AsObject(DependencyValue, `dependencies[${Index}]`)
    const OriginalRef = AsString(Dependency.ref, `dependencies[${Index}].ref`)
    const RewriteRef = (Value: string): string => {
      if (OriginalRootRef !== undefined && Value === OriginalRootRef) {
        return NewRootRef
      }
      return RefMap.get(Value) ?? `${Prefix}${Value}`
    }
    const Result: JsonObject = { ref: RewriteRef(OriginalRef) }

    if (Dependency.dependsOn !== undefined) {
      Result.dependsOn = AsArray(Dependency.dependsOn, `dependencies[${Index}].dependsOn`).map((Value, ChildIndex) =>
        RewriteRef(AsString(Value, `dependencies[${Index}].dependsOn[${ChildIndex}]`))
      )
    }

    return Result
  })
}

function TrivyInventory(Trivy: JsonObject, RootRef: string): { Components: JsonObject[]; Dependencies: JsonObject[]; RootDependencies: string[] } {
  if (Trivy.bomFormat !== 'CycloneDX' || Trivy.specVersion !== CycloneDxSpecVersion) {
    throw new Error(`Trivy input must be CycloneDX ${CycloneDxSpecVersion}`)
  }

  const Components = AsArray(Trivy.components, 'Trivy components')
  const Metadata = AsObject(Trivy.metadata, 'Trivy metadata')
  const OriginalRootValue = Metadata.component
  const OriginalRootRef = OriginalRootValue === undefined
    ? undefined
    : AsString(AsObject(OriginalRootValue, 'Trivy root component')['bom-ref'], 'Trivy root component bom-ref')
  const RefMap = new Map<string, string>()
  const PrefixedComponents = Components.map((ComponentValue, Index) =>
    PrefixComponent(AsObject(ComponentValue, `Trivy components[${Index}]`), 'trivy:', RefMap)
  )
  const DependencyValues = Trivy.dependencies === undefined ? [] : AsArray(Trivy.dependencies, 'Trivy dependencies')
  const Rewritten = RewriteDependencies(DependencyValues, RefMap, OriginalRootRef, RootRef, 'trivy:')
  const OriginalRootDependency = Rewritten.find(Dependency => Dependency.ref === RootRef)
  const RootDependencies = OriginalRootDependency === undefined || OriginalRootDependency.dependsOn === undefined
    ? PrefixedComponents.map(Component => AsString(Component['bom-ref'], 'Trivy component bom-ref'))
    : AsArray(OriginalRootDependency.dependsOn, 'rewritten Trivy root dependsOn').map((Value, Index) =>
      AsString(Value, `rewritten Trivy root dependsOn[${Index}]`)
    )

  return {
    Components: PrefixedComponents,
    Dependencies: Rewritten.filter(Dependency => Dependency.ref !== RootRef),
    RootDependencies
  }
}

function SortBom(Document: JsonObject): JsonObject {
  const Components = AsArray(Document.components, 'components').map((Value, Index) =>
    AsObject(Value, `components[${Index}]`)
  )
  Components.sort((Left, Right) =>
    AsString(Left['bom-ref'], 'component bom-ref').localeCompare(AsString(Right['bom-ref'], 'component bom-ref'))
  )
  Document.components = Components

  const Dependencies = AsArray(Document.dependencies, 'dependencies').map((Value, Index) => {
    const Dependency = AsObject(Value, `dependencies[${Index}]`)
    if (Dependency.dependsOn !== undefined) {
      const DependsOn = AsArray(Dependency.dependsOn, `dependencies[${Index}].dependsOn`).map((Ref, RefIndex) =>
        AsString(Ref, `dependencies[${Index}].dependsOn[${RefIndex}]`)
      )
      Dependency.dependsOn = [...new Set(DependsOn)].sort()
    }
    return Dependency
  })
  Dependencies.sort((Left, Right) => AsString(Left.ref, 'dependency ref').localeCompare(AsString(Right.ref, 'dependency ref')))
  Document.dependencies = Dependencies

  return Document
}

export function BuildPlatformSbom(Options: PlatformSbomOptions): JsonObject {
  const Identity: ReleaseIdentity = Options
  ValidateIdentity(Identity, 'platform')
  const Inputs = ParseBuildInputs(Options.BuildInputs)
  if (Inputs.Role !== Options.Role) {
    throw new Error(`build input role ${Inputs.Role} does not match requested role ${Options.Role}`)
  }
  const Contract = RoleContract(Options.Role)
  ValidateBuildDescriptor(Options.BuildMetadata, Inputs, Options.Digest)
  const BuildTimes = ProvenanceBuildTimestamps(Options.BuildMetadata)
  ValidateGeneratedTimestamp(Options.Generated, BuildTimes.FinishedOn)
  const Materials = ResolveBaseMaterials(Inputs, Options.BuildMetadata)
  const PlatformIdentity = `${Inputs.ArtifactArch}\0${BuildTimes.StartedOn}\0${BuildTimes.FinishedOn}`
  const Root = RootComponent(Identity, 'platform', PlatformIdentity)
  const RootRef = AsString(Root['bom-ref'], 'root bom-ref')
  const Inventory = TrivyInventory(Options.Trivy, RootRef)
  const Bases = BaseComponents(Materials)
  const Binaries = BinaryComponents(Options.BinaryInventory, Options.Version, Contract)
  const RustComponent: JsonObject = {
    type: 'application',
    name: 'rustc',
    version: Inputs.RustToolchainVersion,
    'bom-ref': `urn:oxibelt:toolchain:rust:${Inputs.RustToolchainVersion}`,
    properties: [Property('com.oxibelt.release.toolchain', 'rust')]
  }
  const RootPropertyValues = AsArray(Root.properties, 'root properties')
  RootPropertyValues.push(Property('com.oxibelt.release.platform', Inputs.Platform))
  RootPropertyValues.push(Property('com.oxibelt.release.artifact_arch', Inputs.ArtifactArch))
  RootPropertyValues.push(Property('com.oxibelt.release.rust_toolchain_version', Inputs.RustToolchainVersion))
  RootPropertyValues.push(Property('com.oxibelt.build.started_on', BuildTimes.StartedOn))
  RootPropertyValues.push(Property('com.oxibelt.build.finished_on', BuildTimes.FinishedOn))
  if (Inputs.TargetCpu !== undefined) {
    RootPropertyValues.push(Property('com.oxibelt.release.target_cpu', Inputs.TargetCpu))
  }

  const DirectRefs = [
    ...Inventory.RootDependencies,
    ...Bases.map(Component => AsString(Component['bom-ref'], 'base bom-ref')),
    ...Binaries.map(Component => AsString(Component['bom-ref'], 'binary bom-ref')),
    AsString(RustComponent['bom-ref'], 'Rust toolchain bom-ref')
  ]
  const Document: JsonObject = {
    bomFormat: 'CycloneDX',
    specVersion: CycloneDxSpecVersion,
    serialNumber: `urn:uuid:${DeterministicUuid(IdentitySeed(Identity, 'platform', `${PlatformIdentity}\0${Options.Generated}\0document`))}`,
    version: 1,
    metadata: {
      timestamp: Options.Generated,
      tools: HelperTools(Options.Trivy),
      component: Root
    },
    components: [...Inventory.Components, ...Bases, ...Binaries, RustComponent],
    dependencies: [
      { ref: RootRef, dependsOn: DirectRefs },
      ...Inventory.Dependencies,
      ...Binaries.map(Binary => ({
        ref: AsString(Binary['bom-ref'], 'binary bom-ref'),
        dependsOn: [AsString(RustComponent['bom-ref'], 'Rust toolchain bom-ref')]
      }))
    ]
  }

  const Result = SortBom(Document)
  ValidateReleaseSbom(Result, {
    Kind: 'platform',
    Role: Options.Role,
    Digest: Options.Digest,
    Revision: Options.Revision,
    Workflow: Options.Workflow
  })
  return Result
}

function AllComponents(Document: JsonObject): JsonObject[] {
  const Result: JsonObject[] = []
  const Visit = (Component: JsonObject): void => {
    Result.push(Component)
    if (Component.components !== undefined) {
      for (const Child of AsArray(Component.components, 'nested components')) {
        Visit(AsObject(Child, 'nested component'))
      }
    }
  }

  for (const ComponentValue of AsArray(Document.components, 'components')) {
    Visit(AsObject(ComponentValue, 'component'))
  }

  return Result
}

function ValidateUniqueReferences(Document: JsonObject, RootRef: string): void {
  const ComponentRefs = new Set<string>([RootRef])

  for (const Component of AllComponents(Document)) {
    const Ref = AsString(Component['bom-ref'], 'component bom-ref')
    if (ComponentRefs.has(Ref)) {
      throw new Error(`duplicate CycloneDX bom-ref ${Ref}`)
    }
    ComponentRefs.add(Ref)
  }

  const DependencyRefs = new Set<string>()
  for (const [Index, DependencyValue] of AsArray(Document.dependencies, 'dependencies').entries()) {
    const Dependency = AsObject(DependencyValue, `dependencies[${Index}]`)
    const Ref = AsString(Dependency.ref, `dependencies[${Index}].ref`)
    if (!ComponentRefs.has(Ref)) {
      throw new Error(`dependency ref ${Ref} does not identify a component`)
    }
    if (DependencyRefs.has(Ref)) {
      throw new Error(`duplicate dependency entry for ${Ref}`)
    }
    DependencyRefs.add(Ref)

    if (Dependency.dependsOn !== undefined) {
      for (const Value of AsArray(Dependency.dependsOn, `dependencies[${Index}].dependsOn`)) {
        const ChildRef = AsString(Value, `dependency ${Ref} child ref`)
        if (!ComponentRefs.has(ChildRef)) {
          throw new Error(`dependency child ref ${ChildRef} does not identify a component`)
        }
      }
    }
  }

  if (!DependencyRefs.has(RootRef)) {
    throw new Error('CycloneDX dependency graph must contain the metadata component')
  }
}

function ValidateComponentSha256(Component: JsonObject, ExpectedDigest: string, Context: string): void {
  const Normalized = NormalizeDigest(ExpectedDigest, `${Context} digest`)
  const Hashes = AsArray(Component.hashes, `${Context} hashes`)
  if (Hashes.length !== 1) {
    throw new Error(`${Context} must have exactly one SHA-256 hash`)
  }
  const Hash = AsObject(Hashes[0], `${Context} hash`)
  if (Hash.alg !== 'SHA-256' || Hash.content !== Normalized.slice('sha256:'.length)) {
    throw new Error(`${Context} hash does not match its digest`)
  }
}

function ValidateBuildTimestampProperties(PropertiesValue: Map<string, string>, Context: string): BuildTimestamps {
  const StartedOn = PropertiesValue.get('com.oxibelt.build.started_on') ?? ''
  const FinishedOn = PropertiesValue.get('com.oxibelt.build.finished_on') ?? ''
  if (
    !CanonicalTimestamp.test(StartedOn) ||
    !CanonicalTimestamp.test(FinishedOn) ||
    Number.isNaN(Date.parse(StartedOn)) ||
    Number.isNaN(Date.parse(FinishedOn)) ||
    Date.parse(FinishedOn) < Date.parse(StartedOn)
  ) {
    throw new Error(`${Context} BuildKit timestamps are missing, invalid, or out of order`)
  }

  return { StartedOn, FinishedOn }
}

function ValidateRequiredPlatformComponents(Document: JsonObject, Version: string, Role: ImageRole): void {
  const Contract = RoleContract(Role)
  const RequiredBaseStages = Role === 'standalone' || Role === 'dataplane'
    ? new Set(['builder', 'person-proof-ui', 'runtime'])
    : new Set(['builder', 'runtime'])
  const Components = AllComponents(Document)
  const BinaryNames = new Set<string>()
  const BaseStages = new Set<string>()
  let RustToolchains = 0

  for (const Component of Components) {
    if (Component.properties === undefined) {
      continue
    }
    const ComponentProperties = Properties(Component, `component ${String(Component['bom-ref'])}`)
    const BinaryName = ComponentProperties.get('com.oxibelt.release.binary.name')
    if (BinaryName !== undefined) {
      const ExpectedPath = KnownBinaries.get(BinaryName)
      if (
        ExpectedPath === undefined ||
        !Contract.binaries.includes(BinaryName) ||
        ComponentProperties.get('com.oxibelt.release.binary.path') !== ExpectedPath ||
        Component.type !== 'application' ||
        Component.name !== BinaryName
      ) {
        throw new Error(`invalid release binary component ${BinaryName}`)
      }
      if (Component.version !== Version) {
        throw new Error(`release binary component ${BinaryName} has the wrong version`)
      }
      const Hashes = AsArray(Component.hashes, `binary ${BinaryName} hashes`)
      const BinaryHash = Hashes.length === 1
        ? AsObject(Hashes[0], `binary ${BinaryName} hash`)
        : {}
      if (
        Hashes.length !== 1 ||
        BinaryHash.alg !== 'SHA-256' ||
        !Sha256.test(AsString(BinaryHash.content, `binary ${BinaryName} hash content`))
      ) {
        throw new Error(`release binary component ${BinaryName} must have exactly one SHA-256 hash`)
      }
      if (BinaryNames.has(BinaryName)) {
        throw new Error(`duplicate release binary component ${BinaryName}`)
      }
      BinaryNames.add(BinaryName)
    }

    const BaseStage = ComponentProperties.get('com.oxibelt.release.base.stage')
    if (BaseStage !== undefined) {
      const ExpectedBuildArgument = KnownBaseStages.get(BaseStage)
      const BuildArgument = ComponentProperties.get('com.oxibelt.release.base.build_argument')
      const Reference = ComponentProperties.get('com.oxibelt.release.base.reference')
      if (
        !RequiredBaseStages.has(BaseStage) ||
        ExpectedBuildArgument === undefined ||
        BuildArgument !== ExpectedBuildArgument ||
        Reference === undefined ||
        BaseStages.has(BaseStage) ||
        Component.type !== 'container' ||
        Component.name !== Reference ||
        Component.version !== Reference
      ) {
        throw new Error(`invalid or duplicate base-image component ${BaseStage}`)
      }
      ParseDockerReference(Reference)
      const Digest = ComponentProperties.get('com.oxibelt.release.base.digest') ?? ''
      ValidateComponentSha256(Component, Digest, `base image ${BaseStage}`)
      BaseStages.add(BaseStage)
    }

    if (ComponentProperties.get('com.oxibelt.release.toolchain') === 'rust') {
      if (Component.name !== 'rustc' || Component.version !== RequiredRustToolchain) {
        throw new Error('Rust toolchain component does not match the release contract')
      }
      RustToolchains += 1
    }
  }

  if (
    BinaryNames.size !== Contract.binaries.length ||
    BaseStages.size !== RequiredBaseStages.size ||
    RustToolchains !== 1
  ) {
    throw new Error('platform SBOM is missing required binaries, base images, or Rust toolchain')
  }
}

function ValidateRoot(
  Document: JsonObject,
  Options: VerifySbomOptions
): { Root: JsonObject; Properties: Map<string, string>; Timestamp: string } {
  if (Document.bomFormat !== 'CycloneDX' || Document.specVersion !== CycloneDxSpecVersion || Document.version !== 1) {
    throw new Error(`release SBOM must be CycloneDX ${CycloneDxSpecVersion} document version 1`)
  }
  if (
    typeof Document.serialNumber !== 'string' ||
    !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(Document.serialNumber)
  ) {
    throw new Error('release SBOM must contain a deterministic UUID serial number')
  }
  const Metadata = AsObject(Document.metadata, 'metadata')
  const Timestamp = AsString(Metadata.timestamp, 'metadata.timestamp')
  AsObject(Metadata.tools, 'metadata.tools')
  const Root = AsObject(Metadata.component, 'metadata.component')
  const RootRef = AsString(Root['bom-ref'], 'metadata.component bom-ref')
  const RootPropertyMap = Properties(Root, 'metadata.component')

  if (Root.type !== 'container') {
    throw new Error('metadata component must be a container')
  }
  if (RootPropertyMap.get('com.oxibelt.release.kind') !== Options.Kind) {
    throw new Error(`release SBOM kind must be ${Options.Kind}`)
  }
  if (RootPropertyMap.get('com.oxibelt.attestation.predicate_type') !== CycloneDxPredicateType) {
    throw new Error(`release SBOM predicate type must be ${CycloneDxPredicateType}`)
  }
  const Role = AsImageRole(RootPropertyMap.get('com.oxibelt.release.role'), 'release SBOM role')
  const Contract = RoleContract(Role)
  if (Options.Role !== undefined && Options.Role !== Role) {
    throw new Error(`release SBOM role must be ${Options.Role}`)
  }
  if (RootPropertyMap.get('com.oxibelt.release.image') !== Contract.image || Root.name !== Contract.image) {
    throw new Error(`release SBOM image for role ${Role} must be ${Contract.image}`)
  }
  if (RootPropertyMap.get('org.opencontainers.image.source') !== OfficialSource) {
    throw new Error(`release SBOM source must be ${OfficialSource}`)
  }
  const Created = RootPropertyMap.get('org.opencontainers.image.created') ?? ''
  if (!CanonicalTimestamp.test(Timestamp) || Number.isNaN(Date.parse(Timestamp))) {
    throw new Error('release SBOM generation timestamp is invalid')
  }
  if (!CanonicalTimestamp.test(Created) || Number.isNaN(Date.parse(Created))) {
    throw new Error('release SBOM subject creation timestamp is invalid')
  }
  const Revision = RootPropertyMap.get('org.opencontainers.image.revision') ?? ''
  if (!GitRevision.test(Revision) || (Options.Revision !== undefined && Revision !== Options.Revision)) {
    throw new Error('release SBOM source revision is invalid or unexpected')
  }
  const Workflow = RootPropertyMap.get('com.oxibelt.builder.workflow') ?? ''
  const ExpectedWorkflow = Options.Kind === 'platform' ? PlatformBuilderWorkflow : IndexBuilderWorkflow
  if (Workflow !== ExpectedWorkflow || (Options.Workflow !== undefined && Workflow !== Options.Workflow)) {
    throw new Error('release SBOM builder workflow is invalid or unexpected')
  }
  const Version = RootPropertyMap.get('com.oxibelt.release.version') ?? ''
  if (!ReleaseValue.test(Version) || Root.version !== Version || (Options.Version !== undefined && Version !== Options.Version)) {
    throw new Error('release SBOM version is invalid or unexpected')
  }
  if (Options.Image !== undefined && Options.Image !== Contract.image) {
    throw new Error(`expected image does not match the official ${Role} image`)
  }
  const SubjectDigest = RootPropertyMap.get('com.oxibelt.oci.subject_digest')
  if (SubjectDigest !== undefined) {
    NormalizeDigest(SubjectDigest, 'embedded subject digest')
    if (Options.Digest !== undefined && SubjectDigest !== NormalizeDigest(Options.Digest, 'expected digest')) {
      throw new Error('embedded subject digest does not match the expected digest')
    }
    ValidateComponentSha256(Root, SubjectDigest, 'root component')
  } else {
    throw new Error('release SBOM is missing its immutable subject digest')
  }

  ValidateUniqueReferences(Document, RootRef)
  return { Root, Properties: RootPropertyMap, Timestamp }
}

export function ValidateReleaseSbom(Document: JsonObject, Options: VerifySbomOptions): void {
  const Validated = ValidateRoot(Document, Options)
  const Role = AsImageRole(Validated.Properties.get('com.oxibelt.release.role'), 'release SBOM role')

  if (Options.Kind === 'platform') {
    const ArtifactArch = Validated.Properties.get('com.oxibelt.release.artifact_arch') ?? ''
    const Platform = Validated.Properties.get('com.oxibelt.release.platform') ?? ''
    const TargetCpu = Validated.Properties.get('com.oxibelt.release.target_cpu')
    const Expected = ArtifactPlatforms.get(ArtifactArch)
    if (Expected === undefined || Platform !== Expected.Platform || TargetCpu !== Expected.TargetCpu) {
      throw new Error('platform SBOM architecture metadata is invalid')
    }
    if (Validated.Properties.get('com.oxibelt.release.rust_toolchain_version') !== RequiredRustToolchain) {
      throw new Error(`platform SBOM Rust toolchain must be ${RequiredRustToolchain}`)
    }
    const BuildTimes = ValidateBuildTimestampProperties(Validated.Properties, 'platform SBOM')
    if (Date.parse(Validated.Timestamp) < Date.parse(BuildTimes.FinishedOn)) {
      throw new Error('platform SBOM generation timestamp predates the image build')
    }
    ValidateRequiredPlatformComponents(
      Document,
      Validated.Properties.get('com.oxibelt.release.version') ?? '',
      Role
    )
    return
  }

  if (
    Validated.Properties.get('com.oxibelt.release.platform') !== 'multi' ||
    Validated.Properties.get('com.oxibelt.release.artifact_arch') !== 'multi'
  ) {
    throw new Error('index SBOM root must use multi architecture metadata')
  }
  const IndexBuildTimes = ValidateBuildTimestampProperties(Validated.Properties, 'index SBOM')
  if (Date.parse(Validated.Timestamp) < Date.parse(IndexBuildTimes.FinishedOn)) {
    throw new Error('index SBOM generation timestamp predates index composition')
  }

  const Components = AllComponents(Document)
  const ChildRoots = Components.flatMap(Component => {
    if (Component.properties === undefined) {
      return []
    }
    const ComponentProperties = Properties(Component, `component ${String(Component['bom-ref'])}`)
    return ComponentProperties.get('com.oxibelt.release.index_child') === 'true'
      ? [{ Component, Properties: ComponentProperties }]
      : []
  })
  const ChildArchs = ChildRoots.map(Child => Child.Properties.get('com.oxibelt.release.artifact_arch') ?? '').sort()

  if (JSON.stringify(ChildArchs) !== JSON.stringify([...RequiredIndexArtifactArchs].sort())) {
    throw new Error('index SBOM must contain exactly amd64, arm64, and riscv64 platform roots')
  }

  const IndexVersion = Validated.Properties.get('com.oxibelt.release.version') ?? ''
  const IndexRevision = Validated.Properties.get('org.opencontainers.image.revision') ?? ''
  const IndexCreated = Validated.Properties.get('org.opencontainers.image.created') ?? ''
  const IndexRootRef = AsString(Validated.Root['bom-ref'], 'index root bom-ref')
  const RootDependency = AsArray(Document.dependencies, 'index dependencies')
    .map((Value, Index) => AsObject(Value, `index dependencies[${Index}]`))
    .find(Dependency => Dependency.ref === IndexRootRef)
  const DirectChildren = RootDependency === undefined
    ? []
    : AsArray(RootDependency.dependsOn, 'index root dependsOn').map((Value, Index) =>
      AsString(Value, `index root dependsOn[${Index}]`)
    ).sort()
  const ExpectedChildRefs = ChildRoots.map(Child => AsString(Child.Component['bom-ref'], 'index child bom-ref')).sort()
  if (JSON.stringify(DirectChildren) !== JSON.stringify(ExpectedChildRefs)) {
    throw new Error('index SBOM root must depend directly on exactly the three platform roots')
  }

  const ChildDigests = new Set<string>()
  for (const Child of ChildRoots) {
    const ArtifactArch = Child.Properties.get('com.oxibelt.release.artifact_arch') ?? ''
    const ExpectedPlatform = ArtifactPlatforms.get(ArtifactArch)
    const ChildDigest = Child.Properties.get('com.oxibelt.oci.subject_digest') ?? ''
    if (
      Child.Component.type !== 'container' ||
      ExpectedPlatform === undefined ||
      Child.Properties.get('com.oxibelt.release.kind') !== 'platform' ||
      Child.Properties.get('com.oxibelt.release.platform') !== ExpectedPlatform.Platform ||
      Child.Properties.get('com.oxibelt.release.target_cpu') !== ExpectedPlatform.TargetCpu ||
      Child.Properties.get('com.oxibelt.release.version') !== IndexVersion ||
      Child.Properties.get('org.opencontainers.image.revision') !== IndexRevision ||
      Child.Properties.get('org.opencontainers.image.created') !== IndexCreated ||
      Child.Properties.get('org.opencontainers.image.source') !== OfficialSource ||
      Child.Properties.get('com.oxibelt.builder.workflow') !== PlatformBuilderWorkflow
    ) {
      throw new Error(`index platform root ${ArtifactArch} does not match the index release identity`)
    }
    const NormalizedChildDigest = NormalizeDigest(ChildDigest, `index platform ${ArtifactArch} subject digest`)
    if (ChildDigests.has(NormalizedChildDigest)) {
      throw new Error(`index platforms must not share subject digest ${NormalizedChildDigest}`)
    }
    ValidateComponentSha256(Child.Component, NormalizedChildDigest, `index platform ${ArtifactArch}`)
    ValidateBuildTimestampProperties(Child.Properties, `index platform ${ArtifactArch}`)
    ChildDigests.add(NormalizedChildDigest)

    const Prefix = `platform:${ArtifactArch}:`
    const PlatformComponents = Components.filter(Component =>
      AsString(Component['bom-ref'], 'index component bom-ref').startsWith(Prefix) && Component !== Child.Component
    )
    ValidateRequiredPlatformComponents({ components: PlatformComponents }, IndexVersion, Role)
  }
}

function NamespacePlatformDocument(Document: JsonObject, ArtifactArch: string): { Components: JsonObject[]; Dependencies: JsonObject[]; ChildRootRef: string } {
  const Metadata = AsObject(Document.metadata, 'platform metadata')
  const OriginalRoot = AsObject(Metadata.component, 'platform metadata.component')
  const OriginalRootRef = AsString(OriginalRoot['bom-ref'], 'platform root bom-ref')
  const Prefix = `platform:${ArtifactArch}:`
  const RefMap = new Map<string, string>()
  const ChildRoot = PrefixComponent(OriginalRoot, Prefix, RefMap)
  AppendProperty(ChildRoot, 'com.oxibelt.release.index_child', 'true')
  const Children = AsArray(Document.components, 'platform components').map((Value, Index) =>
    PrefixComponent(AsObject(Value, `platform components[${Index}]`), Prefix, RefMap)
  )
  const Dependencies = RewriteDependencies(
    AsArray(Document.dependencies, 'platform dependencies'),
    RefMap,
    undefined,
    '',
    Prefix
  )

  return {
    Components: [ChildRoot, ...Children],
    Dependencies,
    ChildRootRef: RefMap.get(OriginalRootRef) ?? `${Prefix}${OriginalRootRef}`
  }
}

export function BuildIndexSbom(Options: IndexSbomOptions): JsonObject {
  const Identity: ReleaseIdentity = Options
  ValidateIdentity(Identity, 'index')
  ValidateTimestampOrder(Options.BuildStartedOn, Options.BuildFinishedOn, 'index build')
  ValidateGeneratedTimestamp(Options.Generated, Options.BuildFinishedOn)
  if (Options.PlatformSboms.length !== RequiredIndexArtifactArchs.length) {
    throw new Error(`index SBOM requires exactly ${RequiredIndexArtifactArchs.length} platform SBOMs`)
  }

  const ByArch = new Map<string, JsonObject>()
  const ChildDigests = new Set<string>()
  for (const PlatformSbom of Options.PlatformSboms) {
    ValidateReleaseSbom(PlatformSbom, {
      Kind: 'platform',
      Role: Options.Role,
      Revision: Options.Revision,
      Version: Options.Version,
      Image: Options.Image,
      Workflow: PlatformBuilderWorkflow
    })
    const Root = AsObject(AsObject(PlatformSbom.metadata, 'platform metadata').component, 'platform root')
    const RootPropertyMap = Properties(Root, 'platform root')
    const ArtifactArch = RootPropertyMap.get('com.oxibelt.release.artifact_arch') ?? ''
    const SubjectDigest = RootPropertyMap.get('com.oxibelt.oci.subject_digest')

    if (!RequiredIndexArtifactArchs.includes(ArtifactArch) || ByArch.has(ArtifactArch)) {
      throw new Error(`unexpected or duplicate index platform ${ArtifactArch}`)
    }
    if (SubjectDigest === undefined) {
      throw new Error(`index platform ${ArtifactArch} is missing its immutable subject digest`)
    }
    const NormalizedSubjectDigest = NormalizeDigest(SubjectDigest, `index platform ${ArtifactArch} subject digest`)
    if (ChildDigests.has(NormalizedSubjectDigest)) {
      throw new Error(`index platforms must not share subject digest ${NormalizedSubjectDigest}`)
    }
    if (
      RootPropertyMap.get('org.opencontainers.image.created') !== Options.Created ||
      RootPropertyMap.get('org.opencontainers.image.source') !== Options.Source
    ) {
      throw new Error(`platform ${ArtifactArch} release identity does not match the index`)
    }
    ChildDigests.add(NormalizedSubjectDigest)
    ByArch.set(ArtifactArch, PlatformSbom)
  }

  const ChildIdentity = RequiredIndexArtifactArchs.map(ArtifactArch => {
    const Document = ByArch.get(ArtifactArch)
    if (Document === undefined) {
      throw new Error(`missing index platform ${ArtifactArch}`)
    }
    return `${ArtifactArch}\0${AsString(Document.serialNumber, `platform ${ArtifactArch} serial number`)}`
  }).join('\0')
  const IndexIdentity = `${Options.BuildStartedOn}\0${Options.BuildFinishedOn}\0${ChildIdentity}`
  const Root = RootComponent(Identity, 'index', `multi-architecture\0${IndexIdentity}`)
  const RootRef = AsString(Root['bom-ref'], 'index root bom-ref')
  const Components: JsonObject[] = []
  const Dependencies: JsonObject[] = []
  const ChildRootRefs: string[] = []

  for (const ArtifactArch of RequiredIndexArtifactArchs) {
    const PlatformSbom = ByArch.get(ArtifactArch)
    if (PlatformSbom === undefined) {
      throw new Error(`missing index platform ${ArtifactArch}`)
    }
    const Namespaced = NamespacePlatformDocument(PlatformSbom, ArtifactArch)
    Components.push(...Namespaced.Components)
    Dependencies.push(...Namespaced.Dependencies)
    ChildRootRefs.push(Namespaced.ChildRootRef)
  }

  const RootPropertiesValue = AsArray(Root.properties, 'index root properties')
  RootPropertiesValue.push(Property('com.oxibelt.release.platform', 'multi'))
  RootPropertiesValue.push(Property('com.oxibelt.release.artifact_arch', 'multi'))
  RootPropertiesValue.push(Property('com.oxibelt.build.started_on', Options.BuildStartedOn))
  RootPropertiesValue.push(Property('com.oxibelt.build.finished_on', Options.BuildFinishedOn))

  const Document: JsonObject = SortBom({
    bomFormat: 'CycloneDX',
    specVersion: CycloneDxSpecVersion,
    serialNumber: `urn:uuid:${DeterministicUuid(IdentitySeed(Identity, 'index', `${IndexIdentity}\0${Options.Generated}\0document`))}`,
    version: 1,
    metadata: {
      timestamp: Options.Generated,
      tools: HelperTools(undefined),
      component: Root
    },
    components: Components,
    dependencies: [{ ref: RootRef, dependsOn: ChildRootRefs }, ...Dependencies]
  })

  ValidateReleaseSbom(Document, {
    Kind: 'index',
    Role: Options.Role,
    Digest: Options.Digest,
    Revision: Options.Revision,
    Workflow: Options.Workflow
  })
  return Document
}

function ParseCli(Argv: string[]): CliParameters {
  const ModeValue = Argv[2]
  if (ModeValue !== 'platform' && ModeValue !== 'index' && ModeValue !== 'verify') {
    throw new Error('usage: release_sbom.ts <platform|index|verify> [options]')
  }

  const Values = new Map<string, string[]>()
  for (let Index = 3; Index < Argv.length; Index += 2) {
    const Option = Argv[Index]
    const Value = Argv[Index + 1]
    if (!Option.startsWith('--') || Value === undefined || Value.startsWith('--')) {
      throw new Error(`invalid or missing value for ${Option}`)
    }
    const Existing = Values.get(Option) ?? []
    Existing.push(Value)
    Values.set(Option, Existing)
  }

  return { Mode: ModeValue, Values }
}

function RequiredCliValue(Parameters: CliParameters, Name: string): string {
  const Values = Parameters.Values.get(Name)
  if (Values === undefined || Values.length !== 1) {
    throw new Error(`${Name} must be provided exactly once`)
  }
  return Values[0]
}

function OptionalCliValue(Parameters: CliParameters, Name: string): string | undefined {
  const Values = Parameters.Values.get(Name)
  if (Values === undefined) {
    return undefined
  }
  if (Values.length !== 1) {
    throw new Error(`${Name} may be provided at most once`)
  }
  return Values[0]
}

function AssertKnownOptions(Parameters: CliParameters, Known: Set<string>): void {
  for (const Option of Parameters.Values.keys()) {
    if (!Known.has(Option)) {
      throw new Error(`unknown option ${Option}`)
    }
  }
}

function CliIdentity(Parameters: CliParameters): ReleaseIdentity {
  return {
    Role: AsImageRole(RequiredCliValue(Parameters, '--role'), '--role'),
    Image: RequiredCliValue(Parameters, '--image'),
    Digest: OptionalCliValue(Parameters, '--digest'),
    Version: RequiredCliValue(Parameters, '--version'),
    Revision: RequiredCliValue(Parameters, '--revision'),
    Source: RequiredCliValue(Parameters, '--source'),
    Created: RequiredCliValue(Parameters, '--created'),
    Workflow: RequiredCliValue(Parameters, '--workflow')
  }
}

export function RunReleaseSbomCli(Argv: string[]): void {
  const Parameters = ParseCli(Argv)
  const Common = new Set([
    '--role', '--image', '--digest', '--version', '--revision', '--source', '--created', '--generated', '--workflow'
  ])

  if (Parameters.Mode === 'platform') {
    const Known = new Set([...Common, '--trivy', '--build-metadata', '--build-inputs', '--binaries', '--output'])
    AssertKnownOptions(Parameters, Known)
    const Identity = CliIdentity(Parameters)
    const Document = BuildPlatformSbom({
      ...Identity,
      Trivy: ReadJson(RequiredCliValue(Parameters, '--trivy')),
      BuildMetadata: ReadJson(RequiredCliValue(Parameters, '--build-metadata')),
      BuildInputs: ReadJson(RequiredCliValue(Parameters, '--build-inputs')),
      BinaryInventory: ReadJson(RequiredCliValue(Parameters, '--binaries')),
      Generated: RequiredCliValue(Parameters, '--generated')
    })
    Fs.writeFileSync(RequiredCliValue(Parameters, '--output'), SerializeReleaseSbom(Document))
    return
  }

  if (Parameters.Mode === 'index') {
    const Known = new Set([...Common, '--platform-sbom', '--output', '--build-started-on', '--build-finished-on'])
    AssertKnownOptions(Parameters, Known)
    const PlatformPaths = Parameters.Values.get('--platform-sbom') ?? []
    const Document = BuildIndexSbom({
      ...CliIdentity(Parameters),
      PlatformSboms: PlatformPaths.map(Path => ReadJson(Path)),
      Generated: RequiredCliValue(Parameters, '--generated'),
      BuildStartedOn: RequiredCliValue(Parameters, '--build-started-on'),
      BuildFinishedOn: RequiredCliValue(Parameters, '--build-finished-on')
    })
    Fs.writeFileSync(RequiredCliValue(Parameters, '--output'), SerializeReleaseSbom(Document))
    return
  }

  const Known = new Set(['--input', '--kind', '--role', '--digest', '--revision', '--workflow', '--image', '--version'])
  AssertKnownOptions(Parameters, Known)
  const Kind = RequiredCliValue(Parameters, '--kind')
  if (Kind !== 'platform' && Kind !== 'index') {
    throw new Error('--kind must be platform or index')
  }
  ValidateReleaseSbom(ReadJson(RequiredCliValue(Parameters, '--input')), {
    Kind,
    Role: OptionalCliValue(Parameters, '--role') === undefined
      ? undefined
      : AsImageRole(OptionalCliValue(Parameters, '--role'), '--role'),
    Digest: OptionalCliValue(Parameters, '--digest'),
    Revision: OptionalCliValue(Parameters, '--revision'),
    Workflow: OptionalCliValue(Parameters, '--workflow'),
    Image: OptionalCliValue(Parameters, '--image'),
    Version: OptionalCliValue(Parameters, '--version')
  })
}

if (Process.argv[1] !== undefined && import.meta.url === pathToFileURL(Process.argv[1]).href) {
  try {
    RunReleaseSbomCli(Process.argv)
  } catch (ErrorValue) {
    console.error(FormatError(ErrorValue))
    Process.exit(1)
  }
}
