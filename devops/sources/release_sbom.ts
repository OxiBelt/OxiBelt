import * as Crypto from 'node:crypto'
import * as Fs from 'node:fs'
import * as Process from 'node:process'
import { pathToFileURL } from 'node:url'

/* eslint-disable @typescript-eslint/naming-convention -- Options and parsed release, CycloneDX, and GitHub JSON use stable lower-camel-case keys. */
type JsonRecord = Record<string, unknown>

export type PlatformSbomOptions = {
  imagePlan: unknown
  trivySbom: unknown
  binaryInventory: unknown
  role: string
  artifactArch: string
  imageDigest?: string
  buildMetadata?: unknown
}

export type IndexSbomOptions = {
  imagePlan: unknown
  indexMetadata: unknown
  role: string
  platformSboms: unknown[]
}

export type VerificationOptions = {
  subjectName: string
  subjectDigest: string
  signerWorkflow: string
  sourceRepository: string
  sourceRef: string
  sourceRevision: string
  workflowPath: string
  expectedSbom?: unknown
}

type CliParameters = {
  mode: 'platform' | 'index' | 'verify'
  values: Map<string, string[]>
}

const CycloneDxPredicateType = 'https://cyclonedx.org/bom'
const ProvenancePredicateType = 'https://slsa.dev/provenance/v1'
const MaximumAttestationBytes = 16 * 1024 * 1024
const Sha256 = /^sha256:[0-9a-f]{64}$/
const Sha256Value = /^[0-9a-f]{64}$/
const ReservedPropertyPrefix = 'io.oxibelt.'
const ExpectedIndexArchs = ['amd64', 'arm64', 'riscv64'] as const
const ProtectedPlatformPropertyNames = [
  'io.oxibelt.artifact.arch',
  'io.oxibelt.image.digest',
  'io.oxibelt.image.repository',
  'io.oxibelt.image.role',
  'io.oxibelt.oci.platform',
  'io.oxibelt.release.ref',
  'io.oxibelt.release.revision',
  'io.oxibelt.release.version',
  'io.oxibelt.target.cpu'
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

function ExactString(Value: unknown, Expected: string, Description: string): void {
  if (Value !== Expected) {
    throw new Error(`${Description} was ${JSON.stringify(Value)}, expected ${JSON.stringify(Expected)}`)
  }
}

function ParseDigest(Value: unknown, Description: string): string {
  const Digest = StringValue(Value, Description)
  if (!Sha256.test(Digest)) {
    throw new Error(`${Description} must be a lowercase sha256 digest`)
  }
  return Digest
}

function CloneJson<T>(Value: T): T {
  return JSON.parse(JSON.stringify(Value)) as T
}

function JsonText(Value: unknown): string {
  return `${JSON.stringify(Value, null, 2)}\n`
}

export function ParseJsonDocument(Text: string, Description: string): unknown {
  try {
    return JSON.parse(Text) as unknown
  } catch (ErrorValue) {
    throw new Error(`${Description} is not valid JSON: ${FormatError(ErrorValue)}`)
  }
}

function ReadJson(Path: string, Description: string, SizeLimit?: number): unknown {
  const Stat = Fs.statSync(Path)
  if (!Stat.isFile()) {
    throw new Error(`${Description} is not a file: ${Path}`)
  }
  if (SizeLimit !== undefined && Stat.size > SizeLimit) {
    throw new Error(`${Description} exceeds the ${SizeLimit} byte attestation limit`)
  }
  return ParseJsonDocument(Fs.readFileSync(Path, 'utf8'), Description)
}

function AssertOutputSize(Value: unknown): void {
  const Size = Buffer.byteLength(JsonText(Value))
  if (Size > MaximumAttestationBytes) {
    throw new Error(`CycloneDX SBOM is ${Size} bytes and exceeds the ${MaximumAttestationBytes} byte attestation limit`)
  }
}

function AssertCycloneDx(Value: unknown, Description: string): JsonRecord {
  const Bom = RecordValue(Value, Description)
  ExactString(Bom.bomFormat, 'CycloneDX', `${Description} bomFormat`)
  const SpecVersion = StringValue(Bom.specVersion, `${Description} specVersion`)
  if (SpecVersion !== '1.6' && SpecVersion !== '1.7') {
    throw new Error(`${Description} specVersion must be 1.6 or 1.7`)
  }
  StringValue(Bom.serialNumber, `${Description} serialNumber`)
  return Bom
}

function Properties(Value: unknown, Description: string): JsonRecord[] {
  if (Value === undefined) {
    return []
  }
  return ArrayValue(Value, Description).map((Item, Index) => {
    const Property = RecordValue(Item, `${Description}[${Index}]`)
    StringValue(Property.name, `${Description}[${Index}].name`)
    StringValue(Property.value, `${Description}[${Index}].value`)
    return Property
  })
}

function PropertyMap(Component: JsonRecord, Description: string): Map<string, string> {
  const Result = new Map<string, string>()
  for (const Property of Properties(Component.properties, `${Description} properties`)) {
    const Name = StringValue(Property.name, `${Description} property name`)
    const Value = StringValue(Property.value, `${Description} property value`)
    if (Result.has(Name)) {
      throw new Error(`${Description} has duplicate property ${Name}`)
    }
    Result.set(Name, Value)
  }
  return Result
}

function AssertNoReservedProperties(Value: unknown, Path = '$'): void {
  if (Array.isArray(Value)) {
    Value.forEach((Item, Index) => AssertNoReservedProperties(Item, `${Path}[${Index}]`))
    return
  }
  if (!IsRecord(Value)) {
    return
  }
  if (Array.isArray(Value.properties)) {
    Value.properties.forEach((Item, Index) => {
      if (IsRecord(Item) && typeof Item.name === 'string' && Item.name.startsWith(ReservedPropertyPrefix)) {
        throw new Error(`input SBOM contains reserved property ${Item.name} at ${Path}.properties[${Index}]`)
      }
    })
  }
  for (const [Key, Child] of Object.entries(Value)) {
    AssertNoReservedProperties(Child, `${Path}.${Key}`)
  }
}

function CollectComponents(Value: unknown, Result: JsonRecord[] = []): JsonRecord[] {
  if (Array.isArray(Value)) {
    for (const Item of Value) {
      CollectComponents(Item, Result)
    }
    return Result
  }
  if (!IsRecord(Value)) {
    return Result
  }
  if (typeof Value.type === 'string' && typeof Value['bom-ref'] === 'string') {
    Result.push(Value)
  }
  if (Array.isArray(Value.components)) {
    for (const Component of Value.components) {
      CollectComponents(Component, Result)
    }
  }
  return Result
}

function AssertUniqueBomRefs(Bom: JsonRecord, Description: string): void {
  const Seen = new Set<string>()
  const Metadata = RecordValue(Bom.metadata, `${Description} metadata`)
  const Root = RecordValue(Metadata.component, `${Description} metadata.component`)
  const Components = [Root, ...CollectComponents(Bom.components)]
  for (const [Index, Component] of Components.entries()) {
    const BomRef = StringValue(Component['bom-ref'], `${Description} component ${Index} bom-ref`)
    if (Seen.has(BomRef)) {
      throw new Error(`${Description} has duplicate component bom-ref ${BomRef}`)
    }
    Seen.add(BomRef)
  }
}

function ReplaceDependencyRef(Bom: JsonRecord, OldRef: string, NewRef: string): void {
  if (!Array.isArray(Bom.dependencies)) {
    return
  }
  for (const Item of Bom.dependencies) {
    const Dependency = RecordValue(Item, 'CycloneDX dependency')
    if (Dependency.ref === OldRef) {
      Dependency.ref = NewRef
    }
    if (Array.isArray(Dependency.dependsOn)) {
      Dependency.dependsOn = Dependency.dependsOn.map(Ref => Ref === OldRef ? NewRef : Ref)
    }
  }
}

function SortBom(Bom: JsonRecord): void {
  const SortComponents = (Value: unknown): void => {
    if (!Array.isArray(Value)) {
      return
    }
    for (const Item of Value) {
      if (IsRecord(Item)) {
        SortComponents(Item.components)
        if (Array.isArray(Item.properties)) {
          Item.properties.sort((Left, Right) => String(RecordValue(Left, 'property').name).localeCompare(String(RecordValue(Right, 'property').name)))
        }
        if (Array.isArray(Item.hashes)) {
          Item.hashes.sort((Left, Right) => String(RecordValue(Left, 'hash').alg).localeCompare(String(RecordValue(Right, 'hash').alg)))
        }
      }
    }
    Value.sort((Left, Right) => {
      const LeftRecord = RecordValue(Left, 'component')
      const RightRecord = RecordValue(Right, 'component')
      return String(LeftRecord['bom-ref'] ?? LeftRecord.name).localeCompare(String(RightRecord['bom-ref'] ?? RightRecord.name))
    })
  }
  SortComponents(Bom.components)
  const Metadata = RecordValue(Bom.metadata, 'CycloneDX metadata')
  const Root = RecordValue(Metadata.component, 'CycloneDX metadata.component')
  if (Array.isArray(Root.properties)) {
    Root.properties.sort((Left, Right) => String(RecordValue(Left, 'property').name).localeCompare(String(RecordValue(Right, 'property').name)))
  }
  if (Array.isArray(Bom.dependencies)) {
    for (const Item of Bom.dependencies) {
      const Dependency = RecordValue(Item, 'dependency')
      if (Array.isArray(Dependency.dependsOn)) {
        Dependency.dependsOn = [...new Set(Dependency.dependsOn.map(String))].sort()
      }
    }
    Bom.dependencies.sort((Left, Right) => String(RecordValue(Left, 'dependency').ref).localeCompare(String(RecordValue(Right, 'dependency').ref)))
  }
}

function FindReleaseContract(ImagePlanValue: unknown, Role: string, ArtifactArch?: string): {
  plan: JsonRecord
  role: JsonRecord
  artifact?: JsonRecord
} {
  const Plan = RecordValue(ImagePlanValue, 'image release plan')
  if (Plan.schemaVersion !== 5) {
    throw new Error('image release plan schemaVersion must be 5')
  }
  const Version = StringValue(Plan.version, 'image release plan version')
  ExactString(Plan.tag, Version, 'image release plan tag')
  StringValue(Plan.revision, 'image release plan revision')
  const Roles = ArrayValue(Plan.roles, 'image release plan roles')
    .map((Item, Index) => RecordValue(Item, `image release plan roles[${Index}]`))
    .filter(Item => Item.role === Role)
  if (Roles.length !== 1) {
    throw new Error(`image release plan must have exactly one role contract for ${Role}`)
  }
  const RoleContract = Roles[0]
  StringValue(RoleContract.image, `release role ${Role} image`)
  const Binaries = ArrayValue(RoleContract.binaries, `release role ${Role} binaries`).map((Item, Index) => StringValue(Item, `release role ${Role} binaries[${Index}]`))
  if (Binaries.length === 0 || new Set(Binaries).size !== Binaries.length) {
    throw new Error(`release role ${Role} must have unique binaries`)
  }
  if (ArtifactArch === undefined) {
    return { plan: Plan, role: RoleContract }
  }
  const Artifacts = ArrayValue(Plan.artifacts, 'image release plan artifacts')
    .map((Item, Index) => RecordValue(Item, `image release plan artifacts[${Index}]`))
    .filter(Item => Item.role === Role && Item.artifactArch === ArtifactArch)
  if (Artifacts.length !== 1) {
    throw new Error(`image release plan must have exactly one artifact for ${Role}/${ArtifactArch}`)
  }
  const Artifact = Artifacts[0]
  for (const Key of ['image', 'dockerTarget', 'binaries', 'entrypoint', 'user', 'ports', 'embeddedAssets']) {
    if (JSON.stringify(Artifact[Key]) !== JSON.stringify(RoleContract[Key])) {
      throw new Error(`release artifact ${Role}/${ArtifactArch} has inconsistent ${Key}`)
    }
  }
  StringValue(Artifact.localTag, `release artifact ${Role}/${ArtifactArch} localTag`)
  StringValue(Artifact.platform, `release artifact ${Role}/${ArtifactArch} platform`)
  StringValue(Artifact.dockerArchitecture, `release artifact ${Role}/${ArtifactArch} dockerArchitecture`)
  return { plan: Plan, role: RoleContract, artifact: Artifact }
}

function ResolveBuildDigest(Options: PlatformSbomOptions): string {
  if (Options.buildMetadata !== undefined) {
    const Metadata = RecordValue(Options.buildMetadata, 'Buildx metadata')
    const Digest = ParseDigest(Metadata['containerimage.digest'], 'Buildx containerimage.digest')
    if (Options.imageDigest !== undefined && Options.imageDigest !== Digest) {
      throw new Error(`explicit image digest ${Options.imageDigest} does not match Buildx digest ${Digest}`)
    }
    return Digest
  }
  return ParseDigest(Options.imageDigest, 'image digest')
}

function ValidateInventory(Value: unknown, RoleContract: JsonRecord, Version: string): JsonRecord[] {
  const Inventory = RecordValue(Value, 'binary inventory')
  if (Inventory.schemaVersion !== 1) {
    throw new Error('binary inventory schemaVersion must be 1')
  }
  const ExpectedNames = ArrayValue(RoleContract.binaries, 'role binaries')
    .map((Item, Index) => StringValue(Item, `role binaries[${Index}]`))
  const Binaries = ArrayValue(Inventory.binaries, 'binary inventory binaries').map((Item, Index) => {
    const Binary = RecordValue(Item, `binary inventory binaries[${Index}]`)
    const Name = StringValue(Binary.name, `binary inventory binaries[${Index}].name`)
    ExactString(Binary.path, `/usr/local/bin/${Name}`, `binary inventory ${Name} path`)
    ExactString(Binary.version, Version, `binary inventory ${Name} version`)
    const Digest = StringValue(Binary.sha256, `binary inventory ${Name} sha256`)
    if (!Sha256Value.test(Digest)) {
      throw new Error(`binary inventory ${Name} sha256 must be 64 lowercase hex characters`)
    }
    return Binary
  })
  const ActualNames = Binaries.map(Item => String(Item.name))
  if (new Set(ActualNames).size !== ActualNames.length || [...ActualNames].sort().join('\n') !== [...ExpectedNames].sort().join('\n')) {
    throw new Error(`binary inventory must contain exactly the role binaries: ${ExpectedNames.join(', ')}`)
  }
  return Binaries.sort((Left, Right) => String(Left.name).localeCompare(String(Right.name)))
}

function Property(Name: string, Value: string): JsonRecord {
  return { name: Name, value: Value }
}

function RootIdentifiesLocalTag(Root: JsonRecord, LocalTag: string): boolean {
  const Values: string[] = []
  for (const Key of ['name', 'bom-ref', 'purl']) {
    if (typeof Root[Key] === 'string') {
      Values.push(String(Root[Key]))
    }
  }
  if (typeof Root.name === 'string' && typeof Root.version === 'string') {
    Values.push(`${Root.name}:${Root.version}`)
  }
  for (const Item of Properties(Root.properties, 'Trivy CycloneDX root properties')) {
    Values.push(String(Item.value))
  }
  return Values.some(Value => {
    if (Value === LocalTag || Value.includes(LocalTag)) {
      return true
    }
    try {
      const Decoded = decodeURIComponent(Value)
      return Decoded === LocalTag || Decoded.includes(LocalTag)
    } catch {
      return false
    }
  })
}

export function BuildPlatformSbom(Options: PlatformSbomOptions): JsonRecord {
  const Contract = FindReleaseContract(Options.imagePlan, Options.role, Options.artifactArch)
  const Plan = Contract.plan
  const Role = Contract.role
  const Artifact = Contract.artifact as JsonRecord
  const Version = StringValue(Plan.version, 'release version')
  const Revision = StringValue(Plan.revision, 'release revision')
  const Image = StringValue(Role.image, 'release image repository')
  const LocalTag = StringValue(Artifact.localTag, 'release artifact local tag')
  const Platform = StringValue(Artifact.platform, 'release artifact platform')
  const TargetCpu = Artifact.targetCpu === undefined ? 'architecture-default' : StringValue(Artifact.targetCpu, 'release artifact targetCpu')
  const Digest = ResolveBuildDigest(Options)
  const Input = AssertCycloneDx(Options.trivySbom, 'Trivy CycloneDX SBOM')
  AssertNoReservedProperties(Input)
  AssertUniqueBomRefs(Input, 'Trivy CycloneDX SBOM')
  const Bom = CloneJson(Input)
  const Metadata = RecordValue(Bom.metadata, 'Trivy CycloneDX metadata')
  const Root = RecordValue(Metadata.component, 'Trivy CycloneDX metadata.component')
  ExactString(Root.type, 'container', 'Trivy CycloneDX root component type')
  if (!RootIdentifiesLocalTag(Root, LocalTag)) {
    throw new Error(`Trivy CycloneDX root component does not identify local image tag ${LocalTag}`)
  }
  const OldRootRef = StringValue(Root['bom-ref'], 'Trivy CycloneDX root component bom-ref')
  Root.type = 'container'
  Root.name = LocalTag
  Root.version = Version
  Root['bom-ref'] = LocalTag
  Root.hashes = [{ alg: 'SHA-256', content: Digest.slice('sha256:'.length) }]
  // Trivy root properties are producer metadata and may be multi-valued.
  // The attested root owns only the exact protected release identity below.
  Root.properties = [
    Property('io.oxibelt.image.role', Options.role),
    Property('io.oxibelt.release.version', Version),
    Property('io.oxibelt.release.revision', Revision),
    Property('io.oxibelt.release.ref', `refs/tags/${Version}`),
    Property('io.oxibelt.artifact.arch', Options.artifactArch),
    Property('io.oxibelt.oci.platform', Platform),
    Property('io.oxibelt.target.cpu', TargetCpu),
    Property('io.oxibelt.image.repository', Image),
    Property('io.oxibelt.image.digest', Digest)
  ]
  ReplaceDependencyRef(Bom, OldRootRef, LocalTag)

  const Binaries = ValidateInventory(Options.binaryInventory, Role, Version)
  const Components = Bom.components === undefined ? [] : ArrayValue(Bom.components, 'Trivy CycloneDX components')
  const BinaryRefs: string[] = []
  for (const Binary of Binaries) {
    const Name = String(Binary.name)
    const BinaryDigest = String(Binary.sha256)
    const BomRef = `urn:oxibelt:binary:${Options.role}:${Options.artifactArch}:${Name}:${BinaryDigest}`
    BinaryRefs.push(BomRef)
    Components.push({
      type: 'application',
      name: Name,
      version: Version,
      'bom-ref': BomRef,
      hashes: [{ alg: 'SHA-256', content: BinaryDigest }]
    })
  }
  Bom.components = Components
  const Dependencies = Bom.dependencies === undefined ? [] : ArrayValue(Bom.dependencies, 'Trivy CycloneDX dependencies')
  let RootDependency = Dependencies.find(Item => IsRecord(Item) && Item.ref === LocalTag)
  if (RootDependency === undefined) {
    RootDependency = { ref: LocalTag, dependsOn: [] }
    Dependencies.push(RootDependency)
  }
  const RootDependencyRecord = RecordValue(RootDependency, 'root dependency')
  const ExistingDependsOn = RootDependencyRecord.dependsOn === undefined ? [] : ArrayValue(RootDependencyRecord.dependsOn, 'root dependsOn').map(String)
  RootDependencyRecord.dependsOn = [...ExistingDependsOn, ...BinaryRefs]
  Bom.dependencies = Dependencies
  SortBom(Bom)
  AssertUniqueBomRefs(Bom, 'enriched CycloneDX SBOM')
  const OutputProperties = PropertyMap(Root, 'enriched root component')
  for (const Name of ProtectedPlatformPropertyNames) {
    if (!OutputProperties.has(Name)) {
      throw new Error(`enriched root component is missing protected release property ${Name}`)
    }
  }
  AssertOutputSize(Bom)
  return Bom
}

function DeterministicUuid(Value: string): string {
  const Bytes = Crypto.createHash('sha256').update(Value, 'utf8').digest().subarray(0, 16)
  Bytes[6] = (Bytes[6] & 0x0f) | 0x50
  Bytes[8] = (Bytes[8] & 0x3f) | 0x80
  const Hex = Bytes.toString('hex')
  return `${Hex.slice(0, 8)}-${Hex.slice(8, 12)}-${Hex.slice(12, 16)}-${Hex.slice(16, 20)}-${Hex.slice(20)}`
}

function ValidateIndexMetadata(Value: unknown, Role: string, Image: string): { digest: string, children: JsonRecord[] } {
  const Metadata = RecordValue(Value, 'index metadata')
  if (Metadata.schemaVersion !== 2) {
    throw new Error('index metadata schemaVersion must be 2')
  }
  ExactString(Metadata.role, Role, 'index metadata role')
  ExactString(Metadata.image, Image, 'index metadata image')
  const Digest = ParseDigest(Metadata.digest, 'index metadata digest')
  const Children = ArrayValue(Metadata.children, 'index metadata children').map((Item, Index) => {
    const Child = RecordValue(Item, `index metadata children[${Index}]`)
    const Arch = StringValue(Child.artifactArch, `index metadata children[${Index}].artifactArch`)
    if (!ExpectedIndexArchs.includes(Arch as typeof ExpectedIndexArchs[number])) {
      throw new Error(`index metadata contains unexpected artifact architecture ${Arch}`)
    }
    ParseDigest(Child.digest, `index metadata child ${Arch} digest`)
    ExactString(Child.os, 'linux', `index metadata child ${Arch} os`)
    ExactString(Child.architecture, Arch, `index metadata child ${Arch} architecture`)
    if (Child.variant !== null) {
      throw new Error(`index metadata child ${Arch} variant must be null`)
    }
    return Child
  })
  const Archs = Children.map(Item => String(Item.artifactArch))
  if (new Set(Archs).size !== Archs.length || Archs.join(',') !== ExpectedIndexArchs.join(',')) {
    throw new Error(`index metadata children must be ordered exactly ${ExpectedIndexArchs.join(',')}`)
  }
  return { digest: Digest, children: Children }
}

function ValidatePlatformSbomForIndex(
  Value: unknown,
  ImagePlan: unknown,
  Role: string,
  Image: string,
  Child: JsonRecord
): void {
  const Arch = StringValue(Child.artifactArch, 'index child artifactArch')
  const Contract = FindReleaseContract(ImagePlan, Role, Arch)
  const Plan = Contract.plan
  const Artifact = Contract.artifact as JsonRecord
  const Bom = AssertCycloneDx(Value, `platform ${Arch} CycloneDX SBOM`)
  const Metadata = RecordValue(Bom.metadata, `platform ${Arch} metadata`)
  const Root = RecordValue(Metadata.component, `platform ${Arch} root component`)
  ExactString(Root.type, 'container', `platform ${Arch} root component type`)
  ExactString(Root.name, Artifact.localTag as string, `platform ${Arch} root component name`)
  ExactString(Root['bom-ref'], Artifact.localTag as string, `platform ${Arch} root component bom-ref`)
  const PropertiesValue = PropertyMap(Root, `platform ${Arch} root component`)
  const Expected: Record<string, string> = {
    'io.oxibelt.image.role': Role,
    'io.oxibelt.release.version': StringValue(Plan.version, 'release version'),
    'io.oxibelt.release.revision': StringValue(Plan.revision, 'release revision'),
    'io.oxibelt.release.ref': `refs/tags/${StringValue(Plan.version, 'release version')}`,
    'io.oxibelt.artifact.arch': Arch,
    'io.oxibelt.oci.platform': StringValue(Artifact.platform, `release artifact ${Arch} platform`),
    'io.oxibelt.target.cpu': Artifact.targetCpu === undefined
      ? 'architecture-default'
      : StringValue(Artifact.targetCpu, `release artifact ${Arch} targetCpu`),
    'io.oxibelt.image.repository': Image,
    'io.oxibelt.image.digest': StringValue(Child.digest, 'index child digest')
  }
  for (const [Name, ExpectedValue] of Object.entries(Expected)) {
    if (PropertiesValue.get(Name) !== ExpectedValue) {
      throw new Error(`platform ${Arch} SBOM property ${Name} does not match index metadata`)
    }
  }
}

export function BuildIndexSbom(Options: IndexSbomOptions): JsonRecord {
  const Contract = FindReleaseContract(Options.imagePlan, Options.role)
  const Plan = Contract.plan
  const Image = StringValue(Contract.role.image, 'release image repository')
  const Version = StringValue(Plan.version, 'release version')
  const Revision = StringValue(Plan.revision, 'release revision')
  const Index = ValidateIndexMetadata(Options.indexMetadata, Options.role, Image)
  if (Options.platformSboms.length !== ExpectedIndexArchs.length) {
    throw new Error(`index SBOM requires exactly ${ExpectedIndexArchs.length} platform SBOMs`)
  }
  const SbomsByArch = new Map<string, unknown>()
  for (const Sbom of Options.platformSboms) {
    const Bom = AssertCycloneDx(Sbom, 'platform CycloneDX SBOM')
    const Metadata = RecordValue(Bom.metadata, 'platform CycloneDX metadata')
    const Root = RecordValue(Metadata.component, 'platform CycloneDX root component')
    const Arch = PropertyMap(Root, 'platform CycloneDX root component').get('io.oxibelt.artifact.arch')
    if (Arch === undefined || SbomsByArch.has(Arch)) {
      throw new Error('platform SBOMs must have unique io.oxibelt.artifact.arch properties')
    }
    SbomsByArch.set(Arch, Sbom)
  }
  for (const Child of Index.children) {
    const Arch = StringValue(Child.artifactArch, 'index child artifactArch')
    const PlatformSbom = SbomsByArch.get(Arch)
    if (PlatformSbom === undefined) {
      throw new Error(`missing platform SBOM for ${Arch}`)
    }
    ValidatePlatformSbomForIndex(PlatformSbom, Options.imagePlan, Options.role, Image, Child)
  }
  if (SbomsByArch.size !== ExpectedIndexArchs.length) {
    throw new Error('platform SBOM set contains an unexpected architecture')
  }

  const RootRef = `${Image}@${Index.digest}`
  const Components = Index.children.map(Child => {
    const Arch = StringValue(Child.artifactArch, 'index child artifactArch')
    const Digest = ParseDigest(Child.digest, `index child ${Arch} digest`)
    return {
      type: 'container',
      name: `${Image}:${Version}-alpine-musl-${Arch}`,
      version: Digest,
      'bom-ref': `${Image}@${Digest}`,
      hashes: [{ alg: 'SHA-256', content: Digest.slice('sha256:'.length) }],
      properties: [
        Property('io.oxibelt.artifact.arch', Arch),
        Property('io.oxibelt.oci.platform', `linux/${Arch}`),
        Property('io.oxibelt.image.digest', Digest)
      ]
    }
  })
  const Bom: JsonRecord = {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    serialNumber: `urn:uuid:${DeterministicUuid(RootRef)}`,
    version: 1,
    metadata: {
      component: {
        type: 'container',
        name: Image,
        version: Version,
        'bom-ref': RootRef,
        hashes: [{ alg: 'SHA-256', content: Index.digest.slice('sha256:'.length) }],
        properties: [
          Property('io.oxibelt.image.role', Options.role),
          Property('io.oxibelt.release.version', Version),
          Property('io.oxibelt.release.revision', Revision),
          Property('io.oxibelt.release.ref', `refs/tags/${Version}`),
          Property('io.oxibelt.image.repository', Image),
          Property('io.oxibelt.image.digest', Index.digest),
          Property('io.oxibelt.sbom.inventory', 'separate-platform-attestation')
        ]
      }
    },
    components: Components,
    dependencies: [{ ref: RootRef, dependsOn: Components.map(Component => Component['bom-ref']) }]
  }
  SortBom(Bom)
  Bom.components = ExpectedIndexArchs.map(Arch => {
    const Component = Components.find(Item => PropertyMap(Item, `index ${Arch} component`).get('io.oxibelt.artifact.arch') === Arch)
    if (Component === undefined) {
      throw new Error(`generated index SBOM is missing component ${Arch}`)
    }
    return Component
  })
  Bom.dependencies = [{
    ref: RootRef,
    dependsOn: (Bom.components as JsonRecord[]).map(Component => StringValue(Component['bom-ref'], 'index child bom-ref'))
  }]
  AssertUniqueBomRefs(Bom, 'index CycloneDX SBOM')
  AssertOutputSize(Bom)
  return Bom
}

function CertificateValue(Certificate: JsonRecord, Names: string[], Description: string): string {
  for (const Name of Names) {
    if (typeof Certificate[Name] === 'string' && Certificate[Name] !== '') {
      return String(Certificate[Name])
    }
  }
  throw new Error(`verification certificate is missing ${Description}`)
}

function CanonicalJson(Value: unknown): unknown {
  if (Array.isArray(Value)) {
    return Value.map(CanonicalJson)
  }
  if (!IsRecord(Value)) {
    return Value
  }
  return Object.fromEntries(
    Object.keys(Value).sort().map(Key => [Key, CanonicalJson(Value[Key])])
  )
}

function ExactJson(Actual: unknown, Expected: unknown): boolean {
  return JSON.stringify(CanonicalJson(Actual)) === JSON.stringify(CanonicalJson(Expected))
}

function AttestationMatches(Value: unknown, Options: VerificationOptions): boolean {
  try {
    const Result = RecordValue(Value, 'attestation verification result')
    const Verification = RecordValue(Result.verificationResult, 'verificationResult')
    const Signature = RecordValue(Verification.signature, 'verificationResult.signature')
    const Certificate = RecordValue(Signature.certificate, 'verificationResult.signature.certificate')
    if (CertificateValue(Certificate, ['subjectAlternativeName', 'SubjectAlternativeName'], 'SubjectAlternativeName') !== Options.signerWorkflow) {
      return false
    }
    if (CertificateValue(Certificate, ['sourceRepository', 'SourceRepository', 'sourceRepositoryURI', 'SourceRepositoryURI'], 'SourceRepository') !== Options.sourceRepository &&
      CertificateValue(Certificate, ['sourceRepository', 'SourceRepository', 'sourceRepositoryURI', 'SourceRepositoryURI'], 'SourceRepository') !== `https://github.com/${Options.sourceRepository}`) {
      return false
    }
    if (CertificateValue(Certificate, ['sourceRepositoryRef', 'SourceRepositoryRef'], 'SourceRepositoryRef') !== Options.sourceRef) {
      return false
    }
    if (CertificateValue(Certificate, ['sourceRepositoryDigest', 'SourceRepositoryDigest'], 'SourceRepositoryDigest') !== Options.sourceRevision) {
      return false
    }
    if (CertificateValue(Certificate, ['buildSignerDigest', 'BuildSignerDigest'], 'BuildSignerDigest') !== Options.sourceRevision) {
      return false
    }
    if (CertificateValue(Certificate, ['runnerEnvironment', 'RunnerEnvironment'], 'RunnerEnvironment') !== 'github-hosted') {
      return false
    }
    const Timestamps = ArrayValue(Verification.verifiedTimestamps, 'verificationResult.verifiedTimestamps')
    if (Timestamps.length === 0) {
      return false
    }
    const Statement = RecordValue(Verification.statement, 'verificationResult.statement')
    const ExpectedPredicate = Options.expectedSbom === undefined ? ProvenancePredicateType : CycloneDxPredicateType
    if (Statement.predicateType !== ExpectedPredicate) {
      return false
    }
    const Subjects = ArrayValue(Statement.subject, 'verificationResult.statement.subject')
    if (Subjects.length !== 1) {
      return false
    }
    const Subject = RecordValue(Subjects[0], 'verificationResult.statement.subject[0]')
    if (Subject.name !== Options.subjectName) {
      return false
    }
    const SubjectDigest = RecordValue(Subject.digest, 'verificationResult.statement.subject[0].digest')
    if (SubjectDigest.sha256 !== Options.subjectDigest.slice('sha256:'.length)) {
      return false
    }
    if (Options.expectedSbom !== undefined) {
      return ExactJson(Statement.predicate, Options.expectedSbom)
    }
    const Predicate = RecordValue(Statement.predicate, 'provenance predicate')
    const BuildDefinition = RecordValue(Predicate.buildDefinition, 'provenance buildDefinition')
    if (BuildDefinition.buildType !== 'https://actions.github.io/buildtypes/workflow/v1') {
      return false
    }
    const External = RecordValue(BuildDefinition.externalParameters, 'provenance externalParameters')
    const Workflow = RecordValue(External.workflow, 'provenance externalParameters.workflow')
    if (
      Workflow.path !== Options.workflowPath ||
      Workflow.ref !== Options.sourceRef ||
      Workflow.repository !== `https://github.com/${Options.sourceRepository}`
    ) {
      return false
    }
    const Internal = RecordValue(BuildDefinition.internalParameters, 'provenance internalParameters')
    const GitHub = RecordValue(Internal.github, 'provenance internalParameters.github')
    if (GitHub.runner_environment !== 'github-hosted') {
      return false
    }
    const Dependencies = ArrayValue(BuildDefinition.resolvedDependencies, 'provenance resolvedDependencies')
    if (Dependencies.length !== 1) {
      return false
    }
    const Dependency = RecordValue(Dependencies[0], 'provenance resolvedDependencies[0]')
    const DependencyDigest = RecordValue(Dependency.digest, 'provenance resolvedDependencies[0].digest')
    if (
      Dependency.uri !== `git+https://github.com/${Options.sourceRepository}@${Options.sourceRef}` ||
      DependencyDigest.gitCommit !== Options.sourceRevision
    ) {
      return false
    }
    const RunDetails = RecordValue(Predicate.runDetails, 'provenance runDetails')
    const Builder = RecordValue(RunDetails.builder, 'provenance runDetails.builder')
    return Builder.id === Options.signerWorkflow
  } catch {
    return false
  }
}

export function VerifyAttestations(Value: unknown, Options: VerificationOptions): void {
  ParseDigest(Options.subjectDigest, 'verified subject digest')
  const Results = ArrayValue(Value, 'gh attestation verify JSON')
  if (Results.length === 0) {
    throw new Error('gh attestation verify returned no verified attestations')
  }
  if (!Results.some(Result => AttestationMatches(Result, Options))) {
    throw new Error('no verified attestation exactly matches the expected subject, signer, source, timestamp, and predicate')
  }
}

function ParseCli(Argv: string[]): CliParameters {
  const Mode = Argv[2]
  if (Mode !== 'platform' && Mode !== 'index' && Mode !== 'verify') {
    throw new Error('first argument must be platform, index, or verify')
  }
  const Values = new Map<string, string[]>()
  for (let Index = 3; Index < Argv.length; Index += 2) {
    const Option = Argv[Index]
    const Value = Argv[Index + 1]
    if (!Option.startsWith('--') || Value === undefined || Value.startsWith('--')) {
      throw new Error(`invalid or missing value for CLI argument ${Option}`)
    }
    const Existing = Values.get(Option) ?? []
    Existing.push(Value)
    Values.set(Option, Existing)
  }
  return { mode: Mode, values: Values }
}

function CliValue(Parameters: CliParameters, Name: string): string {
  const Values = Parameters.values.get(Name)
  if (Values === undefined || Values.length !== 1) {
    throw new Error(`${Name} must be provided exactly once`)
  }
  return Values[0]
}

function OptionalCliValue(Parameters: CliParameters, Name: string): string | undefined {
  const Values = Parameters.values.get(Name)
  if (Values === undefined) {
    return undefined
  }
  if (Values.length !== 1) {
    throw new Error(`${Name} may be provided at most once`)
  }
  return Values[0]
}

function AssertKnownOptions(Parameters: CliParameters, Names: string[]): void {
  for (const Name of Parameters.values.keys()) {
    if (!Names.includes(Name)) {
      throw new Error(`unknown ${Parameters.mode} option: ${Name}`)
    }
  }
}

function WriteOutput(Path: string, Value: unknown): void {
  Fs.writeFileSync(Path, JsonText(Value))
}

function RunCli(): void {
  const Parameters = ParseCli(Process.argv)
  if (Parameters.mode === 'platform') {
    AssertKnownOptions(Parameters, ['--image-plan', '--trivy-sbom', '--binary-inventory', '--role', '--artifact-arch', '--build-metadata', '--image-digest', '--output'])
    const BuildMetadataPath = OptionalCliValue(Parameters, '--build-metadata')
    WriteOutput(CliValue(Parameters, '--output'), BuildPlatformSbom({
      imagePlan: ReadJson(CliValue(Parameters, '--image-plan'), 'image release plan'),
      trivySbom: ReadJson(CliValue(Parameters, '--trivy-sbom'), 'Trivy CycloneDX SBOM', MaximumAttestationBytes),
      binaryInventory: ReadJson(CliValue(Parameters, '--binary-inventory'), 'binary inventory'),
      role: CliValue(Parameters, '--role'),
      artifactArch: CliValue(Parameters, '--artifact-arch'),
      buildMetadata: BuildMetadataPath === undefined ? undefined : ReadJson(BuildMetadataPath, 'Buildx metadata'),
      imageDigest: OptionalCliValue(Parameters, '--image-digest')
    }))
    return
  }
  if (Parameters.mode === 'index') {
    AssertKnownOptions(Parameters, ['--image-plan', '--index-metadata', '--role', '--platform-sbom', '--output'])
    const PlatformPaths = Parameters.values.get('--platform-sbom') ?? []
    WriteOutput(CliValue(Parameters, '--output'), BuildIndexSbom({
      imagePlan: ReadJson(CliValue(Parameters, '--image-plan'), 'image release plan'),
      indexMetadata: ReadJson(CliValue(Parameters, '--index-metadata'), 'index metadata'),
      role: CliValue(Parameters, '--role'),
      platformSboms: PlatformPaths.map(Path => ReadJson(Path, 'platform CycloneDX SBOM', MaximumAttestationBytes))
    }))
    return
  }
  AssertKnownOptions(Parameters, ['--attestations', '--expected-sbom', '--subject-name', '--subject-digest', '--signer-workflow', '--source-repository', '--source-ref', '--source-revision', '--workflow-path'])
  const ExpectedSbomPath = OptionalCliValue(Parameters, '--expected-sbom')
  VerifyAttestations(ReadJson(CliValue(Parameters, '--attestations'), 'gh attestation verify JSON'), {
    subjectName: CliValue(Parameters, '--subject-name'),
    subjectDigest: CliValue(Parameters, '--subject-digest'),
    signerWorkflow: CliValue(Parameters, '--signer-workflow'),
    sourceRepository: CliValue(Parameters, '--source-repository'),
    sourceRef: CliValue(Parameters, '--source-ref'),
    sourceRevision: CliValue(Parameters, '--source-revision'),
    workflowPath: CliValue(Parameters, '--workflow-path'),
    expectedSbom: ExpectedSbomPath === undefined ? undefined : ReadJson(ExpectedSbomPath, 'expected CycloneDX SBOM', MaximumAttestationBytes)
  })
}

function FormatError(ErrorValue: unknown): string {
  return ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)
}

if (
  Process.argv[1] !== undefined &&
  !Process.execArgv.includes('-e') &&
  !Process.execArgv.includes('--eval') &&
  import.meta.url === pathToFileURL(Process.argv[1]).href
) {
  try {
    RunCli()
  } catch (ErrorValue) {
    console.error(FormatError(ErrorValue))
    Process.exit(1)
  }
}
