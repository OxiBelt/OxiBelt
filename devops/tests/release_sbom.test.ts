import * as Assert from 'node:assert/strict'
import test from 'node:test'
import { BuildImageReleasePlan, ParseReleaseTag } from '../sources/docker_image_release.js'
import {
  BuildIndexSbom,
  BuildPlatformSbom,
  ParseJsonDocument,
  VerifyAttestations,
  type PlatformSbomOptions,
  type VerificationOptions
} from '../sources/release_sbom.js'

const Version = '1.2.3'
const Revision = '0123456789abcdef0123456789abcdef01234567'
const Repository = 'OxiBelt/OxiBelt'
const Source = `https://github.com/${Repository}`
const Roles = ['standalone', 'dataplane', 'dataplane-strict', 'controller', 'tools', 'keysigner']
const Archs = ['amd64v2', 'amd64', 'amd64v4', 'arm64', 'riscv64']

/* eslint-disable @typescript-eslint/naming-convention -- Fixtures intentionally mirror external CycloneDX and GitHub JSON fields. */
function ReleasePlan(): ReturnType<typeof BuildImageReleasePlan> {
  return BuildImageReleasePlan({
    releaseTag: ParseReleaseTag(Version),
    revision: Revision,
    source: Source
  })
}

function Digest(Character: string): string {
  return `sha256:${Character.repeat(64)}`
}

function DeepClone<T>(Value: T): T {
  return JSON.parse(JSON.stringify(Value)) as T
}

function TrivySbom(LocalTag: string, SpecVersion: '1.6' | '1.7' = '1.7'): Record<string, unknown> {
  return {
    bomFormat: 'CycloneDX',
    specVersion: SpecVersion,
    serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000001',
    version: 1,
    metadata: {
      component: {
        type: 'container',
        name: LocalTag,
        'bom-ref': 'trivy-root'
      }
    },
    components: [{
      type: 'library',
      name: 'musl',
      version: '1.2.5',
      'bom-ref': 'pkg:apk/alpine/musl@1.2.5'
    }],
    dependencies: [
      { ref: 'trivy-root', dependsOn: ['pkg:apk/alpine/musl@1.2.5'] },
      { ref: 'pkg:apk/alpine/musl@1.2.5', dependsOn: [] }
    ]
  }
}

function PlatformOptions(
  Role = 'standalone',
  Arch = 'amd64',
  ImageDigest = Digest('a'),
  SpecVersion: '1.6' | '1.7' = '1.7'
): PlatformSbomOptions {
  const Plan = ReleasePlan()
  const RoleContract = Plan.roles.find(Item => Item.role === Role)
  const Artifact = Plan.artifacts.find(Item => Item.role === Role && Item.artifactArch === Arch)
  if (RoleContract === undefined || Artifact === undefined) {
    throw new Error(`missing fixture release contract ${Role}/${Arch}`)
  }
  return {
    imagePlan: Plan,
    trivySbom: TrivySbom(Artifact.localTag, SpecVersion),
    binaryInventory: {
      schemaVersion: 1,
      binaries: RoleContract.binaries.map((Name, Index) => ({
        name: Name,
        path: `/usr/local/bin/${Name}`,
        version: Version,
        sha256: String(Index + 1).repeat(64).slice(0, 64)
      }))
    },
    role: Role,
    artifactArch: Arch,
    buildMetadata: { 'containerimage.digest': ImageDigest }
  }
}

function RootComponent(Bom: Record<string, unknown>): Record<string, unknown> {
  return ((Bom.metadata as Record<string, unknown>).component as Record<string, unknown>)
}

function PropertyMap(Component: Record<string, unknown>): Map<string, string> {
  return new Map((Component.properties as Array<{ name: string, value: string }>).map(Item => [Item.name, Item.value]))
}

function IndexMetadata(Role = 'standalone'): Record<string, unknown> {
  const Plan = ReleasePlan()
  const Contract = Plan.roles.find(Item => Item.role === Role)
  if (Contract === undefined) {
    throw new Error(`missing fixture role ${Role}`)
  }
  return {
    schemaVersion: 2,
    role: Role,
    image: Contract.image,
    digest: Digest('f'),
    children: [
      { artifactArch: 'amd64', digest: Digest('a'), os: 'linux', architecture: 'amd64', variant: null },
      { artifactArch: 'arm64', digest: Digest('b'), os: 'linux', architecture: 'arm64', variant: null },
      { artifactArch: 'riscv64', digest: Digest('c'), os: 'linux', architecture: 'riscv64', variant: null }
    ]
  }
}

function IndexPlatformSboms(Role = 'standalone'): Record<string, unknown>[] {
  return [
    BuildPlatformSbom(PlatformOptions(Role, 'riscv64', Digest('c'))),
    BuildPlatformSbom(PlatformOptions(Role, 'amd64', Digest('a'), '1.6')),
    BuildPlatformSbom(PlatformOptions(Role, 'arm64', Digest('b')))
  ]
}

function VerificationPolicy(ExpectedSbom?: unknown): VerificationOptions {
  return {
    subjectName: 'ghcr.io/oxibelt/oxibelt',
    subjectDigest: Digest('a'),
    signerWorkflow: `${Source}/.github/workflows/release-image-arch.yml@refs/tags/${Version}`,
    sourceRepository: Repository,
    sourceRef: `refs/tags/${Version}`,
    sourceRevision: Revision,
    workflowPath: '.github/workflows/release.yml',
    expectedSbom: ExpectedSbom
  }
}

function VerificationResult(Options: VerificationOptions, Predicate?: unknown): Record<string, unknown> {
  const IsSbom = Options.expectedSbom !== undefined
  return {
    attestation: { bundle: {} },
    verificationResult: {
      signature: {
        certificate: {
          subjectAlternativeName: Options.signerWorkflow,
          sourceRepositoryURI: `https://github.com/${Options.sourceRepository}`,
          sourceRepositoryRef: Options.sourceRef,
          sourceRepositoryDigest: Options.sourceRevision,
          buildSignerDigest: Options.sourceRevision,
          runnerEnvironment: 'github-hosted'
        }
      },
      verifiedTimestamps: [{ type: 'rekor', uri: 'https://rekor.sigstore.dev', timestamp: '2026-07-16T00:00:00Z' }],
      statement: {
        _type: 'https://in-toto.io/Statement/v1',
        subject: [{ name: Options.subjectName, digest: { sha256: Options.subjectDigest.slice('sha256:'.length) } }],
        predicateType: IsSbom ? 'https://cyclonedx.org/bom' : 'https://slsa.dev/provenance/v1',
        predicate: Predicate ?? (IsSbom ? Options.expectedSbom : {
          buildDefinition: {
            buildType: 'https://actions.github.io/buildtypes/workflow/v1',
            externalParameters: {
              workflow: {
                path: Options.workflowPath,
                ref: Options.sourceRef,
                repository: `https://github.com/${Options.sourceRepository}`
              }
            },
            internalParameters: { github: { runner_environment: 'github-hosted' } },
            resolvedDependencies: [{
              uri: `git+https://github.com/${Options.sourceRepository}@${Options.sourceRef}`,
              digest: { gitCommit: Options.sourceRevision }
            }]
          },
          runDetails: { builder: { id: Options.signerWorkflow } }
        })
      }
    }
  }
}
test('platform enrichment accepts CycloneDX 1.6 and 1.7 for every role and architecture', () => {
  let Counter = 0
  for (const Role of Roles) {
    for (const Arch of Archs) {
      Counter += 1
      const Character = (Counter % 9 + 1).toString()
      const Options = PlatformOptions(Role, Arch, Digest(Character), Counter % 2 === 0 ? '1.6' : '1.7')
      const Result = BuildPlatformSbom(Options)
      const Artifact = (Options.imagePlan as ReturnType<typeof ReleasePlan>).artifacts
        .find(Item => Item.role === Role && Item.artifactArch === Arch)
      if (Artifact === undefined) {
        throw new Error('missing artifact fixture')
      }
      Assert.equal(Result.specVersion, Counter % 2 === 0 ? '1.6' : '1.7')
      const Root = RootComponent(Result)
      Assert.equal(Root.type, 'container')
      Assert.equal(Root.name, Artifact.localTag)
      Assert.equal(Root['bom-ref'], Artifact.localTag)
      Assert.equal(PropertyMap(Root).size, 9)
      Assert.equal(PropertyMap(Root).get('io.oxibelt.image.role'), Role)
      Assert.equal(PropertyMap(Root).get('io.oxibelt.artifact.arch'), Arch)
      Assert.equal(PropertyMap(Root).get('io.oxibelt.image.digest'), Digest(Character))
      const Components = Result.components as Array<Record<string, unknown>>
      Assert.equal(Components.some(Item => Item.name === 'musl'), true)
      for (const Binary of Artifact.binaries) {
        Assert.equal(Components.some(Item => Item.type === 'application' && Item.name === Binary), true)
      }
    }
  }
})

test('platform enrichment is deterministic and attaches binaries to the root dependency', () => {
  const Options = PlatformOptions()
  const First = BuildPlatformSbom(Options)
  const Second = BuildPlatformSbom(Options)
  Assert.deepEqual(First, Second)
  const Root = RootComponent(First)
  const Dependency = (First.dependencies as Array<{ ref: string, dependsOn: string[] }>).find(Item => Item.ref === Root['bom-ref'])
  Assert.ok(Dependency)
  Assert.equal(Dependency.dependsOn.some(Reference => Reference.startsWith('urn:oxibelt:binary:')), true)
})

test('platform enrichment normalizes multi-valued Trivy root properties', () => {
  const Options = PlatformOptions('controller')
  const Plan = Options.imagePlan as ReturnType<typeof ReleasePlan>
  const Artifact = Plan.artifacts.find(Item => Item.role === 'controller' && Item.artifactArch === 'amd64')
  if (Artifact === undefined) {
    throw new Error('missing controller/amd64 fixture')
  }
  const InputRoot = RootComponent(Options.trivySbom as Record<string, unknown>)
  InputRoot.name = '/controller.tar'
  InputRoot.properties = [
    { name: 'aquasecurity:trivy:DiffID', value: Digest('1') },
    { name: 'aquasecurity:trivy:DiffID', value: Digest('2') },
    { name: 'aquasecurity:trivy:Reference', value: Artifact.localTag }
  ]

  const Result = BuildPlatformSbom(Options)
  const Root = RootComponent(Result)
  const RootProperties = Root.properties as Array<{ name: string, value: string }>
  Assert.equal(RootProperties.length, 9)
  Assert.equal(new Set(RootProperties.map(Item => Item.name)).size, 9)
  Assert.equal(RootProperties.every(Item => Item.name.startsWith('io.oxibelt.')), true)
  Assert.equal(RootProperties.some(Item => Item.name.startsWith('aquasecurity:trivy:')), false)

  const Components = Result.components as Array<Record<string, unknown>>
  Assert.equal(Components.some(Item => Item.name === 'musl'), true)
  Assert.equal(Components.some(Item => Item.type === 'application' && Item.name === 'oxibelt-gateway-controller'), true)
  const RootDependency = (Result.dependencies as Array<{ ref: string, dependsOn: string[] }>)
    .find(Item => Item.ref === Artifact.localTag)
  Assert.ok(RootDependency)
  Assert.equal(RootDependency.dependsOn.includes('pkg:apk/alpine/musl@1.2.5'), true)
  Assert.equal(RootDependency.dependsOn.some(Reference => Reference.startsWith('urn:oxibelt:binary:')), true)
})

test('platform enrichment rejects invalid CycloneDX identity, reserved properties, and duplicate refs', () => {
  Assert.throws(() => ParseJsonDocument('{', 'test document'), /not valid JSON/)

  const InvalidFormat = PlatformOptions()
  ;(InvalidFormat.trivySbom as Record<string, unknown>).bomFormat = 'SPDX'
  Assert.throws(() => BuildPlatformSbom(InvalidFormat), /bomFormat/)

  const InvalidVersion = PlatformOptions()
  ;(InvalidVersion.trivySbom as Record<string, unknown>).specVersion = '1.5'
  Assert.throws(() => BuildPlatformSbom(InvalidVersion), /specVersion/)

  const MissingSerial = PlatformOptions()
  delete (MissingSerial.trivySbom as Record<string, unknown>).serialNumber
  Assert.throws(() => BuildPlatformSbom(MissingSerial), /serialNumber/)

  const Reserved = PlatformOptions()
  const ReservedRoot = RootComponent(Reserved.trivySbom as Record<string, unknown>)
  ReservedRoot.properties = [{ name: 'io.oxibelt.image.role', value: 'standalone' }]
  Assert.throws(() => BuildPlatformSbom(Reserved), /reserved property/)

  const Duplicate = PlatformOptions()
  ;(Duplicate.trivySbom as Record<string, unknown>).components = [
    { type: 'library', name: 'one', 'bom-ref': 'duplicate' },
    { type: 'library', name: 'two', 'bom-ref': 'duplicate' }
  ]
  Assert.throws(() => BuildPlatformSbom(Duplicate), /duplicate component bom-ref/)

  const WrongLocalTag = PlatformOptions()
  RootComponent(WrongLocalTag.trivySbom as Record<string, unknown>).name = 'another:image'
  Assert.throws(() => BuildPlatformSbom(WrongLocalTag), /does not identify local image tag/)
})

test('platform enrichment rejects plan, digest, component, and binary inventory mismatches', () => {
  const BadSchema = PlatformOptions()
  ;(BadSchema.imagePlan as Record<string, unknown>).schemaVersion = 4
  Assert.throws(() => BuildPlatformSbom(BadSchema), /schemaVersion must be 7/)

  const BadDigest = PlatformOptions()
  BadDigest.imageDigest = Digest('b')
  Assert.throws(() => BuildPlatformSbom(BadDigest), /does not match Buildx digest/)

  const BadComponent = PlatformOptions()
  RootComponent(BadComponent.trivySbom as Record<string, unknown>).type = 'application'
  Assert.throws(() => BuildPlatformSbom(BadComponent), /root component type/)

  const BadRole = PlatformOptions()
  BadRole.role = 'unknown'
  Assert.throws(() => BuildPlatformSbom(BadRole), /role contract/)

  const BadAssets = PlatformOptions()
  const RoleContract = (BadAssets.imagePlan as ReturnType<typeof ReleasePlan>).roles
    .find(Item => Item.role === BadAssets.role)
  if (RoleContract === undefined) {
    throw new Error('missing role contract fixture')
  }
  ;(RoleContract as unknown as Record<string, unknown>).embeddedAssets = ['person-proof', 'unknown']
  Assert.throws(() => BuildPlatformSbom(BadAssets), /unique recognized embedded assets/)

  const BadInventory = PlatformOptions()
  const Binaries = (BadInventory.binaryInventory as { binaries: Array<Record<string, unknown>> }).binaries
  Binaries[0].path = '/tmp/wrong'
  Assert.throws(() => BuildPlatformSbom(BadInventory), /path/)

  const DuplicateInventory = PlatformOptions()
  const DuplicateBinaries = (DuplicateInventory.binaryInventory as { binaries: Array<Record<string, unknown>> }).binaries
  DuplicateBinaries.push(DeepClone(DuplicateBinaries[0]))
  Assert.throws(() => BuildPlatformSbom(DuplicateInventory), /exactly the role binaries/)
})

test('platform enrichment enforces the GitHub attestation size limit', () => {
  const Options = PlatformOptions()
  ;(Options.trivySbom as Record<string, unknown>).oversized = 'x'.repeat(16 * 1024 * 1024)
  Assert.throws(() => BuildPlatformSbom(Options), /exceeds the .* byte attestation limit/)
})

test('index composition emits deterministic CycloneDX 1.7 with ordered exact children', () => {
  const Options = {
    imagePlan: ReleasePlan(),
    indexMetadata: IndexMetadata(),
    role: 'standalone',
    platformSboms: IndexPlatformSboms()
  }
  const First = BuildIndexSbom(Options)
  const Second = BuildIndexSbom(Options)
  Assert.deepEqual(First, Second)
  Assert.equal(First.specVersion, '1.7')
  Assert.match(String(First.serialNumber), /^urn:uuid:[0-9a-f-]{36}$/)
  const Root = RootComponent(First)
  Assert.equal(PropertyMap(Root).get('io.oxibelt.sbom.inventory'), 'separate-platform-attestation')
  const Components = First.components as Array<Record<string, unknown>>
  Assert.deepEqual(
    Components.map(Component => PropertyMap(Component).get('io.oxibelt.artifact.arch')),
    ['amd64', 'arm64', 'riscv64']
  )
  Assert.deepEqual(
    (First.dependencies as Array<{ dependsOn: string[] }>)[0].dependsOn,
    Components.map(Component => Component['bom-ref'])
  )
})

test('index composition rejects missing, duplicate, extra, reordered, or mismatched children', () => {
  const Base = {
    imagePlan: ReleasePlan(),
    indexMetadata: IndexMetadata(),
    role: 'standalone',
    platformSboms: IndexPlatformSboms()
  }
  Assert.throws(() => BuildIndexSbom({ ...Base, platformSboms: Base.platformSboms.slice(0, 2) }), /exactly 3/)

  const DuplicateSboms = [...Base.platformSboms]
  DuplicateSboms[0] = DuplicateSboms[1]
  Assert.throws(() => BuildIndexSbom({ ...Base, platformSboms: DuplicateSboms }), /unique io\.oxibelt\.artifact\.arch/)

  const ReorderedMetadata = DeepClone(Base.indexMetadata) as { children: unknown[] }
  ReorderedMetadata.children.reverse()
  Assert.throws(() => BuildIndexSbom({ ...Base, indexMetadata: ReorderedMetadata }), /ordered exactly/)

  const ExtraMetadata = DeepClone(Base.indexMetadata) as { children: unknown[] }
  ExtraMetadata.children.push({ artifactArch: 's390x', digest: Digest('d'), os: 'linux', architecture: 's390x', variant: null })
  Assert.throws(() => BuildIndexSbom({ ...Base, indexMetadata: ExtraMetadata }), /unexpected artifact architecture/)

  const WrongDigestSboms = DeepClone(Base.platformSboms)
  PropertyMap(RootComponent(WrongDigestSboms[0])).set('io.oxibelt.image.digest', Digest('d'))
  const WrongDigestProperties = RootComponent(WrongDigestSboms[0]).properties as Array<{ name: string, value: string }>
  WrongDigestProperties.find(Item => Item.name === 'io.oxibelt.image.digest')!.value = Digest('d')
  Assert.throws(() => BuildIndexSbom({ ...Base, platformSboms: WrongDigestSboms }), /does not match index metadata/)
})

test('index composition cross-validates all protected platform properties and root identity', () => {
  const Base = {
    imagePlan: ReleasePlan(),
    indexMetadata: IndexMetadata(),
    role: 'standalone',
    platformSboms: IndexPlatformSboms()
  }
  for (const PropertyName of [
    'io.oxibelt.image.role',
    'io.oxibelt.release.version',
    'io.oxibelt.release.revision',
    'io.oxibelt.release.ref',
    'io.oxibelt.artifact.arch',
    'io.oxibelt.oci.platform',
    'io.oxibelt.target.cpu',
    'io.oxibelt.image.repository',
    'io.oxibelt.image.digest'
  ]) {
    const Sboms = DeepClone(Base.platformSboms)
    const Properties = RootComponent(Sboms[1]).properties as Array<{ name: string, value: string }>
    Properties.find(Item => Item.name === PropertyName)!.value = 'wrong'
    Assert.throws(() => BuildIndexSbom({ ...Base, platformSboms: Sboms }))
  }
  const WrongRoot = DeepClone(Base.platformSboms)
  RootComponent(WrongRoot[1]).name = 'wrong:tag'
  Assert.throws(() => BuildIndexSbom({ ...Base, platformSboms: WrongRoot }), /root component name/)
})

test('verification accepts a later exact provenance result and duplicate exact results', () => {
  const Policy = VerificationPolicy()
  const Historical = VerificationResult(Policy)
  ;(((Historical.verificationResult as Record<string, unknown>).signature as Record<string, unknown>).certificate as Record<string, unknown>).subjectAlternativeName =
    `${Policy.signerWorkflow}-prefix-confusable`
  VerifyAttestations([Historical, VerificationResult(Policy), VerificationResult(Policy)], Policy)
})

test('verification accepts only an exact canonical CycloneDX predicate', () => {
  const ExpectedSbom = BuildPlatformSbom(PlatformOptions())
  const Policy = VerificationPolicy(ExpectedSbom)
  VerifyAttestations([VerificationResult(Policy)], Policy)
  const Changed = DeepClone(ExpectedSbom)
  Changed.version = 2
  Assert.throws(
    () => VerifyAttestations([VerificationResult({ ...Policy, expectedSbom: Changed }, ExpectedSbom)], { ...Policy, expectedSbom: Changed }),
    /no verified attestation exactly matches/
  )
})

test('verification rejects wrong signer, source, subject, provenance, predicate, and missing timestamp', () => {
  const Policy = VerificationPolicy()
  const Mutations: Array<(Result: Record<string, unknown>) => void> = [
    Result => { Certificate(Result).subjectAlternativeName = `${Policy.signerWorkflow}/extra` },
    Result => { Certificate(Result).sourceRepositoryRef = 'refs/heads/main' },
    Result => { Certificate(Result).sourceRepositoryDigest = Digest('e') },
    Result => { Certificate(Result).buildSignerDigest = Digest('e') },
    Result => { Certificate(Result).runnerEnvironment = 'self-hosted' },
    Result => { Statement(Result).subject = [{ name: `${Policy.subjectName}-other`, digest: { sha256: 'a'.repeat(64) } }] },
    Result => { Statement(Result).predicateType = 'https://cyclonedx.org/bom' },
    Result => { Provenance(Result).buildDefinition.buildType = 'wrong' },
    Result => { Provenance(Result).buildDefinition.externalParameters.workflow.path = '.github/workflows/other.yml' },
    Result => { Provenance(Result).buildDefinition.internalParameters.github.runner_environment = 'self-hosted' },
    Result => { Provenance(Result).buildDefinition.resolvedDependencies[0].digest.gitCommit = Digest('e') },
    Result => { Provenance(Result).runDetails.builder.id = `${Policy.signerWorkflow}-other` },
    Result => { (Result.verificationResult as Record<string, unknown>).verifiedTimestamps = [] }
  ]
  for (const Mutate of Mutations) {
    const Result = VerificationResult(Policy)
    Mutate(Result)
    Assert.throws(() => VerifyAttestations([Result], Policy), /no verified attestation exactly matches/)
  }
})

function Certificate(Result: Record<string, unknown>): Record<string, unknown> {
  return ((((Result.verificationResult as Record<string, unknown>).signature as Record<string, unknown>).certificate) as Record<string, unknown>)
}

function Statement(Result: Record<string, unknown>): Record<string, unknown> {
  return ((Result.verificationResult as Record<string, unknown>).statement as Record<string, unknown>)
}

type ProvenanceFixture = {
  buildDefinition: {
    buildType: string
    externalParameters: { workflow: { path: string } }
    internalParameters: { github: { runner_environment: string } }
    resolvedDependencies: Array<{ digest: { gitCommit: string } }>
  }
  runDetails: { builder: { id: string } }
}

function Provenance(Result: Record<string, unknown>): ProvenanceFixture {
  return Statement(Result).predicate as ProvenanceFixture
}
