import * as Assert from 'node:assert/strict'
import * as Crypto from 'node:crypto'
import * as Fs from 'node:fs'
import * as Os from 'node:os'
import * as Path from 'node:path'
import test from 'node:test'
import {
  BuildIndexSbom,
  BuildPlatformSbom,
  type JsonObject,
  RunReleaseSbomCli,
  SerializeReleaseSbom,
  ValidateReleaseSbom
} from '../sources/release_sbom.js'

/* eslint-disable @typescript-eslint/naming-convention -- Fixtures and assertions mirror CycloneDX and release JSON keys. */

const Image = 'ghcr.io/oxibelt/oxibelt'
const Role = 'standalone' as const
const Source = 'https://github.com/OxiBelt/OxiBelt'
const Version = '1.2.3-build.01234567'
const Revision = '0123456789abcdef0123456789abcdef01234567'
const Created = '2026-07-14T12:34:56Z'
const BuildStartedOn = '2026-07-14T12:35:00.060Z'
const BuildFinishedOn = '2026-07-14T12:42:00.366Z'
const ProvenanceBuildStartedOn = '2026-07-14T21:35:00.060641684+09:00'
const ProvenanceBuildFinishedOn = '2026-07-14T21:42:00.366512143+09:00'
const Generated = '2026-07-14T12:43:00Z'
const IndexBuildStartedOn = '2026-07-14T12:44:00Z'
const IndexBuildFinishedOn = '2026-07-14T12:45:00Z'
const IndexGenerated = '2026-07-14T12:46:00Z'
const PlatformWorkflow = 'OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml'
const IndexWorkflow = 'OxiBelt/OxiBelt/.github/workflows/release.yml'

const BinaryPaths = new Map([
  ['oxibelt', '/usr/local/bin/oxibelt'],
  ['oxibeltctl', '/usr/local/bin/oxibeltctl'],
  ['oxibelt-keysigner', '/usr/local/bin/oxibelt-keysigner'],
  ['oxibelt-netport-switcher', '/usr/local/bin/oxibelt-netport-switcher']
])

type ImageRole = 'standalone' | 'dataplane' | 'controller' | 'tools' | 'keysigner'

type RoleFixture = {
  Role: ImageRole
  Image: string
  DockerTarget: string
  Binaries: string[]
  Entrypoint: string[]
  User: string
  Ports: string[]
  EmbeddedAssets: boolean
}

const RoleFixtures: RoleFixture[] = [
  {
    Role: 'standalone',
    Image,
    DockerTarget: 'standalone',
    Binaries: ['oxibelt', 'oxibeltctl', 'oxibelt-keysigner', 'oxibelt-netport-switcher'],
    Entrypoint: ['/usr/local/bin/oxibelt', '--config', '/etc/oxibelt/config/oxibelt.toml'],
    User: '10001:10001',
    Ports: ['8443/tcp', '8443/udp'],
    EmbeddedAssets: true
  },
  {
    Role: 'dataplane',
    Image: 'ghcr.io/oxibelt/oxibelt-dataplane',
    DockerTarget: 'dataplane',
    Binaries: ['oxibelt'],
    Entrypoint: ['/usr/local/bin/oxibelt', '--config', '/etc/oxibelt/config/oxibelt.toml'],
    User: '10001:10001',
    Ports: ['8443/tcp', '8443/udp'],
    EmbeddedAssets: true
  },
  {
    Role: 'controller',
    Image: 'ghcr.io/oxibelt/oxibelt-gateway-controller',
    DockerTarget: 'controller',
    Binaries: ['oxibelt-gateway-controller'],
    Entrypoint: ['/usr/local/bin/oxibelt-gateway-controller'],
    User: '10001:10001',
    Ports: [],
    EmbeddedAssets: false
  },
  {
    Role: 'tools',
    Image: 'ghcr.io/oxibelt/oxibelt-tools',
    DockerTarget: 'tools',
    Binaries: ['oxibeltctl'],
    Entrypoint: ['/usr/local/bin/oxibeltctl'],
    User: '10001:10001',
    Ports: [],
    EmbeddedAssets: false
  },
  {
    Role: 'keysigner',
    Image: 'ghcr.io/oxibelt/oxibelt-keysigner',
    DockerTarget: 'keysigner',
    Binaries: ['oxibelt-keysigner'],
    Entrypoint: ['/usr/local/bin/oxibelt-keysigner'],
    User: '10002:10002',
    Ports: [],
    EmbeddedAssets: false
  }
]

const AllBinaryPaths = new Map([
  ...BinaryPaths,
  ['oxibelt-gateway-controller', '/usr/local/bin/oxibelt-gateway-controller']
])

type ArtifactFixture = {
  ArtifactArch: string
  Platform: string
  TargetCpu?: string
  RustImage: string
}

const Artifacts = new Map<string, ArtifactFixture>([
  ['amd64v2', { ArtifactArch: 'amd64v2', Platform: 'linux/amd64', TargetCpu: 'x86-64-v2', RustImage: 'rust:1.96.0-trixie' }],
  ['amd64', { ArtifactArch: 'amd64', Platform: 'linux/amd64', TargetCpu: 'x86-64-v3', RustImage: 'rust:1.96.0-trixie' }],
  ['amd64v4', { ArtifactArch: 'amd64v4', Platform: 'linux/amd64', TargetCpu: 'x86-64-v4', RustImage: 'rust:1.96.0-trixie' }],
  ['arm64', { ArtifactArch: 'arm64', Platform: 'linux/arm64', RustImage: 'rust:1.96.0-trixie' }],
  ['riscv64', { ArtifactArch: 'riscv64', Platform: 'linux/riscv64', RustImage: 'rust:1.96.0-trixie' }]
])

function Hash(Value: string): string {
  return Crypto.createHash('sha256').update(Value).digest('hex')
}

function DigestFor(ArtifactValue: ArtifactFixture): string {
  return `sha256:${Hash(`image-${ArtifactValue.ArtifactArch}`)}`
}

function Artifact(Name: string): ArtifactFixture {
  const Result = Artifacts.get(Name)
  if (Result === undefined) {
    throw new Error(`missing test artifact ${Name}`)
  }
  return Result
}

function BaseImages(ArtifactValue: ArtifactFixture): Array<{ buildArgument: string; stage: string; reference: string }> {
  return [
    { buildArgument: 'RUST_BUILDER_IMAGE', stage: 'builder', reference: ArtifactValue.RustImage },
    { buildArgument: 'OXIBELT_NODE_IMAGE', stage: 'person-proof-ui', reference: 'node:24-alpine3.24' },
    { buildArgument: 'OXIBELT_RUNTIME_IMAGE', stage: 'runtime', reference: 'alpine:3.24' }
  ]
}

function BuildInputs(ArtifactValue: ArtifactFixture): JsonObject {
  return {
    schemaVersion: 2,
    role: Role,
    image: Image,
    dockerTarget: 'standalone',
    binaries: [...BinaryPaths.keys()],
    entrypoint: ['/usr/local/bin/oxibelt', '--config', '/etc/oxibelt/config/oxibelt.toml'],
    user: '10001:10001',
    ports: ['8443/tcp', '8443/udp'],
    embeddedAssets: true,
    artifactArch: ArtifactValue.ArtifactArch,
    platform: ArtifactValue.Platform,
    rustToolchainVersion: '1.96.0',
    rustTarget: ArtifactValue.ArtifactArch === 'riscv64'
      ? 'riscv64gc-unknown-linux-musl'
      : ArtifactValue.ArtifactArch === 'arm64'
        ? 'aarch64-unknown-linux-musl'
        : 'x86_64-unknown-linux-musl',
    targetCpu: ArtifactValue.TargetCpu ?? null,
    baseImages: BaseImages(ArtifactValue)
  }
}

function RoleBuildInputs(ArtifactValue: ArtifactFixture, Fixture: RoleFixture): JsonObject {
  const Inputs = BuildInputs(ArtifactValue)
  Inputs.role = Fixture.Role
  Inputs.image = Fixture.Image
  Inputs.dockerTarget = Fixture.DockerTarget
  Inputs.binaries = Fixture.Binaries
  Inputs.entrypoint = Fixture.Entrypoint
  Inputs.user = Fixture.User
  Inputs.ports = Fixture.Ports
  Inputs.embeddedAssets = Fixture.EmbeddedAssets
  if (!Fixture.EmbeddedAssets) {
    Inputs.baseImages = BaseImages(ArtifactValue).filter(Base => Base.stage !== 'person-proof-ui')
  }

  return Inputs
}

function BuildMetadata(ArtifactValue: ArtifactFixture): JsonObject {
  const [OsValue, Architecture] = ArtifactValue.Platform.split('/', 2)
  const Digest = DigestFor(ArtifactValue)
  return {
    'containerimage.digest': Digest,
    'containerimage.descriptor': {
      digest: Digest,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      platform: { architecture: Architecture, os: OsValue }
    },
    'buildx.build.provenance': {
      metadata: {
        buildStartedOn: ProvenanceBuildStartedOn,
        buildFinishedOn: ProvenanceBuildFinishedOn
      },
      materials: BaseImages(ArtifactValue).map((Base, Index) => {
        const Separator = Base.reference.lastIndexOf(':')
        const Name = Base.reference.slice(0, Separator)
        const Tag = Base.reference.slice(Separator + 1)
        return {
          uri: `pkg:docker/${Name}@${Tag}?platform=linux%2F${ArtifactValue.ArtifactArch}`,
          digest: { sha256: Hash(`${ArtifactValue.ArtifactArch}-${Index}-${Base.reference}`) }
        }
      })
    }
  }
}

function BinaryInventory(): JsonObject {
  return {
    schemaVersion: 1,
    binaries: [...BinaryPaths].map(([Name, PathValue]) => ({
      name: Name,
      path: PathValue,
      version: Version,
      sha256: Hash(`${Name}-${Version}`)
    }))
  }
}

function RoleBinaryInventory(Fixture: RoleFixture): JsonObject {
  return {
    schemaVersion: 1,
    binaries: Fixture.Binaries.map(Name => {
      const PathValue = AllBinaryPaths.get(Name)
      if (PathValue === undefined) {
        throw new Error(`missing test binary path for ${Name}`)
      }

      return {
        name: Name,
        path: PathValue,
        version: Version,
        sha256: Hash(`${Name}-${Version}`)
      }
    })
  }
}

function Trivy(ArtifactValue: ArtifactFixture, SpecVersion = '1.7'): JsonObject {
  const PackageRef = `pkg:apk/alpine/libssl3@3.5.4?arch=${ArtifactValue.ArtifactArch}`
  return {
    $schema: `http://cyclonedx.org/schema/bom-${SpecVersion}.schema.json`,
    bomFormat: 'CycloneDX',
    specVersion: SpecVersion,
    serialNumber: `urn:uuid:00000000-0000-4000-8000-${ArtifactValue.ArtifactArch.padEnd(12, '0').slice(0, 12)}`,
    version: 1,
    metadata: {
      timestamp: Created,
      tools: {
        components: [{ type: 'application', name: 'trivy', version: '0.72.0' }]
      },
      component: {
        type: 'container',
        name: `oxibelt:${ArtifactValue.ArtifactArch}`,
        'bom-ref': `trivy-root-${ArtifactValue.ArtifactArch}`
      }
    },
    components: [{
      type: 'library',
      name: 'libssl3',
      version: '3.5.4',
      'bom-ref': PackageRef
    }],
    dependencies: [
      { ref: `trivy-root-${ArtifactValue.ArtifactArch}`, dependsOn: [PackageRef] },
      { ref: PackageRef, dependsOn: [] }
    ]
  }
}

function PlatformOptions(ArtifactValue: ArtifactFixture, Digest?: string) {
  return {
    Trivy: Trivy(ArtifactValue),
    BuildMetadata: BuildMetadata(ArtifactValue),
    BuildInputs: BuildInputs(ArtifactValue),
    BinaryInventory: BinaryInventory(),
    Role,
    Image,
    Digest: Digest ?? DigestFor(ArtifactValue),
    Version,
    Revision,
    Source,
    Created,
    Generated,
    Workflow: PlatformWorkflow
  }
}

function RootProperties(Document: ReturnType<typeof BuildPlatformSbom>): Map<string, string> {
  const Metadata = Document.metadata as unknown as { component: { properties: Array<{ name: string; value: string }> } }
  return new Map(Metadata.component.properties.map(Property => [Property.name, Property.value]))
}

test('platform SBOM deterministically enriches Trivy inventory with release evidence', () => {
  for (const ArtifactValue of Artifacts.values()) {
    const First = BuildPlatformSbom(PlatformOptions(ArtifactValue))
    const Second = BuildPlatformSbom(PlatformOptions(ArtifactValue))
    const Serialized = SerializeReleaseSbom(First)
    const Properties = RootProperties(First)

    Assert.equal(Serialized, SerializeReleaseSbom(Second))
    Assert.equal(First.bomFormat, 'CycloneDX')
    Assert.equal(First.specVersion, '1.6')
    Assert.equal((First.metadata as unknown as { timestamp: string }).timestamp, Generated)
    Assert.equal(Properties.get('org.opencontainers.image.created'), Created)
    Assert.equal(Properties.get('com.oxibelt.release.artifact_arch'), ArtifactValue.ArtifactArch)
    Assert.equal(Properties.get('com.oxibelt.release.platform'), ArtifactValue.Platform)
    Assert.equal(Properties.get('com.oxibelt.release.target_cpu'), ArtifactValue.TargetCpu)
    Assert.equal(Properties.get('com.oxibelt.release.rust_toolchain_version'), '1.96.0')
    Assert.equal(Properties.get('com.oxibelt.build.started_on'), BuildStartedOn)
    Assert.equal(Properties.get('com.oxibelt.build.finished_on'), BuildFinishedOn)
    Assert.equal(Properties.get('com.oxibelt.oci.subject_digest'), DigestFor(ArtifactValue))
    Assert.match(Serialized, /com\.oxibelt\.release\.binary\.path/)
    Assert.match(Serialized, /com\.oxibelt\.release\.base\.digest/)
    Assert.match(Serialized, /trivy:pkg:apk\/alpine\/libssl3/)
    ValidateReleaseSbom(First, { Kind: 'platform', Revision, Workflow: PlatformWorkflow })
  }
})

test('platform SBOM accepts supported Trivy schemas without changing the release schema', () => {
  const ArtifactValue = Artifact('amd64')

  for (const SpecVersion of ['1.6', '1.7']) {
    const Document = BuildPlatformSbom({
      ...PlatformOptions(ArtifactValue),
      Trivy: Trivy(ArtifactValue, SpecVersion)
    })
    Assert.equal(Document.specVersion, '1.6')
  }

  for (const SpecVersion of ['1.5', '1.8']) {
    Assert.throws(
      () => BuildPlatformSbom({
        ...PlatformOptions(ArtifactValue),
        Trivy: Trivy(ArtifactValue, SpecVersion)
      }),
      /Trivy input must be CycloneDX 1\.6 or 1\.7/
    )
  }

  const NonCycloneDx = Trivy(ArtifactValue)
  NonCycloneDx.bomFormat = 'SPDX'
  Assert.throws(
    () => BuildPlatformSbom({ ...PlatformOptions(ArtifactValue), Trivy: NonCycloneDx }),
    /Trivy input must be CycloneDX 1\.6 or 1\.7/
  )
})

test('platform SBOM enforces every role-specific image and executable allowlist', () => {
  const ArtifactValue = Artifact('amd64')
  for (const Fixture of RoleFixtures) {
    const Document = BuildPlatformSbom({
      ...PlatformOptions(ArtifactValue),
      Role: Fixture.Role,
      Image: Fixture.Image,
      BuildInputs: RoleBuildInputs(ArtifactValue, Fixture),
      BinaryInventory: RoleBinaryInventory(Fixture)
    })
    const Properties = RootProperties(Document)

    Assert.equal(Properties.get('com.oxibelt.release.role'), Fixture.Role)
    Assert.equal(Properties.get('com.oxibelt.release.image'), Fixture.Image)
    ValidateReleaseSbom(Document, {
      Kind: 'platform',
      Role: Fixture.Role,
      Image: Fixture.Image,
      Digest: DigestFor(ArtifactValue)
    })
  }

  const Dataplane = RoleFixtures.find(Fixture => Fixture.Role === 'dataplane')
  if (Dataplane === undefined) {
    throw new Error('missing dataplane fixture')
  }
  Assert.throws(
    () => BuildPlatformSbom({
      ...PlatformOptions(ArtifactValue),
      Role: Dataplane.Role,
      Image: Dataplane.Image,
      BuildInputs: RoleBuildInputs(ArtifactValue, Dataplane),
      BinaryInventory: BinaryInventory()
    }),
    /dataplane.*exactly 1 binaries/
  )
})

test('platform subject digest must match BuildKit and is embedded consistently', () => {
  const ImageDigest = DigestFor(Artifact('amd64'))
  const Document = BuildPlatformSbom(PlatformOptions(Artifact('amd64'), ImageDigest))
  const Properties = RootProperties(Document)

  Assert.equal(Properties.get('com.oxibelt.oci.subject_digest'), ImageDigest)
  ValidateReleaseSbom(Document, { Kind: 'platform', Digest: ImageDigest })
  Assert.throws(
    () => BuildPlatformSbom(PlatformOptions(Artifact('amd64'), `sha256:${'b'.repeat(64)}`)),
    /does not match the BuildKit image digest/
  )
})

test('platform generation fails closed on incomplete or conflicting release evidence', () => {
  const MissingBinary = structuredClone(BinaryInventory())
  const MutableMissingBinary = MissingBinary as unknown as {
    schemaVersion: number
    binaries: Array<{ name: string; path: string; version: string; sha256: string }>
  }
  MutableMissingBinary.binaries.pop()
  Assert.throws(
    () => BuildPlatformSbom({ ...PlatformOptions(Artifact('amd64')), BinaryInventory: MissingBinary }),
    /exactly 4 binaries/
  )

  const WrongPath = structuredClone(BinaryInventory())
  const MutableWrongPath = WrongPath as unknown as {
    schemaVersion: number
    binaries: Array<{ name: string; path: string; version: string; sha256: string }>
  }
  MutableWrongPath.binaries[0].path = '/tmp/oxibelt'
  Assert.throws(
    () => BuildPlatformSbom({ ...PlatformOptions(Artifact('amd64')), BinaryInventory: WrongPath }),
    /unexpected release binary or path/
  )

  const MissingMaterial = structuredClone(BuildMetadata(Artifact('amd64')))
  const MutableMissingMaterial = MissingMaterial as unknown as {
    'containerimage.digest': string
    'buildx.build.provenance': {
      materials: object[]
    }
  }
  MutableMissingMaterial['buildx.build.provenance'].materials.pop()
  Assert.throws(
    () => BuildPlatformSbom({ ...PlatformOptions(Artifact('amd64')), BuildMetadata: MissingMaterial }),
    /must resolve to exactly one provenance digest/
  )

  const WrongCpu = structuredClone(BuildInputs(Artifact('amd64')))
  const MutableWrongCpu = WrongCpu as unknown as { targetCpu: string }
  MutableWrongCpu.targetCpu = 'x86-64-v2'
  Assert.throws(
    () => BuildPlatformSbom({ ...PlatformOptions(Artifact('amd64')), BuildInputs: WrongCpu }),
    /does not match platform, Rust target, and target CPU/
  )

  const WrongTarget = structuredClone(BuildInputs(Artifact('amd64')))
  const MutableWrongTarget = WrongTarget as unknown as { rustTarget: string }
  MutableWrongTarget.rustTarget = 'aarch64-unknown-linux-musl'
  Assert.throws(
    () => BuildPlatformSbom({ ...PlatformOptions(Artifact('amd64')), BuildInputs: WrongTarget }),
    /does not match platform, Rust target, and target CPU/
  )

  const WrongDescriptor = structuredClone(BuildMetadata(Artifact('amd64')))
  const MutableWrongDescriptor = WrongDescriptor as unknown as {
    'containerimage.descriptor': { platform: { architecture: string } }
  }
  MutableWrongDescriptor['containerimage.descriptor'].platform.architecture = 'arm64'
  Assert.throws(
    () => BuildPlatformSbom({ ...PlatformOptions(Artifact('amd64')), BuildMetadata: WrongDescriptor }),
    /descriptor platform does not match/
  )

  const MissingTimestamps = structuredClone(BuildMetadata(Artifact('amd64')))
  const MutableMissingTimestamps = MissingTimestamps as unknown as {
    'buildx.build.provenance': { metadata?: object }
  }
  delete MutableMissingTimestamps['buildx.build.provenance'].metadata
  Assert.throws(
    () => BuildPlatformSbom({ ...PlatformOptions(Artifact('amd64')), BuildMetadata: MissingTimestamps }),
    /exactly one consistent build timestamp pair/
  )
  Assert.throws(
    () => BuildPlatformSbom({
      ...PlatformOptions(Artifact('amd64')),
      Generated: '2026-07-14T12:40:00Z'
    }),
    /generation timestamp predates the subject build/
  )

  const WrongMaterialRepository = structuredClone(BuildMetadata(Artifact('amd64')))
  const MutableWrongMaterialRepository = WrongMaterialRepository as unknown as {
    'buildx.build.provenance': {
      materials: Array<{ uri: string }>
    }
  }
  MutableWrongMaterialRepository['buildx.build.provenance'].materials[0].uri =
    'pkg:docker/unrelated/rust@1.96.0-alpine3.24?platform=linux%2Famd64'
  Assert.throws(
    () => BuildPlatformSbom({ ...PlatformOptions(Artifact('amd64')), BuildMetadata: WrongMaterialRepository }),
    /must resolve to exactly one provenance digest/
  )
})

test('verification rejects malformed required hashes and base-image metadata', () => {
  const InvalidBinaryHash = structuredClone(BuildPlatformSbom(PlatformOptions(Artifact('amd64'))))
  const BinaryComponents = InvalidBinaryHash.components as unknown as Array<{
    hashes?: Array<{ alg: string; content: string }>
    name?: string
  }>
  const Binary = BinaryComponents.find(Component => Component.name === 'oxibelt')
  Assert.notEqual(Binary, undefined)
  if (Binary?.hashes !== undefined) {
    Binary.hashes[0].alg = 'SHA-1'
  }
  Assert.throws(
    () => ValidateReleaseSbom(InvalidBinaryHash, { Kind: 'platform', Digest: DigestFor(Artifact('amd64')) }),
    /exactly one SHA-256 hash/
  )

  const InvalidBase = structuredClone(BuildPlatformSbom(PlatformOptions(Artifact('amd64'))))
  const BaseComponentsValue = InvalidBase.components as unknown as Array<{
    properties?: Array<{ name: string; value: string }>
  }>
  const Base = BaseComponentsValue.find(Component =>
    Component.properties?.some(Property => Property.name === 'com.oxibelt.release.base.stage') === true
  )
  Assert.notEqual(Base, undefined)
  if (Base?.properties !== undefined) {
    Base.properties = Base.properties.filter(Property => Property.name !== 'com.oxibelt.release.base.build_argument')
  }
  Assert.throws(
    () => ValidateReleaseSbom(InvalidBase, { Kind: 'platform', Digest: DigestFor(Artifact('amd64')) }),
    /invalid or duplicate base-image component/
  )
})

test('CycloneDX identity changes when release identity changes on the same commit', () => {
  const First = BuildPlatformSbom(PlatformOptions(Artifact('amd64')))
  const UpdatedInventory = structuredClone(BinaryInventory())
  const MutableInventory = UpdatedInventory as unknown as { binaries: Array<{ version: string }> }
  for (const Binary of MutableInventory.binaries) {
    Binary.version = '1.2.4'
  }
  const Second = BuildPlatformSbom({
    ...PlatformOptions(Artifact('amd64')),
    BinaryInventory: UpdatedInventory,
    Version: '1.2.4'
  })

  Assert.notEqual(First.serialNumber, Second.serialNumber)
  Assert.notEqual(
    (First.metadata as unknown as { component: { 'bom-ref': string } }).component['bom-ref'],
    (Second.metadata as unknown as { component: { 'bom-ref': string } }).component['bom-ref']
  )
})

test('index SBOM aggregates and namespaces exactly the representative platform documents', () => {
  const Platforms = ['riscv64', 'amd64', 'arm64'].map(Name => BuildPlatformSbom(PlatformOptions(Artifact(Name))))
  const Options = {
    PlatformSboms: Platforms,
    Role,
    Image,
    Digest: DigestFor(Artifact('amd64v4')),
    Version,
    Revision,
    Source,
    Created,
    Generated: IndexGenerated,
    BuildStartedOn: IndexBuildStartedOn,
    BuildFinishedOn: IndexBuildFinishedOn,
    Workflow: IndexWorkflow
  }
  const First = BuildIndexSbom(Options)
  const Second = BuildIndexSbom({ ...Options, PlatformSboms: [...Platforms].reverse() })
  const Serialized = SerializeReleaseSbom(First)
  const Properties = RootProperties(First)

  Assert.equal(Serialized, SerializeReleaseSbom(Second))
  Assert.equal((First.metadata as unknown as { timestamp: string }).timestamp, IndexGenerated)
  Assert.equal(Properties.get('org.opencontainers.image.created'), Created)
  Assert.equal(Properties.get('com.oxibelt.build.started_on'), IndexBuildStartedOn)
  Assert.equal(Properties.get('com.oxibelt.build.finished_on'), IndexBuildFinishedOn)
  Assert.match(Serialized, /platform:amd64:/)
  Assert.match(Serialized, /platform:arm64:/)
  Assert.match(Serialized, /platform:riscv64:/)
  Assert.doesNotMatch(Serialized, /platform:amd64v2:/)
  ValidateReleaseSbom(First, { Kind: 'index', Revision, Workflow: IndexWorkflow })
})

test('index generation rejects duplicate, nonrepresentative, and mismatched child SBOMs', () => {
  const Amd64 = BuildPlatformSbom(PlatformOptions(Artifact('amd64')))
  const Arm64 = BuildPlatformSbom(PlatformOptions(Artifact('arm64')))
  const Riscv64 = BuildPlatformSbom(PlatformOptions(Artifact('riscv64')))
  const BaseOptions = {
    Role,
    Image,
    Digest: DigestFor(Artifact('amd64v4')),
    Version,
    Revision,
    Source,
    Created,
    Generated: IndexGenerated,
    BuildStartedOn: IndexBuildStartedOn,
    BuildFinishedOn: IndexBuildFinishedOn,
    Workflow: IndexWorkflow
  }

  Assert.throws(
    () => BuildIndexSbom({ ...BaseOptions, PlatformSboms: [Amd64, Amd64, Riscv64] }),
    /unexpected or duplicate index platform/
  )

  const SharedDigest = structuredClone(Arm64)
  const SharedDigestMetadata = SharedDigest.metadata as unknown as {
    component: { hashes: Array<{ alg: string; content: string }>; properties: Array<{ name: string; value: string }> }
  }
  SharedDigestMetadata.component.properties = SharedDigestMetadata.component.properties.map(Property => ({
    ...Property,
    value: Property.name === 'com.oxibelt.oci.subject_digest'
      ? DigestFor(Artifact('amd64'))
      : Property.value
  }))
  SharedDigestMetadata.component.hashes = [{ alg: 'SHA-256', content: DigestFor(Artifact('amd64')).slice(7) }]
  Assert.throws(
    () => BuildIndexSbom({ ...BaseOptions, PlatformSboms: [Amd64, SharedDigest, Riscv64] }),
    /must not share subject digest/
  )
  Assert.throws(
    () => BuildIndexSbom({
      ...BaseOptions,
      PlatformSboms: [BuildPlatformSbom(PlatformOptions(Artifact('amd64v2'))), Arm64, Riscv64]
    }),
    /unexpected or duplicate index platform/
  )

  const MissingDigest = structuredClone(Arm64)
  const MissingDigestMetadata = MissingDigest.metadata as unknown as {
    component: { properties: Array<{ name: string; value: string }> }
  }
  MissingDigestMetadata.component.properties = MissingDigestMetadata.component.properties.filter(
    Property => Property.name !== 'com.oxibelt.oci.subject_digest'
  )
  delete MissingDigest.hashes
  Assert.throws(
    () => BuildIndexSbom({ ...BaseOptions, PlatformSboms: [Amd64, MissingDigest, Riscv64] }),
    /missing its immutable subject digest/
  )

  const Tampered = structuredClone(Arm64)
  const TamperedProperties = RootProperties(Tampered)
  const Metadata = Tampered.metadata as unknown as { component: { properties: Array<{ name: string; value: string }> } }
  Metadata.component.properties = [...TamperedProperties].map(([name, value]) => ({
    name,
    value: name === 'org.opencontainers.image.revision' ? 'f'.repeat(40) : value
  }))
  Assert.throws(
    () => BuildIndexSbom({ ...BaseOptions, PlatformSboms: [Amd64, Tampered, Riscv64] }),
    /source revision is invalid or unexpected/
  )
})

test('CLI writes a platform BOM and verify mode checks expected release identity', TestContext => {
  const Root = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-release-sbom-'))
  TestContext.after(() => Fs.rmSync(Root, { force: true, recursive: true }))
  const Inputs = new Map<string, JsonObject>([
    ['trivy.json', Trivy(Artifact('amd64'))],
    ['metadata.json', BuildMetadata(Artifact('amd64'))],
    ['inputs.json', BuildInputs(Artifact('amd64'))],
    ['binaries.json', BinaryInventory()]
  ])
  for (const [Name, Value] of Inputs) {
    Fs.writeFileSync(Path.join(Root, Name), JSON.stringify(Value))
  }
  const Output = Path.join(Root, 'platform.cdx.json')

  RunReleaseSbomCli([
    'node', 'release_sbom.ts', 'platform',
    '--trivy', Path.join(Root, 'trivy.json'),
    '--build-metadata', Path.join(Root, 'metadata.json'),
    '--build-inputs', Path.join(Root, 'inputs.json'),
    '--binaries', Path.join(Root, 'binaries.json'),
    '--output', Output,
    '--role', Role,
    '--image', Image,
    '--digest', DigestFor(Artifact('amd64')),
    '--version', Version,
    '--revision', Revision,
    '--source', Source,
    '--created', Created,
    '--generated', Generated,
    '--workflow', PlatformWorkflow
  ])
  Assert.equal(Fs.existsSync(Output), true)
  RunReleaseSbomCli([
    'node', 'release_sbom.ts', 'verify',
    '--input', Output,
    '--kind', 'platform',
    '--role', Role,
    '--digest', DigestFor(Artifact('amd64')),
    '--revision', Revision,
    '--workflow', PlatformWorkflow,
    '--image', Image,
    '--version', Version
  ])
  Assert.throws(
    () => RunReleaseSbomCli([
      'node', 'release_sbom.ts', 'verify',
      '--input', Output,
      '--kind', 'platform',
      '--revision', 'f'.repeat(40)
    ]),
    /source revision is invalid or unexpected/
  )
})
