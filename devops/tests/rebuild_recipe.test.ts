import * as Assert from 'node:assert/strict'
import test from 'node:test'
import { BuildImageReleasePlan, ParseReleaseTag } from '../sources/docker_image_release.js'
import {
  BuildIndexRebuildRecipe,
  BuildPlatformRebuildRecipe,
  ExtractVerifiedPredicate,
  RebuildPredicateSha256,
  RebuildPredicateType
} from '../sources/rebuild_recipe.js'

/* oxlint-disable oxibelt/pascal-case -- Fixtures and assertions mirror stable release JSON keys. */

const Revision = 'a'.repeat(40)
const Source = 'https://github.com/OxiBelt/OxiBelt'

function Digest(Character: string): string {
  return `sha256:${Character.repeat(64)}`
}

function Plan(): ReturnType<typeof BuildImageReleasePlan> {
  return BuildImageReleasePlan({
    releaseTag: ParseReleaseTag('1.2.3'),
    revision: Revision,
    source: Source
  })
}

function Environment(): Record<string, unknown> {
  return {
    schemaVersion: 1,
    rustc: 'rustc 1.98.0',
    cargo: 'cargo 1.98.0',
    node: 'v24.13.0',
    pnpm: '11.20.0',
    buildx: 'github.com/docker/buildx v0.36.1',
    buildkit: 'moby/buildkit@sha256:' + '1'.repeat(64),
    trivy: '0.69.3',
    cc: 'gcc 14.2.0',
    ld: 'GNU ld 2.44',
    featureGraphSha256: Digest('2')
  }
}

function PlatformFixture(ArtifactArch = 'amd64', Character = '3'): Parameters<typeof BuildPlatformRebuildRecipe>[0] {
  const ImagePlan = Plan()
  const Artifact = ImagePlan.artifacts.find(Item => Item.role === 'standalone' && Item.artifactArch === ArtifactArch)
  if (Artifact === undefined) throw new Error('missing artifact fixture')
  const ImageDigest = Digest(Character)
  const Binaries = Artifact.binaries.map(Name => ({
    name: Name,
    path: `/usr/local/bin/${Name}`,
    version: ImagePlan.version,
    sha256: Character.repeat(64)
  }))
  return {
    imagePlan: ImagePlan,
    artifactContract: {
      schema: 3,
      role: 'standalone',
      artifact_arch: ArtifactArch,
      revision: Revision,
      source: Source,
      source_ref: ImagePlan.sourceRef,
      source_dirty: ImagePlan.sourceDirty,
      build_kind: ImagePlan.buildKind,
      source_tree: 'b'.repeat(40),
      platform: Artifact.platform,
      docker_architecture: Artifact.dockerArchitecture,
      rust_target: ArtifactArch === 'riscv64'
        ? 'riscv64gc-unknown-linux-musl'
        : ArtifactArch === 'arm64' ? 'aarch64-unknown-linux-musl' : 'x86_64-unknown-linux-musl',
      target_cpu: Artifact.targetCpu ?? null,
      docker_target: Artifact.dockerTarget,
      cargo_builds: [],
      build_parameters: { created: '2026-07-21T00:00:00Z' },
      source_inputs: { 'Cargo.lock': Digest('4') },
      source_inputs_sha256: Digest('5'),
      image_digest: ImageDigest,
      descriptor_digest: ImageDigest
    },
    binaryInventory: { schemaVersion: 1, binaries: Binaries },
    sbom: {
      bomFormat: 'CycloneDX',
      specVersion: '1.7',
      metadata: {
        component: {
          properties: [{ name: 'io.oxibelt.image.digest', value: ImageDigest }]
        }
      }
    },
    buildEnvironment: Environment(),
    role: 'standalone',
    artifactArch: ArtifactArch
  }
}

test('platform recipe deterministically binds source, parameters, output, binaries, and SBOM', () => {
  const Fixture = PlatformFixture()
  const First = BuildPlatformRebuildRecipe(Fixture)
  const Second = BuildPlatformRebuildRecipe(Fixture)

  Assert.deepEqual(First, Second)
  Assert.equal(First.predicateType, RebuildPredicateType)
  Assert.equal(First.kind, 'platform')
  Assert.deepEqual(First.subject, {
    name: 'ghcr.io/oxibelt/oxibelt',
    digest: Digest('3')
  })
  Assert.equal((First.source as Record<string, unknown>).tree, 'b'.repeat(40))
  Assert.match(String((First.output as Record<string, unknown>).artifactContractSha256), /^sha256:[0-9a-f]{64}$/)
})

test('platform recipe rejects plan, contract, SBOM, inventory, and toolchain drift', () => {
  const BadPlan = PlatformFixture()
  ;(BadPlan.imagePlan as Record<string, unknown>).schemaVersion = 6
  Assert.throws(() => BuildPlatformRebuildRecipe(BadPlan), /schemaVersion must be 8/)

  const BadContract = PlatformFixture()
  ;(BadContract.artifactContract as Record<string, unknown>).role = 'controller'
  Assert.throws(() => BuildPlatformRebuildRecipe(BadContract), /contract role/)

  const BadSbom = PlatformFixture()
  const Root = ((BadSbom.sbom as Record<string, unknown>).metadata as Record<string, unknown>).component as Record<string, unknown>
  ;(Root.properties as Array<Record<string, unknown>>)[0].value = Digest('9')
  Assert.throws(() => BuildPlatformRebuildRecipe(BadSbom), /SBOM does not bind/)

  const BadInventory = PlatformFixture()
  ;(BadInventory.binaryInventory as { binaries: Array<Record<string, unknown>> }).binaries.pop()
  Assert.throws(() => BuildPlatformRebuildRecipe(BadInventory), /inventory names/)

  const BadEnvironment = PlatformFixture()
  delete (BadEnvironment.buildEnvironment as Record<string, unknown>).buildkit
  Assert.throws(() => BuildPlatformRebuildRecipe(BadEnvironment), /unexpected fields/)
})

test('index recipe binds ordered platform subjects and recipe hashes', () => {
  const ImagePlan = Plan()
  const PlatformRecipes = [
    BuildPlatformRebuildRecipe(PlatformFixture('amd64', '3')),
    BuildPlatformRebuildRecipe(PlatformFixture('arm64', '4')),
    BuildPlatformRebuildRecipe(PlatformFixture('riscv64', '5'))
  ]
  const IndexDigest = Digest('6')
  const Metadata = {
    schemaVersion: 2,
    role: 'standalone',
    image: 'ghcr.io/oxibelt/oxibelt',
    digest: IndexDigest,
    children: ['amd64', 'arm64', 'riscv64'].map((ArtifactArch, Index) => ({
      artifactArch: ArtifactArch,
      digest: [Digest('3'), Digest('4'), Digest('5')][Index],
      os: 'linux',
      architecture: ArtifactArch,
      variant: null
    }))
  }
  const Result = BuildIndexRebuildRecipe({
    imagePlan: ImagePlan,
    indexMetadata: Metadata,
    indexSbom: {
      bomFormat: 'CycloneDX',
      specVersion: '1.7',
      metadata: { component: { properties: [{ name: 'io.oxibelt.image.digest', value: IndexDigest }] } }
    },
    platformRecipes: PlatformRecipes,
    role: 'standalone'
  })

  Assert.equal(Result.kind, 'index')
  const Children = (Result.output as { children: Array<Record<string, unknown>> }).children
  Assert.deepEqual(Children.map(Item => Item.artifactArch), ['amd64', 'arm64', 'riscv64'])
  Assert.deepEqual(
    Children.map(Item => Item.recipeSha256),
    PlatformRecipes.map(RebuildPredicateSha256)
  )
})

test('predicate extraction requires one exact GitHub identity and rejects conflicts', () => {
  const Predicate = BuildPlatformRebuildRecipe(PlatformFixture())
  const Identity = {
    subjectName: 'ghcr.io/oxibelt/oxibelt',
    subjectDigest: Digest('3'),
    signerWorkflow: 'https://github.com/OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml@refs/tags/1.2.3',
    sourceRepository: 'OxiBelt/OxiBelt',
    sourceRef: 'refs/tags/1.2.3',
    sourceRevision: Revision,
    predicateType: RebuildPredicateType
  }
  const Result = (Value: unknown): Record<string, unknown> => ({
    verificationResult: {
      signature: {
        certificate: {
          subjectAlternativeName: Identity.signerWorkflow,
          sourceRepositoryURI: 'https://github.com/OxiBelt/OxiBelt',
          sourceRepositoryRef: Identity.sourceRef,
          sourceRepositoryDigest: Revision,
          buildSignerDigest: Revision,
          runnerEnvironment: 'github-hosted'
        }
      },
      verifiedTimestamps: [{}],
      statement: {
        subject: [{ name: Identity.subjectName, digest: { sha256: Identity.subjectDigest.slice(7) } }],
        predicateType: RebuildPredicateType,
        predicate: Value
      }
    }
  })

  Assert.deepEqual(ExtractVerifiedPredicate([Result(Predicate), Result(Predicate)], Identity), Predicate)
  Assert.throws(() => ExtractVerifiedPredicate([Result(Predicate), Result({ different: true })], Identity), /conflicting/)
  Assert.throws(() => ExtractVerifiedPredicate([Result(Predicate)], { ...Identity, sourceRef: 'refs/heads/main' }), /no verified/)
})
