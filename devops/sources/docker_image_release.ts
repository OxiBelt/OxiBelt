import * as Fs from 'node:fs'
import * as Process from 'node:process'
import { pathToFileURL } from 'node:url'
import * as Semver from 'semver'

export const GhcrImage = 'ghcr.io/oxibelt/oxibelt'

export type ReleaseKind = 'stable' | 'beta' | 'build'

/* eslint-disable @typescript-eslint/naming-convention -- Release metadata JSON uses stable lower-camel-case keys. */
export type ReleaseTagInfo = {
  tag: string
  major: string
  minor: string
  patch: string
  kind: ReleaseKind
  betaNumber?: string
  buildCommitPrefix?: string
}

export type ArtifactArch = 'amd64v2' | 'amd64' | 'amd64v4' | 'arm64' | 'riscv64'

export type ImageArtifact = {
  artifactArch: ArtifactArch
  artifactName: string
  imageTar: string
  localTag: string
  platform: string
  dockerArchitecture: string
  targetCpu?: string
  canonicalGhcrTag: string
  aliasGhcrTags: string[]
  sbomArtifactName: string
  sbomFile: string
}

export type ImageManifest = {
  name: string
  artifactArchs: ArtifactArch[]
  canonicalGhcrTag: string
  aliasGhcrTags: string[]
}

export type ReleaseSbomContract = {
  format: 'cyclonedx-json'
  specVersion: '1.6'
  predicateType: 'https://cyclonedx.org/bom'
  rustToolchainVersion: '1.96.0'
  binaries: string[]
  indexArtifactName: 'oxibelt-release-sbom-index'
  indexFile: 'oxibelt-release-index.cdx.json'
}

export type ReleaseSupplyChainContract = {
  sourceRepository: 'OxiBelt/OxiBelt'
  oidcIssuer: 'https://token.actions.githubusercontent.com'
  cosignVersion: 'v3.1.1'
  provenancePredicateType: 'https://slsa.dev/provenance/v1'
  provenanceBuildType: 'https://actions.github.io/buildtypes/workflow/v1'
  minimumSlsaBuildLevel: 2
  platformBuilderWorkflow: 'OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml'
  indexBuilderWorkflow: 'OxiBelt/OxiBelt/.github/workflows/release.yml'
}

export type ImageReleasePlan = {
  schemaVersion: 3
  image: string
  tag: string
  version: string
  kind: ReleaseKind
  revision: string
  source: string
  sbom: ReleaseSbomContract
  supplyChain: ReleaseSupplyChainContract
  artifacts: ImageArtifact[]
  manifests: ImageManifest[]
}

type CliParameters = {
  ref?: string
  tag?: string
  revision?: string
  eventName?: string
  releasePrerelease?: string
  image?: string
  source?: string
  output?: string
}

type BuildImageReleasePlanOptions = {
  image?: string
  releaseTag: ReleaseTagInfo
  revision: string
  source: string
}
/* eslint-enable @typescript-eslint/naming-convention */

const BuildCommitPrefix = /^[0-9a-f]{8}$/

const ArtifactSpecs: Array<Omit<ImageArtifact, 'canonicalGhcrTag' | 'aliasGhcrTags' | 'sbomArtifactName' | 'sbomFile'>> = [
  {
    artifactArch: 'amd64v2',
    artifactName: 'oxibelt-alpine-musl-amd64v2-image',
    imageTar: 'oxibelt-alpine-musl-amd64v2.tar',
    localTag: 'oxibelt:alpine-musl-amd64v2',
    platform: 'linux/amd64',
    dockerArchitecture: 'amd64',
    targetCpu: 'x86-64-v2'
  },
  {
    artifactArch: 'amd64',
    artifactName: 'oxibelt-alpine-musl-amd64-image',
    imageTar: 'oxibelt-alpine-musl-amd64.tar',
    localTag: 'oxibelt:alpine-musl-amd64',
    platform: 'linux/amd64',
    dockerArchitecture: 'amd64',
    targetCpu: 'x86-64-v3'
  },
  {
    artifactArch: 'amd64v4',
    artifactName: 'oxibelt-alpine-musl-amd64v4-image',
    imageTar: 'oxibelt-alpine-musl-amd64v4.tar',
    localTag: 'oxibelt:alpine-musl-amd64v4',
    platform: 'linux/amd64',
    dockerArchitecture: 'amd64',
    targetCpu: 'x86-64-v4'
  },
  {
    artifactArch: 'arm64',
    artifactName: 'oxibelt-alpine-musl-arm64-image',
    imageTar: 'oxibelt-alpine-musl-arm64.tar',
    localTag: 'oxibelt:alpine-musl-arm64',
    platform: 'linux/arm64',
    dockerArchitecture: 'arm64'
  },
  {
    artifactArch: 'riscv64',
    artifactName: 'oxibelt-alpine-musl-riscv64-image',
    imageTar: 'oxibelt-alpine-musl-riscv64.tar',
    localTag: 'oxibelt:alpine-musl-riscv64',
    platform: 'linux/riscv64',
    dockerArchitecture: 'riscv64'
  }
]

export function ParseReleaseTag(Tag: string): ReleaseTagInfo {
  if (Tag.startsWith('v')) {
    throw new Error(`release tag must not use a leading v prefix: ${Tag}`)
  }

  const Parsed = Semver.parse(Tag)
  if (Parsed === null || Parsed.version !== Tag || Parsed.build.length > 0) {
    throw new Error(
      `release tag must match X.Y.Z, X.Y.Z-beta.N, or X.Y.Z-build.<8-lowercase-hex-git-prefix>: ${Tag}`
    )
  }

  if (Parsed.prerelease.length === 0) {
    return {
      tag: Tag,
      major: String(Parsed.major),
      minor: String(Parsed.minor),
      patch: String(Parsed.patch),
      kind: 'stable'
    }
  }

  if (
    Parsed.prerelease.length === 2 &&
    Parsed.prerelease[0] === 'beta' &&
    typeof Parsed.prerelease[1] === 'number'
  ) {
    return {
      tag: Tag,
      major: String(Parsed.major),
      minor: String(Parsed.minor),
      patch: String(Parsed.patch),
      kind: 'beta',
      betaNumber: String(Parsed.prerelease[1])
    }
  }

  if (
    Parsed.prerelease.length === 2 &&
    Parsed.prerelease[0] === 'build' &&
    typeof Parsed.prerelease[1] === 'string' &&
    BuildCommitPrefix.test(Parsed.prerelease[1])
  ) {
    return {
      tag: Tag,
      major: String(Parsed.major),
      minor: String(Parsed.minor),
      patch: String(Parsed.patch),
      kind: 'build',
      buildCommitPrefix: Parsed.prerelease[1]
    }
  }

  throw new Error(
    `release tag must match X.Y.Z, X.Y.Z-beta.N, or X.Y.Z-build.<8-lowercase-hex-git-prefix>: ${Tag}`
  )
}

export function TagFromRef(Ref: string): string {
  const Prefix = 'refs/tags/'

  if (!Ref.startsWith(Prefix)) {
    throw new Error(`release ref must start with ${Prefix}`)
  }

  return Ref.slice(Prefix.length)
}

export function ParseReleaseRef(Ref: string): ReleaseTagInfo {
  return ParseReleaseTag(TagFromRef(Ref))
}

export function AssertBuildTagMatchesRevision(Tag: ReleaseTagInfo, Revision: string): void {
  if (Tag.kind !== 'build') {
    return
  }

  const NormalizedRevision = Revision.toLowerCase()
  if (!NormalizedRevision.startsWith(Tag.buildCommitPrefix ?? '')) {
    throw new Error(
      `build release tag ${Tag.tag} must end with the first 8 lowercase hex characters of revision ${Revision}`
    )
  }
}

export function AssertReleaseEventAllowed(
  Tag: ReleaseTagInfo,
  EventName: string | undefined,
  ReleasePrerelease: boolean | undefined
): void {
  const NormalizedEvent = EventName ?? ''

  if (Tag.kind !== 'build' && NormalizedEvent === 'push') {
    throw new Error(`${Tag.kind} release tag ${Tag.tag} must publish from release or workflow_dispatch, not push`)
  }

  if (!['push', 'release', 'workflow_dispatch'].includes(NormalizedEvent)) {
    throw new Error(`unsupported release publishing event: ${NormalizedEvent}`)
  }

  if (NormalizedEvent === 'release' && Tag.kind === 'stable' && ReleasePrerelease === true) {
    throw new Error(`stable release tag ${Tag.tag} must not be published from a GitHub prerelease`)
  }

  if (NormalizedEvent === 'release' && Tag.kind === 'beta' && ReleasePrerelease === false) {
    throw new Error(`beta release tag ${Tag.tag} must be published from a GitHub prerelease`)
  }
}

export function BuildImageReleasePlan(Options: BuildImageReleasePlanOptions): ImageReleasePlan {
  const Image = Options.image ?? GhcrImage
  const Tag = Options.releaseTag.tag
  const Stable = Options.releaseTag.kind === 'stable'
  const Artifacts = ArtifactSpecs.map(Artifact => {
    const AliasGhcrTags: string[] = []

    if (Stable) {
      AliasGhcrTags.push(`${Image}:${Options.releaseTag.major}-alpine-musl-${Artifact.artifactArch}`)
    }

    return {
      ...Artifact,
      canonicalGhcrTag: `${Image}:${Tag}-alpine-musl-${Artifact.artifactArch}`,
      aliasGhcrTags: AliasGhcrTags,
      sbomArtifactName: `oxibelt-release-sbom-${Artifact.artifactArch}`,
      sbomFile: `oxibelt-release-${Artifact.artifactArch}.cdx.json`
    }
  })
  const Manifests: ImageManifest[] = [
    {
      name: 'release',
      artifactArchs: ['amd64', 'arm64', 'riscv64'],
      canonicalGhcrTag: `${Image}:${Tag}`,
      aliasGhcrTags: []
    },
    {
      name: 'alpine-musl',
      artifactArchs: ['amd64', 'arm64', 'riscv64'],
      canonicalGhcrTag: `${Image}:${Tag}-alpine-musl`,
      aliasGhcrTags: []
    }
  ]

  if (Stable) {
    Manifests[0].aliasGhcrTags.push(`${Image}:latest`)
    Manifests[1].aliasGhcrTags.push(`${Image}:${Options.releaseTag.major}-alpine-musl`, `${Image}:alpine-musl`)
  }

  return {
    schemaVersion: 3,
    image: Image,
    tag: Tag,
    version: Tag,
    kind: Options.releaseTag.kind,
    revision: Options.revision,
    source: Options.source,
    sbom: {
      format: 'cyclonedx-json',
      specVersion: '1.6',
      predicateType: 'https://cyclonedx.org/bom',
      rustToolchainVersion: '1.96.0',
      binaries: [
        'oxibelt',
        'oxibelt-keysigner',
        'oxibelt-netport-switcher',
        'oxibeltctl',
        'oxibelt-gateway-controller'
      ],
      indexArtifactName: 'oxibelt-release-sbom-index',
      indexFile: 'oxibelt-release-index.cdx.json'
    },
    supplyChain: {
      sourceRepository: 'OxiBelt/OxiBelt',
      oidcIssuer: 'https://token.actions.githubusercontent.com',
      cosignVersion: 'v3.1.1',
      provenancePredicateType: 'https://slsa.dev/provenance/v1',
      provenanceBuildType: 'https://actions.github.io/buildtypes/workflow/v1',
      minimumSlsaBuildLevel: 2,
      platformBuilderWorkflow: 'OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml',
      indexBuilderWorkflow: 'OxiBelt/OxiBelt/.github/workflows/release.yml'
    },
    artifacts: Artifacts,
    manifests: Manifests
  }
}

function ParseBool(Value: string | undefined): boolean | undefined {
  if (Value === undefined || Value === '') {
    return undefined
  }

  if (Value === 'true') {
    return true
  }

  if (Value === 'false') {
    return false
  }

  throw new Error(`boolean value must be true or false: ${Value}`)
}

function ParseCliParameters(Argv: string[]): CliParameters {
  const Parameters: CliParameters = {}

  for (let Index = 2; Index < Argv.length; Index += 1) {
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
      case '--ref':
        Parameters.ref = Value
        break
      case '--tag':
        Parameters.tag = Value
        break
      case '--revision':
        Parameters.revision = Value
        break
      case '--event-name':
        Parameters.eventName = Value
        break
      case '--release-prerelease':
        Parameters.releasePrerelease = Value
        break
      case '--image':
        Parameters.image = Value
        break
      case '--source':
        Parameters.source = Value
        break
      case '--output':
        Parameters.output = Value
        break
      default:
        throw new Error(`unknown option: ${Option}`)
    }
  }

  return Parameters
}

function FormatError(ErrorValue: unknown): string {
  if (ErrorValue instanceof Error) {
    return ErrorValue.message
  }

  return String(ErrorValue)
}

function RunCli(): void {
  const Parameters = ParseCliParameters(Process.argv)
  const ReleaseTag = Parameters.ref !== undefined
    ? ParseReleaseRef(Parameters.ref)
    : ParseReleaseTag(Parameters.tag ?? '')
  const Revision = Parameters.revision ?? ''

  if (Revision === '') {
    throw new Error('release image planning requires --revision')
  }

  AssertBuildTagMatchesRevision(ReleaseTag, Revision)
  AssertReleaseEventAllowed(ReleaseTag, Parameters.eventName, ParseBool(Parameters.releasePrerelease))

  const Plan = BuildImageReleasePlan({
    image: Parameters.image,
    releaseTag: ReleaseTag,
    revision: Revision,
    source: Parameters.source ?? 'https://github.com/OxiBelt/OxiBelt'
  })
  const Json = `${JSON.stringify(Plan, null, 2)}\n`

  if (Parameters.output === undefined) {
    Process.stdout.write(Json)
  } else {
    Fs.writeFileSync(Parameters.output, Json)
  }
}

if (Process.argv[1] !== undefined && import.meta.url === pathToFileURL(Process.argv[1]).href) {
  try {
    RunCli()
  } catch (ErrorValue) {
    console.error(FormatError(ErrorValue))
    Process.exit(1)
  }
}
