import * as Crypto from 'node:crypto'
import * as Fs from 'node:fs'
import * as Path from 'node:path'
import * as Process from 'node:process'
import { pathToFileURL } from 'node:url'
import { ParseReleaseTag } from './docker_image_release.js'

/* eslint-disable @typescript-eslint/naming-convention -- OCI receipt JSON is a stable public contract. */

type JsonObject = Record<string, unknown>

export const HelmChartPublishReceiptSchemaVersion = 2
export const HelmChartRebuildPredicateSchemaVersion = 2
export const HelmChartRebuildPredicateType = 'https://oxibelt.dev/attestations/helm-chart-rebuild/v2'
export const MaximumHelmChartOciJsonBytes = 256 * 1024
export const MaximumHelmChartOciPlanBytes = 128 * 1024
export const MaximumHelmChartOciArchiveBytes = 16 * 1024 * 1024

const FullRevision = /^[0-9a-f]{40}$/
const Sha256 = /^[0-9a-f]{64}$/
const Digest = /^sha256:[0-9a-f]{64}$/
const Semver = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/
const Repository = 'OxiBelt/OxiBelt'
const Provenance = 'github-workflow-authentication-required'
const ChartContentMediaType = 'application/vnd.cncf.helm.chart.content.v1.tar+gzip'
const ChartConfigMediaType = 'application/vnd.cncf.helm.config.v1+json'
const ExpectedAnnotations = {
  'oxibelt.dev/feature-status': 'experimental',
  'oxibelt.dev/kubernetes-support-policy': '1'
} as const
const ExpectedTransformationRecipe = [
  'read only Git-tracked regular blobs from the exact commit tree',
  'normalize staged directories to 0755 and staged files to 0644 at commit epoch',
  'replace only declared image.tag latest defaults with the exact release SemVer',
  'helm package with exact --version and --app-version',
  'reject noncanonical, unexpected, duplicate, or partial archive members'
] as const

const Charts = [
  {
    name: 'oxibelt', directory: 'deploy/helm/oxibelt', repository: 'oci://ghcr.io/oxibelt/charts/oxibelt',
    defaultImagePaths: [
      'deploy/helm/oxibelt/values.yaml',
      'deploy/helm/oxibelt/examples/strict-dataplane-values.yaml'
    ]
  },
  {
    name: 'oxibelt-gateway-controller', directory: 'deploy/helm/oxibelt-gateway-controller', repository: 'oci://ghcr.io/oxibelt/charts/oxibelt-gateway-controller',
    defaultImagePaths: ['deploy/helm/oxibelt-gateway-controller/values.yaml']
  }
] as const

export type HelmChartPublishReceipt = {
  schemaVersion: 2
  kind: 'helm-chart-publish'
  repository: 'OxiBelt/OxiBelt'
  repositoryProvenance: 'github-workflow-authentication-required'
  source: { ref: string, revision: string, commitEpoch: number, releaseVersion: string }
  plan: { bytes: number, sha256: string }
  charts: Array<{
    name: string
    sourceDirectory: string
    targetOciRepository: string
    tag: string
    filename: string
    package: { bytes: number, sha256: string }
    metadata: { version: string, appVersion: string, annotations: Record<string, string> }
    experimentalStatus: 'experimental'
    defaultImages: Array<{ path: string, from: 'latest', to: string }>
    transformationRecipe: string[]
    manifest: { descriptor: { bytes: number, sha256: string }, digest: string, mediaType: string, bytes: number, config: Descriptor, layers: [Descriptor] }
  }>
}

export type Descriptor = { mediaType: string, digest: string, size: number }

export type BuildHelmChartPublishReceiptOptions = {
  planBytes: Buffer
  archives: Record<string, Buffer>
  artifacts: Record<string, HelmChartOciArtifact>
}

export type HelmChartOciArtifact = {
  descriptorBytes: Buffer
  manifestBytes: Buffer
  configBytes: Buffer
}

export type BuildHelmChartRebuildPredicateOptions = {
  receipt: unknown
  rebuiltPlanBytes: Buffer
  publishedArchives: Record<string, Buffer>
  rebuiltArchives: Record<string, Buffer>
}

function IsObject(Value: unknown): Value is JsonObject {
  return typeof Value === 'object' && Value !== null && !Array.isArray(Value)
}

function ObjectValue(Value: unknown, Label: string): JsonObject {
  if (!IsObject(Value)) throw new Error(`${Label} must be an object`)
  return Value
}

function StringValue(Value: unknown, Label: string): string {
  if (typeof Value !== 'string' || Value === '') throw new Error(`${Label} must be a non-empty string`)
  return Value
}

function NumberValue(Value: unknown, Label: string): number {
  if (typeof Value !== 'number' || !Number.isSafeInteger(Value) || Value < 0) throw new Error(`${Label} must be a non-negative safe integer`)
  return Value
}

function ExactKeys(Value: JsonObject, Expected: string[], Label: string): void {
  const Actual = Object.keys(Value).sort()
  const Required = [...Expected].sort()
  if (Actual.join('\n') !== Required.join('\n')) throw new Error(`${Label} has missing, unexpected, or substituted keys`)
}

function Canonical(Value: unknown): string {
  if (Array.isArray(Value)) return `[${Value.map(Canonical).join(',')}]`
  if (IsObject(Value)) return `{${Object.keys(Value).sort().map(Key => `${JSON.stringify(Key)}:${Canonical(Value[Key])}`).join(',')}}`
  return JSON.stringify(Value)
}

function ExactCanonical(Value: unknown, Expected: unknown, Label: string): void {
  if (Canonical(Value) !== Canonical(Expected)) throw new Error(`${Label} does not match the exact canonical release-plan contract`)
}

export function HelmChartOciSha256(Value: Buffer | string | unknown): string {
  const Content = Buffer.isBuffer(Value) ? Value : typeof Value === 'string' ? Buffer.from(Value, 'utf8') : Buffer.from(Canonical(Value), 'utf8')
  return Crypto.createHash('sha256').update(Content).digest('hex')
}

function ParseStrictJson(Bytes: Buffer, Label: string, MaximumBytes = MaximumHelmChartOciJsonBytes): unknown {
  if (Bytes.length === 0 || Bytes.length > MaximumBytes) throw new Error(`${Label} exceeds the ${MaximumBytes} byte limit`)
  const Text = Bytes.toString('utf8')
  if (!Buffer.from(Text, 'utf8').equals(Bytes)) throw new Error(`${Label} must be UTF-8`)
  let Offset = 0
  let Nodes = 0
  const Skip = () => { while (/[\t\n\r ]/.test(Text[Offset] ?? '')) Offset += 1 }
  const Expect = (Character: string) => { if (Text[Offset] !== Character) throw new Error(`${Label} has invalid JSON structure`); Offset += 1 }
  const ParseString = (): string => {
    const Start = Offset
    Expect('"')
    while (Offset < Text.length) {
      const Character = Text[Offset++]
      if (Character === '"') return JSON.parse(Text.slice(Start, Offset)) as string
      if (Character === '\\') { if (Offset >= Text.length) throw new Error(`${Label} has an invalid JSON escape`); Offset += 1 } else if (Character < ' ') throw new Error(`${Label} has an invalid JSON string`)
    }
    throw new Error(`${Label} has an unterminated JSON string`)
  }
  const ParseValue = (Depth: number): void => {
    if (Depth > 64 || ++Nodes > 8192) throw new Error(`${Label} exceeds JSON nesting or item limits`)
    Skip()
    if (Text[Offset] === '{') {
      Offset += 1; Skip()
      const Keys = new Set<string>()
      if (Text[Offset] === '}') { Offset += 1; return }
      while (true) {
        Skip(); const Key = ParseString()
        if (Keys.has(Key)) throw new Error(`${Label} has a duplicate JSON key`)
        Keys.add(Key); Skip(); Expect(':'); ParseValue(Depth + 1); Skip()
        if (Text[Offset] === '}') { Offset += 1; return }
        Expect(',')
      }
    }
    if (Text[Offset] === '[') {
      Offset += 1; Skip()
      if (Text[Offset] === ']') { Offset += 1; return }
      while (true) {
        ParseValue(Depth + 1); Skip()
        if (Text[Offset] === ']') { Offset += 1; return }
        Expect(',')
      }
    }
    if (Text[Offset] === '"') { ParseString(); return }
    const Scalar = /(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/y
    Scalar.lastIndex = Offset
    const Match = Scalar.exec(Text)
    if (Match === null) throw new Error(`${Label} has an invalid JSON scalar`)
    Offset += Match[0].length
  }
  ParseValue(0); Skip()
  if (Offset !== Text.length) throw new Error(`${Label} has trailing JSON content`)
  let Value: unknown
  try { Value = JSON.parse(Text) as unknown } catch (ErrorValue) { throw new Error(`${Label} is not valid JSON: ${ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)}`) }
  return Value
}

function ParseCanonicalJson(Bytes: Buffer, Label: string): unknown {
  const Value = ParseStrictJson(Bytes, Label)
  const Text = Bytes.toString('utf8')
  if (`${Canonical(Value)}\n` !== Text) throw new Error(`${Label} must be canonical JSON without duplicate keys or whitespace`)
  return Value
}

export function ReadCanonicalHelmChartOciJson(FilePath: string): unknown {
  return ParseCanonicalJson(BoundedRegularFile(FilePath, MaximumHelmChartOciJsonBytes, 'OCI JSON input'), 'OCI JSON input')
}

function DescriptorValue(Value: unknown, Label: string): Descriptor {
  const Object = ObjectValue(Value, Label)
  ExactKeys(Object, ['mediaType', 'digest', 'size'], Label)
  const mediaType = StringValue(Object.mediaType, `${Label}.mediaType`)
  const digest = StringValue(Object.digest, `${Label}.digest`)
  const size = NumberValue(Object.size, `${Label}.size`)
  if (!Digest.test(digest) || size === 0 || size > MaximumHelmChartOciArchiveBytes) throw new Error(`${Label} must bind a non-empty bounded lowercase SHA-256 descriptor`)
  return { mediaType, digest, size }
}

function PlanValue(Value: unknown): JsonObject {
  const Plan = ObjectValue(Value, 'Helm chart release plan')
  ExactKeys(Plan, ['schemaVersion', 'repository', 'repositoryProvenance', 'sourceRef', 'sourceRevision', 'commitEpoch', 'releaseVersion', 'charts'], 'Helm chart release plan')
  if (Plan.schemaVersion !== 1 || Plan.repository !== Repository || Plan.repositoryProvenance !== Provenance) throw new Error('Helm chart release plan identity is invalid')
  const ref = StringValue(Plan.sourceRef, 'Helm chart release plan sourceRef')
  const revision = StringValue(Plan.sourceRevision, 'Helm chart release plan sourceRevision')
  const version = StringValue(Plan.releaseVersion, 'Helm chart release plan releaseVersion')
  try { ParseReleaseTag(version) } catch { throw new Error('Helm chart release plan source identity is invalid') }
  if (!FullRevision.test(revision) || !Semver.test(version) || ref !== `refs/tags/${version}`) throw new Error('Helm chart release plan source identity is invalid')
  NumberValue(Plan.commitEpoch, 'Helm chart release plan commitEpoch')
  if (!Array.isArray(Plan.charts) || Plan.charts.length !== Charts.length) throw new Error('Helm chart release plan must contain exactly two charts')
  for (const [Index, Expected] of Charts.entries()) {
    if (!IsObject(Plan.charts[Index]) || Plan.charts[Index].name !== Expected.name) throw new Error('Helm chart release plan chart order is not canonical')
  }
  return Plan
}

function PlanChart(Value: unknown, Expected: typeof Charts[number], Version: string): JsonObject {
  const Chart = ObjectValue(Value, `Helm chart plan ${Expected.name}`)
  ExactKeys(Chart, ['name', 'sourceDirectory', 'targetOciRepository', 'filename', 'archiveSha256', 'metadata', 'experimentalStatus', 'defaultImages', 'transformationRecipe'], `Helm chart plan ${Expected.name}`)
  if (Chart.name !== Expected.name || Chart.sourceDirectory !== Expected.directory || Chart.targetOciRepository !== Expected.repository || Chart.filename !== `${Expected.name}-${Version}.tgz`) throw new Error(`Helm chart plan identity is invalid for ${Expected.name}`)
  if (!Sha256.test(StringValue(Chart.archiveSha256, `${Expected.name}.archiveSha256`))) throw new Error(`Helm chart plan archive digest is invalid for ${Expected.name}`)
  if (Chart.experimentalStatus !== 'experimental') throw new Error(`Helm chart plan must retain experimental status for ${Expected.name}`)
  const Metadata = ObjectValue(Chart.metadata, `${Expected.name}.metadata`)
  ExactKeys(Metadata, ['version', 'appVersion', 'annotations'], `${Expected.name}.metadata`)
  for (const Key of ['version', 'appVersion']) StringValue(Metadata[Key], `${Expected.name}.metadata.${Key}`)
  if (Metadata.version !== Version || Metadata.appVersion !== Version) throw new Error(`Helm chart plan metadata is invalid for ${Expected.name}`)
  const Annotations = ObjectValue(Metadata.annotations, `${Expected.name}.metadata.annotations`)
  ExactCanonical(Annotations, ExpectedAnnotations, `Helm chart plan annotations for ${Expected.name}`)
  const ExpectedImages = Expected.defaultImagePaths.map(path => ({ path, from: 'latest', to: Version }))
  if (!Array.isArray(Chart.defaultImages) || !Chart.defaultImages.every(Item => IsObject(Item))) throw new Error(`Helm chart plan default image inventory is invalid for ${Expected.name}`)
  for (const Image of Chart.defaultImages) {
    ExactKeys(Image, ['path', 'from', 'to'], `${Expected.name}.defaultImage`)
    if (typeof Image.path !== 'string' || Image.from !== 'latest' || Image.to !== Version) throw new Error(`Helm chart plan default image transformation is invalid for ${Expected.name}`)
  }
  ExactCanonical(Chart.defaultImages, ExpectedImages, `Helm chart plan default images for ${Expected.name}`)
  ExactCanonical(Chart.transformationRecipe, ExpectedTransformationRecipe, `Helm chart plan transformation recipe for ${Expected.name}`)
  return Chart
}

function BoundedBytes(Value: unknown, MaximumBytes: number, Label: string): Buffer {
  if (!Buffer.isBuffer(Value) || Value.length === 0 || Value.length > MaximumBytes) throw new Error(`${Label} must be non-empty bounded bytes`)
  return Value
}

function ManifestValue(Artifact: HelmChartOciArtifact | undefined, ExpectedDigest: string, ExpectedSize: number, Label: string): { descriptor: { bytes: number, sha256: string }, digest: string, mediaType: string, bytes: number, config: Descriptor, layers: [Descriptor] } {
  if (Artifact === undefined) throw new Error(`${Label} OCI artifact evidence is missing`)
  const DescriptorDocument = ObjectValue(ParseStrictJson(BoundedBytes(Artifact.descriptorBytes, MaximumHelmChartOciJsonBytes, `${Label} OCI descriptor`), `${Label} OCI descriptor`), `${Label} OCI descriptor`)
  const DescriptorBinding = DescriptorValue(DescriptorDocument, `${Label} OCI descriptor`)
  if (DescriptorBinding.mediaType !== 'application/vnd.oci.image.manifest.v1+json') throw new Error(`${Label} OCI descriptor media type is invalid`)
  const ManifestBytes = BoundedBytes(Artifact.manifestBytes, MaximumHelmChartOciJsonBytes, `${Label} OCI manifest`)
  const Manifest = ObjectValue(ParseStrictJson(ManifestBytes, `${Label} OCI manifest`), `${Label} OCI manifest`)
  const ManifestKeys = Object.keys(Manifest).sort().join(',')
  if (ManifestKeys !== 'config,layers,schemaVersion' && ManifestKeys !== 'config,layers,mediaType,schemaVersion') throw new Error(`${Label} OCI manifest has missing, unexpected, or substituted keys`)
  if (DescriptorBinding.digest !== `sha256:${HelmChartOciSha256(ManifestBytes)}` || DescriptorBinding.size !== ManifestBytes.length || Manifest.schemaVersion !== 2 || ('mediaType' in Manifest && Manifest.mediaType !== DescriptorBinding.mediaType)) throw new Error(`${Label} OCI descriptor does not bind exact raw manifest bytes`)
  const digest = DescriptorBinding.digest
  const mediaType = DescriptorBinding.mediaType
  const config = DescriptorValue(Manifest.config, `${Label} OCI manifest.config`)
  if (config.mediaType !== ChartConfigMediaType) throw new Error(`${Label} OCI config media type is invalid`)
  const ConfigBytes = BoundedBytes(Artifact.configBytes, MaximumHelmChartOciJsonBytes, `${Label} OCI config`)
  if (config.digest !== `sha256:${HelmChartOciSha256(ConfigBytes)}` || config.size !== ConfigBytes.length) throw new Error(`${Label} OCI config does not bind exact raw config bytes`)
  if (!Array.isArray(Manifest.layers) || Manifest.layers.length !== 1) throw new Error(`${Label} OCI manifest must contain exactly one chart-content layer`)
  const layer = DescriptorValue(Manifest.layers[0], `${Label} OCI manifest.layers[0]`)
  if (layer.mediaType !== ChartContentMediaType || layer.digest !== `sha256:${ExpectedDigest}` || layer.size !== ExpectedSize) throw new Error(`${Label} OCI chart layer does not bind the exact package bytes`)
  return { descriptor: { bytes: Artifact.descriptorBytes.length, sha256: HelmChartOciSha256(Artifact.descriptorBytes) }, digest, mediaType, bytes: ManifestBytes.length, config, layers: [layer] }
}

function ReceiptManifestValue(Value: unknown, ExpectedDigest: string, ExpectedSize: number, Label: string): { descriptor: { bytes: number, sha256: string }, digest: string, mediaType: string, bytes: number, config: Descriptor, layers: [Descriptor] } {
  const Manifest = ObjectValue(Value, `${Label} OCI manifest`)
  ExactKeys(Manifest, ['descriptor', 'digest', 'mediaType', 'bytes', 'config', 'layers'], `${Label} OCI manifest`)
  const DescriptorReceipt = ObjectValue(Manifest.descriptor, `${Label} OCI manifest.descriptor`)
  ExactKeys(DescriptorReceipt, ['bytes', 'sha256'], `${Label} OCI manifest.descriptor`)
  const DescriptorBytes = NumberValue(DescriptorReceipt.bytes, `${Label} OCI manifest.descriptor.bytes`)
  const DescriptorSha256 = StringValue(DescriptorReceipt.sha256, `${Label} OCI manifest.descriptor.sha256`)
  if (DescriptorBytes === 0 || DescriptorBytes > MaximumHelmChartOciJsonBytes || !Sha256.test(DescriptorSha256)) throw new Error(`${Label} OCI descriptor evidence is invalid`)
  const digest = StringValue(Manifest.digest, `${Label} OCI manifest.digest`)
  const mediaType = StringValue(Manifest.mediaType, `${Label} OCI manifest.mediaType`)
  const ManifestBytes = NumberValue(Manifest.bytes, `${Label} OCI manifest.bytes`)
  if (!Digest.test(digest) || mediaType !== 'application/vnd.oci.image.manifest.v1+json' || ManifestBytes === 0 || ManifestBytes > MaximumHelmChartOciJsonBytes) throw new Error(`${Label} OCI manifest identity or size is invalid`)
  const config = DescriptorValue(Manifest.config, `${Label} OCI manifest.config`)
  if (config.mediaType !== ChartConfigMediaType || config.size > MaximumHelmChartOciJsonBytes) throw new Error(`${Label} OCI config media type or size is invalid`)
  if (!Array.isArray(Manifest.layers) || Manifest.layers.length !== 1) throw new Error(`${Label} OCI manifest must contain exactly one chart-content layer`)
  const layer = DescriptorValue(Manifest.layers[0], `${Label} OCI manifest.layers[0]`)
  if (layer.mediaType !== ChartContentMediaType || layer.digest !== `sha256:${ExpectedDigest}` || layer.size !== ExpectedSize) throw new Error(`${Label} OCI chart layer does not bind the exact package bytes`)
  return { descriptor: { bytes: DescriptorBytes, sha256: DescriptorSha256 }, digest, mediaType, bytes: ManifestBytes, config, layers: [layer] }
}

export function BuildHelmChartPublishReceipt(Options: BuildHelmChartPublishReceiptOptions): HelmChartPublishReceipt {
  if (Options.planBytes.length === 0 || Options.planBytes.length > MaximumHelmChartOciPlanBytes) throw new Error(`Helm chart release plan must be non-empty and at most ${MaximumHelmChartOciPlanBytes} bytes`)
  const Plan = PlanValue(ParseCanonicalJson(Options.planBytes, 'Helm chart release plan'))
  const Version = StringValue(Plan.releaseVersion, 'Helm chart release plan releaseVersion')
  const ChartPlans = Charts.map((Expected, Index) => PlanChart((Plan.charts as unknown[])[Index], Expected, Version))
  const Receipt: HelmChartPublishReceipt = {
    schemaVersion: HelmChartPublishReceiptSchemaVersion,
    kind: 'helm-chart-publish',
    repository: Repository,
    repositoryProvenance: Provenance,
    source: { ref: Plan.sourceRef as string, revision: Plan.sourceRevision as string, commitEpoch: Plan.commitEpoch as number, releaseVersion: Version },
    plan: { bytes: Options.planBytes.length, sha256: HelmChartOciSha256(Options.planBytes) },
    charts: ChartPlans.map((Chart, Index) => {
      const Expected = Charts[Index]
      const Archive = Options.archives[Expected.name]
      if (!Buffer.isBuffer(Archive) || Archive.length === 0 || Archive.length > MaximumHelmChartOciArchiveBytes) throw new Error(`package bytes must be non-empty and at most ${MaximumHelmChartOciArchiveBytes} bytes for ${Expected.name}`)
      const archiveSha256 = HelmChartOciSha256(Archive)
      if (archiveSha256 !== Chart.archiveSha256) throw new Error(`package bytes do not match the plan digest for ${Expected.name}`)
      const Manifest = ManifestValue(Options.artifacts[Expected.name], archiveSha256, Archive.length, Expected.name)
      return {
        name: Expected.name, sourceDirectory: Expected.directory, targetOciRepository: Expected.repository, tag: Version,
        filename: Chart.filename as string, package: { bytes: Archive.length, sha256: archiveSha256 },
        metadata: Chart.metadata as HelmChartPublishReceipt['charts'][number]['metadata'], experimentalStatus: 'experimental',
        defaultImages: Chart.defaultImages as HelmChartPublishReceipt['charts'][number]['defaultImages'],
        transformationRecipe: Chart.transformationRecipe as string[], manifest: Manifest
      }
    })
  }
  return ValidateHelmChartPublishReceipt(Receipt)
}

export function ValidateHelmChartPublishReceipt(Value: unknown): HelmChartPublishReceipt {
  const Receipt = ObjectValue(Value, 'Helm chart publish receipt')
  ExactKeys(Receipt, ['schemaVersion', 'kind', 'repository', 'repositoryProvenance', 'source', 'plan', 'charts'], 'Helm chart publish receipt')
  if (Receipt.schemaVersion !== HelmChartPublishReceiptSchemaVersion || Receipt.kind !== 'helm-chart-publish' || Receipt.repository !== Repository || Receipt.repositoryProvenance !== Provenance) throw new Error('Helm chart publish receipt identity is invalid')
  const Source = ObjectValue(Receipt.source, 'Helm chart publish receipt source')
  ExactKeys(Source, ['ref', 'revision', 'commitEpoch', 'releaseVersion'], 'Helm chart publish receipt source')
  const Version = StringValue(Source.releaseVersion, 'Helm chart publish receipt source.releaseVersion')
  try { ParseReleaseTag(Version) } catch { throw new Error('Helm chart publish receipt source identity is invalid') }
  if (!Semver.test(Version) || Source.ref !== `refs/tags/${Version}` || !FullRevision.test(StringValue(Source.revision, 'Helm chart publish receipt source.revision'))) throw new Error('Helm chart publish receipt source identity is invalid')
  NumberValue(Source.commitEpoch, 'Helm chart publish receipt source.commitEpoch')
  const Plan = ObjectValue(Receipt.plan, 'Helm chart publish receipt plan')
  ExactKeys(Plan, ['bytes', 'sha256'], 'Helm chart publish receipt plan')
  const PlanBytes = NumberValue(Plan.bytes, 'Helm chart publish receipt plan.bytes')
  if (PlanBytes === 0 || PlanBytes > MaximumHelmChartOciPlanBytes) throw new Error('Helm chart publish receipt plan size is outside the bounded contract')
  if (!Sha256.test(StringValue(Plan.sha256, 'Helm chart publish receipt plan.sha256'))) throw new Error('Helm chart publish receipt plan digest is invalid')
  if (!Array.isArray(Receipt.charts) || Receipt.charts.length !== Charts.length) throw new Error('Helm chart publish receipt must contain exactly two charts')
  const Result = Receipt as unknown as HelmChartPublishReceipt
  for (const [Index, Expected] of Charts.entries()) {
    const Chart = ObjectValue(Receipt.charts[Index], `Helm chart publish receipt ${Expected.name}`)
    ExactKeys(Chart, ['name', 'sourceDirectory', 'targetOciRepository', 'tag', 'filename', 'package', 'metadata', 'experimentalStatus', 'defaultImages', 'transformationRecipe', 'manifest'], `Helm chart publish receipt ${Expected.name}`)
    if (Chart.name !== Expected.name || Chart.sourceDirectory !== Expected.directory || Chart.targetOciRepository !== Expected.repository || Chart.tag !== Version || Chart.filename !== `${Expected.name}-${Version}.tgz` || Chart.experimentalStatus !== 'experimental') throw new Error(`Helm chart publish receipt chart identity is invalid for ${Expected.name}`)
    const Package = ObjectValue(Chart.package, `${Expected.name}.package`); ExactKeys(Package, ['bytes', 'sha256'], `${Expected.name}.package`)
    const Size = NumberValue(Package.bytes, `${Expected.name}.package.bytes`); const Hash = StringValue(Package.sha256, `${Expected.name}.package.sha256`)
    if (!Sha256.test(Hash) || Size === 0 || Size > MaximumHelmChartOciArchiveBytes) throw new Error(`Helm chart publish receipt package binding is invalid for ${Expected.name}`)
    const Manifest = ReceiptManifestValue(Chart.manifest, Hash, Size, Expected.name)
    const ExpectedImages = Expected.defaultImagePaths.map(path => ({ path, from: 'latest', to: Version }))
    if (!Array.isArray(Chart.defaultImages) || !Chart.defaultImages.every(Item => {
      if (!IsObject(Item)) return false
      ExactKeys(Item, ['path', 'from', 'to'], `${Expected.name}.defaultImage`)
      return Item.from === 'latest' && Item.to === Version && typeof Item.path === 'string'
    })) throw new Error(`Helm chart publish receipt transformation contract is invalid for ${Expected.name}`)
    ExactCanonical(Chart.defaultImages, ExpectedImages, `Helm chart publish receipt default images for ${Expected.name}`)
    ExactCanonical(Chart.transformationRecipe, ExpectedTransformationRecipe, `Helm chart publish receipt transformation recipe for ${Expected.name}`)
    const Metadata = ObjectValue(Chart.metadata, `${Expected.name}.metadata`)
    ExactKeys(Metadata, ['version', 'appVersion', 'annotations'], `${Expected.name}.metadata`)
    const Annotations = ObjectValue(Metadata.annotations, `${Expected.name}.annotations`)
    if (Metadata.version !== Version || Metadata.appVersion !== Version) throw new Error(`Helm chart publish receipt metadata is invalid for ${Expected.name}`)
    ExactCanonical(Annotations, ExpectedAnnotations, `Helm chart publish receipt annotations for ${Expected.name}`)
    Result.charts[Index].manifest = Manifest
  }
  return Result
}

function BoundedArchive(Value: Buffer | undefined, Label: string): Buffer {
  if (!Buffer.isBuffer(Value) || Value.length === 0 || Value.length > MaximumHelmChartOciArchiveBytes) throw new Error(`${Label} must be a non-empty bounded chart archive`)
  return Value
}

function ValidateRebuiltPlanBinding(Plan: JsonObject, Receipt: HelmChartPublishReceipt): void {
  const Version = StringValue(Plan.releaseVersion, 'rebuilt Helm chart release plan releaseVersion')
  if (Plan.sourceRef !== Receipt.source.ref || Plan.sourceRevision !== Receipt.source.revision || Plan.commitEpoch !== Receipt.source.commitEpoch || Version !== Receipt.source.releaseVersion) {
    throw new Error('rebuilt chart plan source does not exactly match the validated publish receipt')
  }
  for (const [Index, Expected] of Charts.entries()) {
    const Chart = PlanChart((Plan.charts as unknown[])[Index], Expected, Version)
    if (Chart.archiveSha256 !== Receipt.charts[Index].package.sha256) throw new Error(`rebuilt ${Expected.name} chart plan does not bind the validated published package`)
  }
}

export function BuildHelmChartRebuildPredicate(Options: BuildHelmChartRebuildPredicateOptions): JsonObject {
  const Receipt = ValidateHelmChartPublishReceipt(Options.receipt)
  if (Options.rebuiltPlanBytes.length === 0 || Options.rebuiltPlanBytes.length > MaximumHelmChartOciPlanBytes) throw new Error('rebuilt chart plan must be non-empty and bounded')
  const RebuiltPlan = PlanValue(ParseCanonicalJson(Options.rebuiltPlanBytes, 'rebuilt Helm chart release plan'))
  if (Options.rebuiltPlanBytes.length !== Receipt.plan.bytes || HelmChartOciSha256(Options.rebuiltPlanBytes) !== Receipt.plan.sha256) throw new Error('rebuilt chart plan does not exactly match the validated publish receipt')
  ValidateRebuiltPlanBinding(RebuiltPlan, Receipt)
  for (const Chart of Receipt.charts) {
    const Published = BoundedArchive(Options.publishedArchives[Chart.name], `published ${Chart.name}`)
    const Rebuilt = BoundedArchive(Options.rebuiltArchives[Chart.name], `rebuilt ${Chart.name}`)
    if (Published.length !== Chart.package.bytes || HelmChartOciSha256(Published) !== Chart.package.sha256) throw new Error(`published ${Chart.name} archive does not match the validated publish receipt`)
    if (!Published.equals(Rebuilt)) throw new Error(`rebuilt ${Chart.name} archive is not byte-for-byte identical to the validated published archive`)
  }
  const Predicate: JsonObject = {
    schemaVersion: HelmChartRebuildPredicateSchemaVersion, predicateType: HelmChartRebuildPredicateType, kind: 'helm-chart', receipt: Receipt,
    comparison: { schemaVersion: 1, exactPackageBytes: true, deterministicPackager: 'v4.2.3', consumptionHelmVersions: ['v3.21.3', 'v4.2.3'] }
  }
  return ValidateHelmChartRebuildPredicate(Predicate)
}

export function ValidateHelmChartRebuildPredicate(Value: unknown): JsonObject {
  const Predicate = ObjectValue(Value, 'Helm chart rebuild predicate')
  ExactKeys(Predicate, ['schemaVersion', 'predicateType', 'kind', 'receipt', 'comparison'], 'Helm chart rebuild predicate')
  if (Predicate.schemaVersion !== HelmChartRebuildPredicateSchemaVersion || Predicate.predicateType !== HelmChartRebuildPredicateType || Predicate.kind !== 'helm-chart') throw new Error('Helm chart rebuild predicate identity is invalid')
  ValidateHelmChartPublishReceipt(Predicate.receipt)
  const Comparison = ObjectValue(Predicate.comparison, 'Helm chart rebuild predicate comparison')
  ExactKeys(Comparison, ['schemaVersion', 'exactPackageBytes', 'deterministicPackager', 'consumptionHelmVersions'], 'Helm chart rebuild predicate comparison')
  if (Comparison.schemaVersion !== 1 || Comparison.exactPackageBytes !== true || Comparison.deterministicPackager !== 'v4.2.3' || Canonical(Comparison.consumptionHelmVersions) !== Canonical(['v3.21.3', 'v4.2.3'])) throw new Error('Helm chart rebuild predicate comparison contract is invalid')
  return Predicate
}

function WriteCanonical(FilePath: string, Value: unknown): void {
  if (FilePath === '' || FilePath.includes('\0') || FilePath.split(Path.sep).includes('..')) throw new Error('OCI JSON output path is invalid')
  const ParentBinding = BindInputPath(Path.dirname(FilePath), 'OCI JSON output parent')
  const Target = Path.join(ParentBinding.resolved, Path.basename(FilePath))
  if (Target !== Path.resolve(FilePath)) throw new Error('OCI JSON output path is invalid')
  const NoFollow = Fs.constants.O_NOFOLLOW
  if (NoFollow === undefined) throw new Error('OCI JSON output requires O_NOFOLLOW')
  let Descriptor: number | undefined
  try {
    Descriptor = Fs.openSync(Target, Fs.constants.O_WRONLY | Fs.constants.O_CREAT | Fs.constants.O_EXCL | NoFollow, 0o600)
    const Content = Buffer.from(`${Canonical(Value)}\n`, 'utf8')
    let Offset = 0
    while (Offset < Content.length) Offset += Fs.writeSync(Descriptor, Content, Offset, Content.length - Offset)
    Fs.fsyncSync(Descriptor)
  } finally {
    if (Descriptor !== undefined) Fs.closeSync(Descriptor)
  }
  VerifyInputPathBinding(ParentBinding.bindings, 'OCI JSON output parent')
}

type InputPathBinding = { path: string, dev: number, ino: number, mode: number }

function BindInputPath(FilePath: string, Label: string): { resolved: string, bindings: InputPathBinding[] } {
  if (FilePath === '' || FilePath.includes('\0') || FilePath.split(Path.sep).includes('..')) throw new Error(`${Label} path is invalid`)
  const Resolved = Path.resolve(FilePath)
  const Root = Path.parse(Resolved).root
  const Bindings: InputPathBinding[] = []
  let Current = Root
  for (const Segment of Resolved.slice(Root.length).split(Path.sep)) {
    if (Segment === '') continue
    Current = Path.join(Current, Segment)
    const Stat = Fs.lstatSync(Current)
    if (Stat.isSymbolicLink()) throw new Error(`${Label} path must not contain symlinks`)
    Bindings.push({ path: Current, dev: Stat.dev, ino: Stat.ino, mode: Stat.mode })
  }
  return { resolved: Resolved, bindings: Bindings }
}

function VerifyInputPathBinding(Bindings: InputPathBinding[], Label: string): void {
  for (const Binding of Bindings) {
    const Stat = Fs.lstatSync(Binding.path)
    if (Stat.isSymbolicLink() || Stat.dev !== Binding.dev || Stat.ino !== Binding.ino || Stat.mode !== Binding.mode) throw new Error(`${Label} path changed while it was read`)
  }
}

function BoundedRegularFile(FilePath: string, MaximumBytes: number, Label: string): Buffer {
  const PathBinding = BindInputPath(FilePath, Label)
  let Descriptor: number | undefined
  try {
    const NoFollow = Fs.constants.O_NOFOLLOW
    if (NoFollow === undefined) throw new Error('O_NOFOLLOW is unavailable')
    Descriptor = Fs.openSync(PathBinding.resolved, Fs.constants.O_RDONLY | NoFollow)
    const Before = Fs.fstatSync(Descriptor)
    if (!Before.isFile() || Before.size <= 0 || Before.size > MaximumBytes) throw new Error(`${Label} must be a non-empty regular file within its byte limit`)
    const Content = Buffer.allocUnsafe(Before.size)
    let Offset = 0
    while (Offset < Content.length) {
      const Read = Fs.readSync(Descriptor, Content, Offset, Content.length - Offset, null)
      if (Read === 0) throw new Error(`${Label} changed while it was read`)
      Offset += Read
    }
    const Extra = Buffer.allocUnsafe(1)
    if (Fs.readSync(Descriptor, Extra, 0, Extra.length, null) !== 0) throw new Error(`${Label} grew while it was read`)
    const After = Fs.fstatSync(Descriptor)
    if (!After.isFile() || After.size !== Before.size || After.dev !== Before.dev || After.ino !== Before.ino || After.mtimeMs !== Before.mtimeMs || After.ctimeMs !== Before.ctimeMs) throw new Error(`${Label} changed while it was read`)
    VerifyInputPathBinding(PathBinding.bindings, Label)
    return Content
  } catch (ErrorValue) {
    if (ErrorValue instanceof Error && ErrorValue.message.startsWith(Label)) throw ErrorValue
    throw new Error(`${Label} must be a non-empty regular non-symlink file within its byte limit`)
  } finally {
    if (Descriptor !== undefined) Fs.closeSync(Descriptor)
  }
}

function CliValues(Arguments: string[], Allowed: string[]): Record<string, string> {
  const Values: Record<string, string> = {}
  for (let Index = 0; Index < Arguments.length; Index += 2) {
    const Name = Arguments[Index]
    const Value = Arguments[Index + 1]
    if (!Allowed.includes(Name)) throw new Error(`unknown option: ${Name ?? '<missing>'}`)
    if (Value === undefined || Value === '' || Value.startsWith('--')) throw new Error(`${Name} must have exactly one non-option value`)
    if (Values[Name] !== undefined) throw new Error(`${Name} must be supplied exactly once`)
    Values[Name] = Value
  }
  for (const Name of Allowed) if (Values[Name] === undefined) throw new Error(`${Name} must be supplied exactly once`)
  return Values
}

function RunCli(): void {
  const Mode = Process.argv[2]
  const Arguments = Process.argv.slice(3)
  if (Mode === 'validate-receipt') { const Values = CliValues(Arguments, ['--input']); ValidateHelmChartPublishReceipt(ReadCanonicalHelmChartOciJson(Values['--input'])); return }
  if (Mode === 'validate-predicate') { const Values = CliValues(Arguments, ['--input']); ValidateHelmChartRebuildPredicate(ReadCanonicalHelmChartOciJson(Values['--input'])); return }
  if (Mode === 'build-receipt') {
    const Values = CliValues(Arguments, ['--plan', '--oxibelt-archive', '--oxibelt-descriptor', '--oxibelt-manifest', '--oxibelt-config', '--controller-archive', '--controller-descriptor', '--controller-manifest', '--controller-config', '--output'])
    WriteCanonical(Values['--output'], BuildHelmChartPublishReceipt({
      planBytes: BoundedRegularFile(Values['--plan'], MaximumHelmChartOciPlanBytes, 'release plan'),
      archives: {
        oxibelt: BoundedRegularFile(Values['--oxibelt-archive'], MaximumHelmChartOciArchiveBytes, 'oxibelt archive'),
        'oxibelt-gateway-controller': BoundedRegularFile(Values['--controller-archive'], MaximumHelmChartOciArchiveBytes, 'controller archive')
      },
      artifacts: {
        oxibelt: {
          descriptorBytes: BoundedRegularFile(Values['--oxibelt-descriptor'], MaximumHelmChartOciJsonBytes, 'oxibelt descriptor'),
          manifestBytes: BoundedRegularFile(Values['--oxibelt-manifest'], MaximumHelmChartOciJsonBytes, 'oxibelt manifest'),
          configBytes: BoundedRegularFile(Values['--oxibelt-config'], MaximumHelmChartOciJsonBytes, 'oxibelt config')
        },
        'oxibelt-gateway-controller': {
          descriptorBytes: BoundedRegularFile(Values['--controller-descriptor'], MaximumHelmChartOciJsonBytes, 'controller descriptor'),
          manifestBytes: BoundedRegularFile(Values['--controller-manifest'], MaximumHelmChartOciJsonBytes, 'controller manifest'),
          configBytes: BoundedRegularFile(Values['--controller-config'], MaximumHelmChartOciJsonBytes, 'controller config')
        }
      }
    }))
    return
  }
  if (Mode === 'build-predicate') {
    const Values = CliValues(Arguments, ['--receipt', '--rebuilt-plan', '--published-oxibelt', '--rebuilt-oxibelt', '--published-controller', '--rebuilt-controller', '--output'])
    WriteCanonical(Values['--output'], BuildHelmChartRebuildPredicate({
      receipt: ReadCanonicalHelmChartOciJson(Values['--receipt']),
      rebuiltPlanBytes: BoundedRegularFile(Values['--rebuilt-plan'], MaximumHelmChartOciPlanBytes, 'rebuilt chart plan'),
      publishedArchives: {
        oxibelt: BoundedRegularFile(Values['--published-oxibelt'], MaximumHelmChartOciArchiveBytes, 'published oxibelt archive'),
        'oxibelt-gateway-controller': BoundedRegularFile(Values['--published-controller'], MaximumHelmChartOciArchiveBytes, 'published controller archive')
      },
      rebuiltArchives: {
        oxibelt: BoundedRegularFile(Values['--rebuilt-oxibelt'], MaximumHelmChartOciArchiveBytes, 'rebuilt oxibelt archive'),
        'oxibelt-gateway-controller': BoundedRegularFile(Values['--rebuilt-controller'], MaximumHelmChartOciArchiveBytes, 'rebuilt controller archive')
      }
    }))
    return
  }
  throw new Error('usage: helm_chart_oci_release.ts <build-receipt|validate-receipt|build-predicate|validate-predicate>')
}

if (Process.argv[1] !== undefined && import.meta.url === pathToFileURL(Process.argv[1]).href) {
  try { RunCli() } catch (ErrorValue) { console.error(`Helm chart OCI release failed: ${ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)}`); Process.exit(1) }
}
