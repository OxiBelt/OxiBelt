import * as Assert from 'node:assert/strict'
import * as Fs from 'node:fs'
import * as Os from 'node:os'
import * as Path from 'node:path'
import { execFileSync } from 'node:child_process'
import test from 'node:test'
import {
  BuildHelmChartPublishReceipt,
  BuildHelmChartRebuildPredicate,
  HelmChartOciSha256,
  HelmChartRebuildPredicateType,
  MaximumHelmChartOciEnvelopeBytes,
  MaximumHelmChartOciJsonBytes,
  ReadCanonicalHelmChartOciJson,
  ValidateHelmChartPublishReceipt,
  ValidateHelmChartRebuildPredicate
} from '../sources/helm_chart_oci_release.js'

const Source = Path.resolve(Path.dirname(new URL(import.meta.url).pathname), '../sources/helm_chart_oci_release.ts')

function Canonical(Value: unknown): string {
  if (Array.isArray(Value)) return `[${Value.map(Canonical).join(',')}]`
  if (typeof Value === 'object' && Value !== null) {
    const ObjectValue = Value as Record<string, unknown>
    return `{${Object.keys(ObjectValue).sort().map(Key => `${JSON.stringify(Key)}:${Canonical(ObjectValue[Key])}`).join(',')}}`
  }
  return JSON.stringify(Value)
}

function Artifact(Archive: Buffer, Annotations?: Record<string, string>) {
  const ConfigBytes = Buffer.from('{"chart":"oci"}', 'utf8')
  const Manifest = {
    schemaVersion: 2,
    config: { mediaType: 'application/vnd.cncf.helm.config.v1+json', digest: `sha256:${HelmChartOciSha256(ConfigBytes)}`, size: ConfigBytes.length },
    layers: [{ mediaType: 'application/vnd.cncf.helm.chart.content.v1.tar+gzip', digest: `sha256:${HelmChartOciSha256(Archive)}`, size: Archive.length }],
    ...(Annotations === undefined ? {} : { annotations: Annotations })
  }
  const ManifestBytes = Buffer.from(JSON.stringify(Manifest, null, 2), 'utf8')
  const Descriptor = { mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: `sha256:${HelmChartOciSha256(ManifestBytes)}`, size: ManifestBytes.length }
  return { descriptorBytes: Buffer.from(JSON.stringify(Descriptor, null, 2), 'utf8'), manifestBytes: ManifestBytes, configBytes: ConfigBytes }
}

function Fixture() {
  const Directory = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-oci-'))
  const Archives = { oxibelt: Buffer.from('data chart'), 'oxibelt-gateway-controller': Buffer.from('controller chart') }
  const Version = '1.2.3-beta.1'
  const Metadata = () => ({ version: Version, appVersion: Version, annotations: { 'oxibelt.dev/feature-status': 'experimental', 'oxibelt.dev/kubernetes-support-policy': '1' } })
  const Recipe = [
    'read only Git-tracked regular blobs from the exact commit tree',
    'normalize staged directories to 0755 and staged files to 0644 at commit epoch',
    'replace only declared image.tag latest defaults with the exact release SemVer',
    'helm package with exact --version and --app-version',
    'reject noncanonical, unexpected, duplicate, or partial archive members'
  ]
  const Plan = {
    schemaVersion: 1, repository: 'OxiBelt/OxiBelt', repositoryProvenance: 'github-workflow-authentication-required', sourceRef: `refs/tags/${Version}`, sourceRevision: 'a'.repeat(40), commitEpoch: 123, releaseVersion: Version,
    charts: [
      { name: 'oxibelt', sourceDirectory: 'deploy/helm/oxibelt', targetOciRepository: 'oci://ghcr.io/oxibelt/charts/oxibelt', filename: `oxibelt-${Version}.tgz`, archiveSha256: HelmChartOciSha256(Archives.oxibelt), metadata: Metadata(), experimentalStatus: 'experimental', defaultImages: [{ path: 'deploy/helm/oxibelt/values.yaml', from: 'latest', to: Version }, { path: 'deploy/helm/oxibelt/examples/strict-dataplane-values.yaml', from: 'latest', to: Version }], transformationRecipe: Recipe },
      { name: 'oxibelt-gateway-controller', sourceDirectory: 'deploy/helm/oxibelt-gateway-controller', targetOciRepository: 'oci://ghcr.io/oxibelt/charts/oxibelt-gateway-controller', filename: `oxibelt-gateway-controller-${Version}.tgz`, archiveSha256: HelmChartOciSha256(Archives['oxibelt-gateway-controller']), metadata: Metadata(), experimentalStatus: 'experimental', defaultImages: [{ path: 'deploy/helm/oxibelt-gateway-controller/values.yaml', from: 'latest', to: Version }], transformationRecipe: Recipe }
    ]
  }
  const PlanBytes = Buffer.from(`${Canonical(Plan)}\n`)
  const Artifacts = { oxibelt: Artifact(Archives.oxibelt), 'oxibelt-gateway-controller': Artifact(Archives['oxibelt-gateway-controller']) }
  const Receipt = BuildHelmChartPublishReceipt({
    planBytes: PlanBytes, archives: Archives,
    artifacts: Artifacts
  })
  return { Directory, Archives, Artifacts, Plan, Receipt, PlanBytes }
}

function ForgedManifestReceipt(FixtureValue: ReturnType<typeof Fixture>, Index: number, ReplaceEvidence: boolean) {
  const Name = ['oxibelt', 'oxibelt-gateway-controller'][Index]
  const MaliciousArtifact = Artifact(Buffer.from(`malicious ${Name} chart`))
  const MaliciousDescriptor = JSON.parse(MaliciousArtifact.descriptorBytes.toString('utf8')) as Record<string, unknown>
  const ForgedReceipt = structuredClone(FixtureValue.Receipt)
  ForgedReceipt.charts[Index].manifest.digest = MaliciousDescriptor.digest as string
  ForgedReceipt.charts[Index].manifest.bytes = MaliciousDescriptor.size as number
  ForgedReceipt.charts[Index].manifest.descriptor = {
    bytes: MaliciousArtifact.descriptorBytes.length,
    sha256: HelmChartOciSha256(MaliciousArtifact.descriptorBytes)
  }
  if (ReplaceEvidence) {
    ForgedReceipt.charts[Index].manifest.evidence = {
      descriptorBase64: MaliciousArtifact.descriptorBytes.toString('base64'),
      manifestBase64: MaliciousArtifact.manifestBytes.toString('base64'),
      configBase64: MaliciousArtifact.configBytes.toString('base64')
    }
  }
  return ForgedReceipt
}

test('builds canonical exact two-chart OCI receipt and predicate', () => {
  const FixtureValue = Fixture()
  try {
    const { Receipt } = FixtureValue
    Assert.equal(Receipt.repository, 'OxiBelt/OxiBelt')
    Assert.equal(Receipt.repositoryProvenance, 'github-workflow-authentication-required')
    Assert.equal(Receipt.schemaVersion, 3)
    Assert.equal(Receipt.charts.length, 2)
    Assert.equal(Receipt.charts[0].manifest.layers[0].digest, `sha256:${Receipt.charts[0].package.sha256}`)
    Assert.deepEqual(Receipt.charts[0].manifest.descriptor, { bytes: FixtureValue.Artifacts.oxibelt.descriptorBytes.length, sha256: HelmChartOciSha256(FixtureValue.Artifacts.oxibelt.descriptorBytes) })
    Assert.equal(Receipt.charts[0].manifest.bytes, FixtureValue.Artifacts.oxibelt.manifestBytes.length)
    Assert.deepEqual(Receipt.charts[0].manifest.evidence, {
      descriptorBase64: FixtureValue.Artifacts.oxibelt.descriptorBytes.toString('base64'),
      manifestBase64: FixtureValue.Artifacts.oxibelt.manifestBytes.toString('base64'),
      configBase64: FixtureValue.Artifacts.oxibelt.configBytes.toString('base64')
    })
    const Predicate = BuildHelmChartRebuildPredicate({ receipt: Receipt, rebuiltPlanBytes: FixtureValue.PlanBytes, publishedArchives: FixtureValue.Archives, rebuiltArchives: FixtureValue.Archives })
    Assert.equal(Predicate.schemaVersion, 3)
    Assert.equal(HelmChartRebuildPredicateType, 'https://oxibelt.dev/attestations/helm-chart-rebuild/v3')
    Assert.equal(Predicate.predicateType, HelmChartRebuildPredicateType)
    Assert.deepEqual((Predicate.comparison as Record<string, unknown>).consumptionHelmVersions, ['v3.21.3', 'v4.2.4'])
    Assert.doesNotThrow(() => ValidateHelmChartPublishReceipt(structuredClone(Receipt)))
    Assert.doesNotThrow(() => ValidateHelmChartRebuildPredicate(structuredClone(Predicate)))
  } finally { Fs.rmSync(FixtureValue.Directory, { recursive: true, force: true }) }
})

test('accepts only exact Helm 4 OCI manifest annotations', () => {
  const FixtureValue = Fixture()
  try {
    const HelmAnnotations = (name: string, description: string) => ({
      'org.opencontainers.image.created': '2026-08-18T11:25:22Z',
      'org.opencontainers.image.description': description,
      'org.opencontainers.image.title': name,
      'org.opencontainers.image.version': '1.2.3-beta.1',
      'oxibelt.dev/feature-status': 'experimental',
      'oxibelt.dev/kubernetes-support-policy': '1'
    })
    const Build = (OxiBeltAnnotations: Record<string, string>, ControllerAnnotations: Record<string, string>) => BuildHelmChartPublishReceipt({
      planBytes: FixtureValue.PlanBytes,
      archives: FixtureValue.Archives,
      artifacts: {
        oxibelt: Artifact(FixtureValue.Archives.oxibelt, OxiBeltAnnotations),
        'oxibelt-gateway-controller': Artifact(FixtureValue.Archives['oxibelt-gateway-controller'], ControllerAnnotations)
      }
    })
    const OxiBeltAnnotations = HelmAnnotations('oxibelt', 'OxiBelt reverse proxy and WAF data plane')
    const ControllerAnnotations = HelmAnnotations('oxibelt-gateway-controller', 'OxiBelt Gateway API controller')
    Assert.doesNotThrow(() => Build(OxiBeltAnnotations, ControllerAnnotations))
    for (const Mutate of [
      (Annotations: Record<string, string>) => { delete Annotations['org.opencontainers.image.created'] },
      (Annotations: Record<string, string>) => { Annotations.extra = 'value' },
      (Annotations: Record<string, string>) => { Annotations['org.opencontainers.image.description'] = 'substituted' },
      (Annotations: Record<string, string>) => { Annotations['org.opencontainers.image.title'] = 'substituted' },
      (Annotations: Record<string, string>) => { Annotations['org.opencontainers.image.version'] = '1.2.3-beta.2' },
      (Annotations: Record<string, string>) => { Annotations['org.opencontainers.image.created'] = '2026-02-31T11:25:22Z' },
      (Annotations: Record<string, string>) => { Annotations['oxibelt.dev/feature-status'] = 'stable' },
      (Annotations: Record<string, string>) => { Annotations['oxibelt.dev/kubernetes-support-policy'] = '2' }
    ]) {
      const Forged = structuredClone(OxiBeltAnnotations)
      Mutate(Forged)
      Assert.throws(() => Build(Forged, ControllerAnnotations), /annotations/)
    }
  } finally { Fs.rmSync(FixtureValue.Directory, { recursive: true, force: true }) }
})

test('rejects plan/archive/manifest binding drift and receipt or predicate extras', () => {
  const FixtureValue = Fixture()
  try {
    const { Receipt, Archives } = FixtureValue
    const Plan = FixtureValue.PlanBytes
    Assert.throws(() => BuildHelmChartPublishReceipt({ planBytes: Plan, archives: { ...Archives, oxibelt: Buffer.from('mutated') }, artifacts: FixtureValue.Artifacts }), /do not match/)
    const BadArtifact = { ...FixtureValue.Artifacts.oxibelt, manifestBytes: Buffer.from('{"schemaVersion":2,"schemaVersion":2}', 'utf8') }
    Assert.throws(() => BuildHelmChartPublishReceipt({ planBytes: Plan, archives: Archives, artifacts: { ...FixtureValue.Artifacts, oxibelt: BadArtifact } }), /duplicate JSON key/)
    const BadDescriptor = { ...FixtureValue.Artifacts.oxibelt, descriptorBytes: Buffer.from(JSON.stringify({ mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: `sha256:${'0'.repeat(64)}`, size: FixtureValue.Artifacts.oxibelt.manifestBytes.length }), 'utf8') }
    Assert.throws(() => BuildHelmChartPublishReceipt({ planBytes: Plan, archives: Archives, artifacts: { ...FixtureValue.Artifacts, oxibelt: BadDescriptor } }), /does not bind exact raw manifest bytes/)
    const BadConfig = { ...FixtureValue.Artifacts.oxibelt, configBytes: Buffer.from('{"substituted":true}', 'utf8') }
    Assert.throws(() => BuildHelmChartPublishReceipt({ planBytes: Plan, archives: Archives, artifacts: { ...FixtureValue.Artifacts, oxibelt: BadConfig } }), /does not bind exact raw config bytes/)
    const Cases: Array<[unknown, RegExp]> = [
      [{ ...Receipt, extra: true }, /missing, unexpected/],
      [{ ...Receipt, charts: [Receipt.charts[1], Receipt.charts[0]] }, /identity is invalid/],
      [{ ...Receipt, repositoryProvenance: 'authenticated' }, /identity is invalid/],
      [{ ...Receipt, charts: [{ ...Receipt.charts[0], package: { ...Receipt.charts[0].package, sha256: '0'.repeat(64) } }, Receipt.charts[1]] }, /does not bind/]
    ]
    for (const [Value, Expected] of Cases) Assert.throws(() => ValidateHelmChartPublishReceipt(Value), Expected)
    const Predicate = BuildHelmChartRebuildPredicate({ receipt: Receipt, rebuiltPlanBytes: FixtureValue.PlanBytes, publishedArchives: FixtureValue.Archives, rebuiltArchives: FixtureValue.Archives })
    Assert.throws(() => ValidateHelmChartRebuildPredicate({ ...Predicate, comparison: { ...(Predicate.comparison as Record<string, unknown>), deterministicPackager: 'v3.21.3' } }), /comparison contract/)
    Assert.throws(() => ValidateHelmChartRebuildPredicate({ ...Predicate, unexpected: true }), /missing, unexpected/)
  } finally { Fs.rmSync(FixtureValue.Directory, { recursive: true, force: true }) }
})

test('bounded canonical file reads reject symlinks, whitespace, and duplicate-key encodings', () => {
  const Directory = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-oci-json-'))
  try {
    const File = Path.join(Directory, 'input.json')
    Fs.writeFileSync(File, '{"a":1}\n')
    Assert.deepEqual(ReadCanonicalHelmChartOciJson(File), { a: 1 })
    Fs.writeFileSync(File, '{ "a":1 }\n')
    Assert.throws(() => ReadCanonicalHelmChartOciJson(File), /canonical JSON/)
    Fs.writeFileSync(File, '{"a":1,"a":2}\n')
    Assert.throws(() => ReadCanonicalHelmChartOciJson(File), /duplicate JSON key/)
    Fs.writeFileSync(File, Buffer.alloc(MaximumHelmChartOciEnvelopeBytes + 1, 0x20))
    Assert.throws(() => ReadCanonicalHelmChartOciJson(File), /byte limit/)
    Fs.unlinkSync(File); Fs.writeFileSync(Path.join(Directory, 'target.json'), '{"a":1}\n'); Fs.symlinkSync('target.json', File)
    Assert.throws(() => ReadCanonicalHelmChartOciJson(File), /symlinks/)
    const ParentAlias = Path.join(Directory, 'parent-alias'); Fs.symlinkSync(Directory, ParentAlias)
    Assert.throws(() => ReadCanonicalHelmChartOciJson(Path.join(ParentAlias, 'target.json')), /symlinks/)
  } finally { Fs.rmSync(Directory, { recursive: true, force: true }) }
})

test('rejects substituted plan semantics, unsupported tags, and oversized evidence', () => {
  const FixtureValue = Fixture()
  try {
    const Build = (Plan: unknown, Archives = FixtureValue.Archives) => BuildHelmChartPublishReceipt({
      planBytes: Buffer.from(`${Canonical(Plan)}\n`), archives: Archives,
      artifacts: FixtureValue.Artifacts
    })
    const Cases: Array<[string, (Plan: Record<string, unknown>) => void]> = [
      ['duplicate default image path', Plan => { ((Plan.charts as Array<Record<string, unknown>>)[0].defaultImages as Array<Record<string, unknown>>)[1].path = 'deploy/helm/oxibelt/values.yaml' }],
      ['substituted default image path', Plan => { ((Plan.charts as Array<Record<string, unknown>>)[0].defaultImages as Array<Record<string, unknown>>)[1].path = 'deploy/helm/oxibelt/values-other.yaml' }],
      ['extra annotation', Plan => { (((Plan.charts as Array<Record<string, unknown>>)[0].metadata as Record<string, unknown>).annotations as Record<string, unknown>).extra = 'value' }],
      ['arbitrary recipe', Plan => { (Plan.charts as Array<Record<string, unknown>>)[0].transformationRecipe = ['arbitrary'] }],
      ['unsupported rc tag', Plan => { Plan.releaseVersion = '1.2.3-rc.1'; Plan.sourceRef = 'refs/tags/1.2.3-rc.1' }],
      ['reversed chart order', Plan => { (Plan.charts as unknown[]).reverse() }]
    ]
    for (const [Name, Mutate] of Cases) {
      const Plan = structuredClone(FixtureValue.Plan) as Record<string, unknown>
      Mutate(Plan)
      Assert.throws(() => Build(Plan), new RegExp(Name === 'unsupported rc tag' ? 'source identity' : Name === 'reversed chart order' ? 'chart order' : 'canonical release-plan contract'))
    }
    Assert.throws(() => BuildHelmChartPublishReceipt({ planBytes: Buffer.alloc(128 * 1024 + 1), archives: FixtureValue.Archives, artifacts: {} }), /at most/)
    Assert.throws(() => BuildHelmChartPublishReceipt({ planBytes: FixtureValue.PlanBytes, archives: { ...FixtureValue.Archives, oxibelt: Buffer.alloc(16 * 1024 * 1024 + 1) }, artifacts: FixtureValue.Artifacts }), /at most/)
    for (const Field of ['descriptorBytes', 'manifestBytes', 'configBytes'] as const) {
      Assert.throws(() => BuildHelmChartPublishReceipt({
        planBytes: FixtureValue.PlanBytes,
        archives: FixtureValue.Archives,
        artifacts: {
          ...FixtureValue.Artifacts,
          oxibelt: { ...FixtureValue.Artifacts.oxibelt, [Field]: Buffer.alloc(MaximumHelmChartOciJsonBytes + 1) }
        }
      }), /bounded bytes/)
    }
  } finally { Fs.rmSync(FixtureValue.Directory, { recursive: true, force: true }) }
})

test('rebuild predicates require exact independently rebuilt plan and package bytes', () => {
  const FixtureValue = Fixture()
  try {
    const Options = { receipt: FixtureValue.Receipt, rebuiltPlanBytes: FixtureValue.PlanBytes, publishedArchives: FixtureValue.Archives, rebuiltArchives: FixtureValue.Archives }
    Assert.doesNotThrow(() => BuildHelmChartRebuildPredicate(Options))
    Assert.throws(() => BuildHelmChartRebuildPredicate({ ...Options, rebuiltPlanBytes: Buffer.from('{}\n') }), /release plan/)
    Assert.throws(() => BuildHelmChartRebuildPredicate({ ...Options, rebuiltArchives: { ...FixtureValue.Archives, oxibelt: Buffer.from('substituted') } }), /byte-for-byte/)
    Assert.throws(() => BuildHelmChartRebuildPredicate({ ...Options, publishedArchives: { 'oxibelt-gateway-controller': FixtureValue.Archives['oxibelt-gateway-controller'] } }), /published oxibelt/)
    const ForgedPlan = structuredClone(FixtureValue.Plan) as Record<string, unknown>
    const ForgedChart = (ForgedPlan.charts as Array<Record<string, unknown>>)[0]
    ForgedChart.archiveSha256 = '0'.repeat(64)
    const ForgedPlanBytes = Buffer.from(`${Canonical(ForgedPlan)}\n`)
    const ForgedReceipt = structuredClone(FixtureValue.Receipt)
    ForgedReceipt.plan = { bytes: ForgedPlanBytes.length, sha256: HelmChartOciSha256(ForgedPlanBytes) }
    Assert.throws(() => BuildHelmChartRebuildPredicate({ ...Options, receipt: ForgedReceipt, rebuiltPlanBytes: ForgedPlanBytes }), /does not bind the validated published package/)
  } finally { Fs.rmSync(FixtureValue.Directory, { recursive: true, force: true }) }
})

test('rejects forged OCI manifest identities that do not contain the recorded package layer', () => {
  const FixtureValue = Fixture()
  try {
    for (const Index of [0, 1]) {
      const SummaryForgery = ForgedManifestReceipt(FixtureValue, Index, false)
      Assert.throws(() => ValidateHelmChartPublishReceipt(structuredClone(SummaryForgery)), /raw OCI evidence/)
      Assert.throws(() => BuildHelmChartRebuildPredicate({
        receipt: SummaryForgery,
        rebuiltPlanBytes: FixtureValue.PlanBytes,
        publishedArchives: FixtureValue.Archives,
        rebuiltArchives: FixtureValue.Archives
      }), /raw OCI evidence/)
      const EvidenceForgery = ForgedManifestReceipt(FixtureValue, Index, true)
      Assert.throws(() => ValidateHelmChartPublishReceipt(structuredClone(EvidenceForgery)), /does not bind the exact package bytes/)
      Assert.throws(() => BuildHelmChartRebuildPredicate({
        receipt: EvidenceForgery,
        rebuiltPlanBytes: FixtureValue.PlanBytes,
        publishedArchives: FixtureValue.Archives,
        rebuiltArchives: FixtureValue.Archives
      }), /does not bind the exact package bytes/)
      const Predicate = BuildHelmChartRebuildPredicate({
        receipt: FixtureValue.Receipt,
        rebuiltPlanBytes: FixtureValue.PlanBytes,
        publishedArchives: FixtureValue.Archives,
        rebuiltArchives: FixtureValue.Archives
      })
      const ForgedPredicate = structuredClone(Predicate)
      ForgedPredicate.receipt = EvidenceForgery
      Assert.throws(() => ValidateHelmChartRebuildPredicate(ForgedPredicate), /does not bind the exact package bytes/)
    }
  } finally { Fs.rmSync(FixtureValue.Directory, { recursive: true, force: true }) }
})

test('rejects substituted raw OCI evidence and all v2 receipt or predicate inputs', () => {
  const FixtureValue = Fixture()
  try {
    const NoncanonicalBase64 = structuredClone(FixtureValue.Receipt)
    NoncanonicalBase64.charts[0].manifest.evidence.descriptorBase64 = 'A==='
    Assert.throws(() => ValidateHelmChartPublishReceipt(NoncanonicalBase64), /canonical padded base64/)

    const DuplicateDescriptor = structuredClone(FixtureValue.Receipt)
    DuplicateDescriptor.charts[0].manifest.evidence.descriptorBase64 = Buffer.from('{"a":1,"a":2}', 'utf8').toString('base64')
    Assert.throws(() => ValidateHelmChartPublishReceipt(DuplicateDescriptor), /duplicate JSON key/)

    const DuplicateManifest = structuredClone(FixtureValue.Receipt)
    DuplicateManifest.charts[0].manifest.evidence.manifestBase64 = Buffer.from('{"schemaVersion":2,"schemaVersion":2}', 'utf8').toString('base64')
    Assert.throws(() => ValidateHelmChartPublishReceipt(DuplicateManifest), /duplicate JSON key/)

    const SubstitutedConfig = structuredClone(FixtureValue.Receipt)
    SubstitutedConfig.charts[0].manifest.evidence.configBase64 = Buffer.from('substituted config', 'utf8').toString('base64')
    Assert.throws(() => ValidateHelmChartPublishReceipt(SubstitutedConfig), /config does not bind exact raw config bytes/)

    const MissingEvidence = structuredClone(FixtureValue.Receipt) as unknown as Record<string, unknown>
    const MissingManifest = (MissingEvidence.charts as Array<Record<string, unknown>>)[0].manifest as Record<string, unknown>
    delete MissingManifest.evidence
    Assert.throws(() => ValidateHelmChartPublishReceipt(MissingEvidence), /missing, unexpected/)

    const LegacyReceipt = structuredClone(FixtureValue.Receipt) as unknown as Record<string, unknown>
    LegacyReceipt.schemaVersion = 2
    Assert.throws(() => ValidateHelmChartPublishReceipt(LegacyReceipt), /identity is invalid/)

    const LegacyPredicate = BuildHelmChartRebuildPredicate({ receipt: FixtureValue.Receipt, rebuiltPlanBytes: FixtureValue.PlanBytes, publishedArchives: FixtureValue.Archives, rebuiltArchives: FixtureValue.Archives })
    LegacyPredicate.schemaVersion = 2
    LegacyPredicate.predicateType = 'https://oxibelt.dev/attestations/helm-chart-rebuild/v2'
    Assert.throws(() => ValidateHelmChartRebuildPredicate(LegacyPredicate), /identity is invalid/)
  } finally { Fs.rmSync(FixtureValue.Directory, { recursive: true, force: true }) }
})

test('CLI accepts only exact option sets and writes newline-canonical predicates', () => {
  const FixtureValue = Fixture()
  try {
    const ReceiptPath = Path.join(FixtureValue.Directory, 'receipt.json')
    const PlanPath = Path.join(FixtureValue.Directory, 'plan.json')
    const PublishedOxiBelt = Path.join(FixtureValue.Directory, 'published-oxibelt.tgz')
    const RebuiltOxiBelt = Path.join(FixtureValue.Directory, 'rebuilt-oxibelt.tgz')
    const PublishedController = Path.join(FixtureValue.Directory, 'published-controller.tgz')
    const RebuiltController = Path.join(FixtureValue.Directory, 'rebuilt-controller.tgz')
    const Output = Path.join(FixtureValue.Directory, 'predicate.json')
    const ForgedReceiptPath = Path.join(FixtureValue.Directory, 'forged-receipt.json')
    const ForgedOutput = Path.join(FixtureValue.Directory, 'forged-predicate.json')
    const LegacyReceiptPath = Path.join(FixtureValue.Directory, 'legacy-receipt.json')
    const LegacyPredicatePath = Path.join(FixtureValue.Directory, 'legacy-predicate.json')
    const PublishReceipt = Path.join(FixtureValue.Directory, 'publish-receipt.json')
    const OxiBeltDescriptor = Path.join(FixtureValue.Directory, 'oxibelt-descriptor.json')
    const OxiBeltManifest = Path.join(FixtureValue.Directory, 'oxibelt-manifest.json')
    const OxiBeltConfig = Path.join(FixtureValue.Directory, 'oxibelt-config.json')
    const ControllerDescriptor = Path.join(FixtureValue.Directory, 'controller-descriptor.json')
    const ControllerManifest = Path.join(FixtureValue.Directory, 'controller-manifest.json')
    const ControllerConfig = Path.join(FixtureValue.Directory, 'controller-config.json')
    Fs.writeFileSync(ReceiptPath, `${Canonical(FixtureValue.Receipt)}\n`)
    Fs.writeFileSync(PlanPath, FixtureValue.PlanBytes)
    Fs.writeFileSync(PublishedOxiBelt, FixtureValue.Archives.oxibelt)
    Fs.writeFileSync(RebuiltOxiBelt, FixtureValue.Archives.oxibelt)
    Fs.writeFileSync(PublishedController, FixtureValue.Archives['oxibelt-gateway-controller'])
    Fs.writeFileSync(RebuiltController, FixtureValue.Archives['oxibelt-gateway-controller'])
    Fs.writeFileSync(OxiBeltDescriptor, FixtureValue.Artifacts.oxibelt.descriptorBytes)
    Fs.writeFileSync(OxiBeltManifest, FixtureValue.Artifacts.oxibelt.manifestBytes)
    Fs.writeFileSync(OxiBeltConfig, FixtureValue.Artifacts.oxibelt.configBytes)
    Fs.writeFileSync(ControllerDescriptor, FixtureValue.Artifacts['oxibelt-gateway-controller'].descriptorBytes)
    Fs.writeFileSync(ControllerManifest, FixtureValue.Artifacts['oxibelt-gateway-controller'].manifestBytes)
    Fs.writeFileSync(ControllerConfig, FixtureValue.Artifacts['oxibelt-gateway-controller'].configBytes)
    const Common = ['--receipt', ReceiptPath, '--rebuilt-plan', PlanPath, '--published-oxibelt', PublishedOxiBelt, '--rebuilt-oxibelt', RebuiltOxiBelt, '--published-controller', PublishedController, '--rebuilt-controller', RebuiltController, '--output', Output]
    const RunCli = (Arguments: string[]) => {
      try { execFileSync('node', ['--import', 'tsx', Source, ...Arguments], { stdio: 'pipe' }) }
      catch (ErrorValue) { throw new Error(Buffer.isBuffer((ErrorValue as Record<string, unknown>).stderr) ? ((ErrorValue as Record<string, unknown>).stderr as Buffer).toString('utf8') : String(ErrorValue)) }
    }
    RunCli(['build-predicate', ...Common])
    Assert.doesNotThrow(() => ReadCanonicalHelmChartOciJson(Output))
    RunCli(['validate-predicate', '--input', Output])
    const ReceiptArguments = ['--plan', PlanPath, '--oxibelt-archive', PublishedOxiBelt, '--oxibelt-descriptor', OxiBeltDescriptor, '--oxibelt-manifest', OxiBeltManifest, '--oxibelt-config', OxiBeltConfig, '--controller-archive', PublishedController, '--controller-descriptor', ControllerDescriptor, '--controller-manifest', ControllerManifest, '--controller-config', ControllerConfig, '--output', PublishReceipt]
    RunCli(['build-receipt', ...ReceiptArguments])
    Assert.doesNotThrow(() => ValidateHelmChartPublishReceipt(ReadCanonicalHelmChartOciJson(PublishReceipt)))
    RunCli(['validate-receipt', '--input', PublishReceipt])
    const ForgedReceipt = ForgedManifestReceipt(FixtureValue, 0, true)
    Fs.writeFileSync(ForgedReceiptPath, `${Canonical(ForgedReceipt)}\n`)
    Assert.throws(() => RunCli(['validate-receipt', '--input', ForgedReceiptPath]), /does not bind the exact package bytes/)
    const ForgedCommon = [...Common]
    ForgedCommon[1] = ForgedReceiptPath
    ForgedCommon[ForgedCommon.length - 1] = ForgedOutput
    Assert.throws(() => RunCli(['build-predicate', ...ForgedCommon]), /does not bind the exact package bytes/)
    const LegacyReceipt = structuredClone(FixtureValue.Receipt) as unknown as Record<string, unknown>
    LegacyReceipt.schemaVersion = 2
    Fs.writeFileSync(LegacyReceiptPath, `${Canonical(LegacyReceipt)}\n`)
    Assert.throws(() => RunCli(['validate-receipt', '--input', LegacyReceiptPath]), /identity is invalid/)
    const LegacyPredicate = BuildHelmChartRebuildPredicate({ receipt: FixtureValue.Receipt, rebuiltPlanBytes: FixtureValue.PlanBytes, publishedArchives: FixtureValue.Archives, rebuiltArchives: FixtureValue.Archives })
    LegacyPredicate.schemaVersion = 2
    LegacyPredicate.predicateType = 'https://oxibelt.dev/attestations/helm-chart-rebuild/v2'
    Fs.writeFileSync(LegacyPredicatePath, `${Canonical(LegacyPredicate)}\n`)
    Assert.throws(() => RunCli(['validate-predicate', '--input', LegacyPredicatePath]), /identity is invalid/)
    Assert.throws(() => RunCli(['build-predicate', ...Common, '--unknown', 'value']), /unknown option/)
    Assert.throws(() => RunCli(['validate-receipt', '--input', ReceiptPath, '--input', ReceiptPath]), /exactly once/)
    Assert.throws(() => RunCli(['validate-receipt', '--input']), /non-option value/)
    Assert.throws(() => RunCli(['validate-predicate', '--input', Output, '--unexpected', 'value']), /unknown option/)
    Assert.throws(() => RunCli(['build-receipt', '--plan', PlanPath, '--plan', PlanPath, ...ReceiptArguments.slice(2, -2), '--output', Path.join(FixtureValue.Directory, 'duplicate.json')]), /exactly once/)
    const OutputParentAlias = Path.join(FixtureValue.Directory, 'output-parent-alias')
    Fs.symlinkSync(FixtureValue.Directory, OutputParentAlias)
    Assert.throws(() => RunCli(['build-predicate', ...Common.slice(0, -2), '--output', Path.join(OutputParentAlias, 'predicate.json')]), /output parent.*symlinks/)
  } finally { Fs.rmSync(FixtureValue.Directory, { recursive: true, force: true }) }
})
