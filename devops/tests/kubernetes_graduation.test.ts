import * as Assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import * as Fs from 'node:fs'
import * as Path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  KubernetesGraduationFeatureIds,
  KubernetesGraduationPolicyDefinitionSha256,
  LoadKubernetesGraduationEvidenceDirectory,
  RenderKubernetesGraduationTables,
  ResolveKubernetesGraduationGitRefRevision,
  ValidateKubernetesGraduationEvidenceFiles,
  ValidateKubernetesGraduationEvidenceObject,
  ValidateKubernetesGraduationEvidenceSet,
  ValidateKubernetesGraduationPhaseRef,
  ValidateKubernetesGraduationPolicyObject,
  ValidateKubernetesGraduationWorkspace,
  type KubernetesGraduationEvidenceReceipt,
  type KubernetesGraduationPolicy
} from '../sources/kubernetes_graduation.js'

/* oxlint-disable oxibelt/pascal-case -- Fixture fields mirror detached receipt JSON. */
const RepoRoot = Path.resolve(Path.dirname(fileURLToPath(import.meta.url)), '../..')

function ReadJson(RelativePath: string): unknown {
  return JSON.parse(Fs.readFileSync(Path.join(RepoRoot, RelativePath), 'utf8')) as unknown
}

function CanonicalJson(Value: unknown): string {
  if (Array.isArray(Value)) {
    return `[${Value.map(Item => CanonicalJson(Item)).join(',')}]`
  }
  if (typeof Value === 'object' && Value !== null) {
    const ObjectValue = Value as Record<string, unknown>
    return `{${Object.keys(ObjectValue).sort().map(Key =>
      `${JSON.stringify(Key)}:${CanonicalJson(ObjectValue[Key])}`
    ).join(',')}}`
  }
  return JSON.stringify(Value)
}

function Policy(): KubernetesGraduationPolicy {
  return structuredClone(ValidateKubernetesGraduationPolicyObject(
    ReadJson('devops/config/kubernetes-feature-graduation.json'),
    ReadJson('devops/config/kubernetes-feature-graduation.schema.json')
  ))
}

function GitHead(): string {
  return execFileSync('git', ['-C', RepoRoot, 'rev-parse', '--verify', 'HEAD^{commit}'], {
    encoding: 'utf8', maxBuffer: 1024, stdio: ['ignore', 'pipe', 'pipe']
  }).trim()
}

function SupportedPolicy(
  FeatureIds: Array<(typeof KubernetesGraduationFeatureIds)[number]>
): KubernetesGraduationPolicy {
  const Result = Policy()
  for (const Feature of Result.features) {
    if (FeatureIds.includes(Feature.id)) {
      Feature.status = 'supported'
      Feature.lastValidatedVersion = Result.targetVersion
      Feature.blockerIds = []
    }
  }
  return ValidateKubernetesGraduationPolicyObject(
    Result,
    ReadJson('devops/config/kubernetes-feature-graduation.schema.json')
  )
}

function Receipt(
  PolicyValue: KubernetesGraduationPolicy,
  FeatureId: (typeof KubernetesGraduationFeatureIds)[number] = 'supply-chain-admission-bundle'
): KubernetesGraduationEvidenceReceipt {
  const Feature = PolicyValue.features.find(Candidate => Candidate.id === FeatureId)
  Assert.notEqual(Feature, undefined)
  if (Feature === undefined) {
    throw new Error(`missing fixture feature ${FeatureId}`)
  }
  const Revision = GitHead()
  const Jobs = Feature.qualifiedPlatforms.map((Platform, Index) => ({
    id: 456 + Index,
    name: `kubernetes qualification ${Platform}`,
    conclusion: 'success' as const
  }))
  const Reports = Feature.qualifiedPlatforms.map((Platform, Index) => ({
    name: `kubernetes-qualification-${Platform.slice('linux/'.length)}.json`,
    sha256: `${Index + 4}`.repeat(64)
  }))
  return {
    schemaVersion: 2,
    policyVersion: PolicyValue.policyVersion,
    policyDefinitionSha256: KubernetesGraduationPolicyDefinitionSha256(PolicyValue),
    featureId: Feature.id,
    intendedStatus: 'supported',
    phase: 'candidate',
    targetVersion: PolicyValue.targetVersion,
    repository: PolicyValue.repository,
    sourceRef: 'refs/heads/main',
    sourceRevision: Revision,
    generatedAt: '2026-08-08T12:00:00Z',
    qualifiedPlatforms: Feature.qualifiedPlatforms,
    workflow: {
      repository: PolicyValue.repository,
      path: '.github/workflows/feature-graduation.yml',
      ref: Revision,
      runId: 123,
      runAttempt: 2,
      jobs: Jobs
    },
    toolVersions: [
      { name: 'kubectl', version: 'v1.34.8' },
      { name: 'helm', version: '3.21.3' }
    ],
    artifactSubjects: Feature.requiredArtifacts.map((Requirement, Index) => {
      const Digest = `sha256:${((Index + 2) % 10).toString().repeat(64)}`
      return {
        name: Requirement.name,
        kind: Requirement.kind,
        reference: `${Requirement.repository}@${Digest}`,
        digest: Digest
      }
    }),
    reportHashes: Reports,
    logHashes: Jobs.map((Job, Index) => ({ jobId: Job.id, sha256: `${Index + 7}`.repeat(64) })),
    gateResults: Feature.gateIds.map(id => ({
      id,
      platformResults: Feature.qualifiedPlatforms.map((platform, Index) => ({
        platform,
        jobId: Jobs[Index].id,
        reportName: Reports[Index].name,
        reportSha256: Reports[Index].sha256,
        result: 'pass' as const
      }))
    })),
    result: 'pass'
  }
}

test('accepts the exact experimental registry, support document, and lifecycle matrix', () => {
  const Loaded = ValidateKubernetesGraduationWorkspace(RepoRoot, GitHead())
  Assert.equal(Loaded.schemaVersion, 2)
  Assert.equal(Loaded.policyVersion, 4)
  Assert.equal(Loaded.targetVersion, '0.8.0')
  Assert.deepEqual(
    Loaded.features.map(Feature => Feature.id).sort(),
    [...KubernetesGraduationFeatureIds].sort()
  )
  Assert.ok(Loaded.features.every(Feature =>
    Feature.status === 'experimental' && Feature.lastValidatedVersion === 'unvalidated'
  ))
  const MismatchedRevision = `${GitHead()[0] === '0' ? '1' : '0'}${GitHead().slice(1)}`
  Assert.throws(
    () => ValidateKubernetesGraduationWorkspace(RepoRoot, MismatchedRevision),
    /expected source revision does not match the checked-out Git source revision/
  )
})

test('preserves support inputs and rejects invalid promotion or platform scope', () => {
  const Schema = ReadJson('devops/config/kubernetes-feature-graduation.schema.json')
  const Unknown = Policy()
  Object.assign(Unknown as unknown as Record<string, unknown>, { ignored: true })
  Assert.throws(
    () => ValidateKubernetesGraduationPolicyObject(Unknown, Schema),
    /unknown property ignored/
  )

  const PromotedWithBlocker = Policy()
  const Controller = PromotedWithBlocker.features.find(Feature => Feature.id === 'gateway-controller')
  Assert.notEqual(Controller, undefined)
  if (Controller !== undefined) {
    Controller.status = 'supported'
    Controller.lastValidatedVersion = PromotedWithBlocker.targetVersion
  }
  Assert.throws(
    () => ValidateKubernetesGraduationPolicyObject(PromotedWithBlocker, Schema),
    /invalid native RISC-V qualification gate or blocker relationship/
  )

  const WrongVersion = Policy()
  const Supply = WrongVersion.features.find(Feature => Feature.id === 'supply-chain-admission-bundle')
  Assert.notEqual(Supply, undefined)
  if (Supply !== undefined) {
    Supply.status = 'supported'
  }
  Assert.throws(
    () => ValidateKubernetesGraduationPolicyObject(WrongVersion, Schema),
    /must bind target version 0.8.0/
  )

  const RiscvSupply = Policy()
  const RiscvSupplyFeature = RiscvSupply.features.find(
    Feature => Feature.id === 'supply-chain-admission-bundle'
  )
  Assert.notEqual(RiscvSupplyFeature, undefined)
  if (RiscvSupplyFeature !== undefined) {
    RiscvSupplyFeature.qualifiedPlatforms.push('linux/riscv64')
  }
  Assert.throws(
    () => ValidateKubernetesGraduationPolicyObject(RiscvSupply, Schema),
    /qualified platforms must be exactly/
  )

  const MissingRiscvBlocker = Policy()
  const MissingRiscvController = MissingRiscvBlocker.features.find(
    Feature => Feature.id === 'gateway-controller'
  )
  Assert.notEqual(MissingRiscvController, undefined)
  if (MissingRiscvController !== undefined) {
    MissingRiscvController.blockerIds = MissingRiscvController.blockerIds.filter(
      BlockerId => BlockerId !== 'native-riscv64-cluster-runner'
    )
  }
  Assert.throws(
    () => ValidateKubernetesGraduationPolicyObject(MissingRiscvBlocker, Schema),
    /invalid native RISC-V qualification gate or blocker relationship/
  )

  const SupplyRiscvBlocker = Policy()
  const SupplyWithoutRiscv = SupplyRiscvBlocker.features.find(
    Feature => Feature.id === 'supply-chain-admission-bundle'
  )
  Assert.notEqual(SupplyWithoutRiscv, undefined)
  if (SupplyWithoutRiscv !== undefined) {
    SupplyWithoutRiscv.blockerIds.push('native-riscv64-cluster-runner')
  }
  Assert.throws(
    () => ValidateKubernetesGraduationPolicyObject(SupplyRiscvBlocker, Schema),
    /invalid native RISC-V qualification gate or blocker relationship/
  )

  const SubstituteArtifact = Policy()
  const SubstituteSupply = SubstituteArtifact.features.find(
    Feature => Feature.id === 'supply-chain-admission-bundle'
  )
  Assert.notEqual(SubstituteSupply, undefined)
  if (SubstituteSupply !== undefined) {
    SubstituteSupply.requiredArtifacts[0].repository = 'ghcr.io/oxibelt/substitute'
  }
  Assert.throws(
    () => ValidateKubernetesGraduationPolicyObject(SubstituteArtifact, Schema),
    /required artifacts must be exactly/
  )
})

test('admits the immediate previous Helm contract only when explicitly requested', () => {
  const PreviousPolicy = Policy()
  PreviousPolicy.supportContract.helm.versions = ['3.21.3', '4.2.3']
  const PreviousSchema = ReadJson(
    'devops/config/kubernetes-feature-graduation.schema.json'
  ) as Record<string, unknown>
  const SupportContract = (PreviousSchema.properties as Record<string, unknown>)
    .supportContract as Record<string, unknown>
  const Helm = ((SupportContract.properties as Record<string, unknown>)
    .helm as Record<string, unknown>)
  const Versions = ((Helm.properties as Record<string, unknown>)
    .versions as Record<string, unknown>)
  const Items = Versions.items as Record<string, unknown>
  Items.enum = ['3.21.3', '4.2.3']

  Assert.throws(
    () => ValidateKubernetesGraduationPolicyObject(PreviousPolicy, PreviousSchema),
    /Helm compatibility versions must be exactly \[3\.21\.3, 4\.2\.4\]/
  )
  const Validated = ValidateKubernetesGraduationPolicyObject(
    PreviousPolicy,
    PreviousSchema,
    { AllowPreviousHelmCompatibility: true }
  )
  Assert.deepEqual(Validated.supportContract.helm.versions, ['3.21.3', '4.2.3'])
})

test('renders detached gate descriptors and qualification platforms deterministically', () => {
  const First = RenderKubernetesGraduationTables(Policy())
  const Second = RenderKubernetesGraduationTables(structuredClone(Policy()))
  Assert.equal(First, Second)
  Assert.match(First, /Graduation target Kubernetes matrix/)
  Assert.match(First, /Qualification platforms/)
  Assert.match(First, /`supply-chain-admission-bundle` \| `experimental` \| `unvalidated` \| `linux\/amd64`, `linux\/arm64`/)
  Assert.match(First, /`image-standalone`.*`chart-gateway-controller`/)
  Assert.match(First, /`native-riscv64` \| `release_candidate` \|/)
  Assert.doesNotMatch(First, /\| State \| Applies to \|/)
})

test('binds candidate and official beta phases to exact release refs', () => {
  ValidateKubernetesGraduationPhaseRef('candidate', 'refs/heads/main')
  ValidateKubernetesGraduationPhaseRef('official_beta', 'refs/tags/0.8.0-beta.3')
  Assert.throws(
    () => ValidateKubernetesGraduationPhaseRef('candidate', 'refs/heads/release'),
    /requires source ref refs\/heads\/main/
  )
  Assert.throws(
    () => ValidateKubernetesGraduationPhaseRef('official_beta', 'refs/tags/0.8.0'),
    /requires an exact 0.8.0 beta tag ref/
  )
  Assert.throws(
    () => ResolveKubernetesGraduationGitRefRevision(
      RepoRoot,
      'refs/tags/0.8.0-beta.999999-does-not-exist'
    ),
    /could not resolve expected source ref/
  )
})

test('requires a supported exact feature-scoped receipt with complete provenance', () => {
  const BaselinePolicy = Policy()
  const PolicyValue = SupportedPolicy(['supply-chain-admission-bundle'])
  const Schema = ReadJson('devops/config/kubernetes-feature-graduation-evidence.schema.json')
  const Evidence = Receipt(PolicyValue)
  ValidateKubernetesGraduationEvidenceObject(
    Evidence, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'
  )

  const ControllerPolicy = SupportedPolicy(['gateway-controller'])
  const ControllerEvidence = Receipt(ControllerPolicy, 'gateway-controller')
  Assert.deepEqual(ControllerEvidence.artifactSubjects, [])
  ValidateKubernetesGraduationEvidenceObject(
    ControllerEvidence,
    Schema,
    ControllerPolicy,
    GitHead(),
    'refs/heads/main',
    'candidate'
  )
  const UnassignedControllerArtifact = structuredClone(ControllerEvidence)
  UnassignedControllerArtifact.artifactSubjects.push({
    name: 'unassigned-image',
    kind: 'oci-image',
    reference: `ghcr.io/oxibelt/unassigned@sha256:${'9'.repeat(64)}`,
    digest: `sha256:${'9'.repeat(64)}`
  })
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      UnassignedControllerArtifact,
      Schema,
      ControllerPolicy,
      GitHead(),
      'refs/heads/main',
      'candidate'
    ),
    /artifact subject names must be exactly \[\]/
  )
  const OfficialBetaEvidence = structuredClone(Evidence)
  OfficialBetaEvidence.phase = 'official_beta'
  OfficialBetaEvidence.sourceRef = 'refs/tags/0.8.0-beta.3'
  ValidateKubernetesGraduationEvidenceObject(
    OfficialBetaEvidence,
    Schema,
    PolicyValue,
    GitHead(),
    'refs/tags/0.8.0-beta.3',
    'official_beta'
  )
  const IncompleteOfficialBetaEvidence = structuredClone(OfficialBetaEvidence)
  IncompleteOfficialBetaEvidence.artifactSubjects.pop()
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      IncompleteOfficialBetaEvidence,
      Schema,
      PolicyValue,
      GitHead(),
      'refs/tags/0.8.0-beta.3',
      'official_beta'
    ),
    /artifact subject names must be exactly/
  )

  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      Evidence, Schema, PolicyValue, GitHead(), 'refs/tags/0.8.0-beta.3', 'candidate'
    ),
    /candidate qualification requires source ref refs\/heads\/main/
  )

  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      Receipt(BaselinePolicy), Schema, BaselinePolicy, GitHead(), 'refs/heads/main', 'candidate'
    ),
    /may only promote a supported feature/
  )

  const MissingGate = structuredClone(Evidence)
  MissingGate.gateResults.pop()
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      MissingGate, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'
    ),
    /gate results must be exactly/
  )

  const MutableArtifact = structuredClone(Evidence)
  MutableArtifact.artifactSubjects[1].reference =
    'ghcr.io/oxibelt/charts/oxibelt-gateway-controller:0.8.0'
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      MutableArtifact, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'
    ),
    /must bind an immutable digest reference/
  )

  const MissingChart = structuredClone(Evidence)
  MissingChart.artifactSubjects.pop()
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      MissingChart, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'
    ),
    /artifact subject names must be exactly/
  )

  const SubstituteReceiptArtifact = structuredClone(Evidence)
  const SubstituteSubject = SubstituteReceiptArtifact.artifactSubjects[0]
  SubstituteSubject.reference = `ghcr.io/oxibelt/substitute@${SubstituteSubject.digest}`
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      SubstituteReceiptArtifact, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'
    ),
    /must bind exact oci-image repository ghcr.io\/oxibelt\/oxibelt/
  )

  const UnknownProducingJob = structuredClone(Evidence)
  UnknownProducingJob.gateResults[0].platformResults[0].jobId = 789
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      UnknownProducingJob, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'
    ),
    /references an unknown producing job/
  )

  const MismatchedReport = structuredClone(Evidence)
  MismatchedReport.gateResults[0].platformResults[0].reportSha256 = '6'.repeat(64)
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      MismatchedReport, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'
    ),
    /does not bind its exact report hash/
  )

  const MissingPlatform = structuredClone(Evidence)
  MissingPlatform.gateResults[0].platformResults.pop()
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      MissingPlatform, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'
    ),
    /platforms must be exactly/
  )

  const ReusedPlatformJob = structuredClone(Evidence)
  ReusedPlatformJob.gateResults[0].platformResults[1].jobId =
    ReusedPlatformJob.gateResults[0].platformResults[0].jobId
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      ReusedPlatformJob, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'
    ),
    /must use a distinct job for every platform/
  )

  const ReusedPlatformReport = structuredClone(Evidence)
  ReusedPlatformReport.gateResults[0].platformResults[1].reportName =
    ReusedPlatformReport.gateResults[0].platformResults[0].reportName
  ReusedPlatformReport.gateResults[0].platformResults[1].reportSha256 =
    ReusedPlatformReport.gateResults[0].platformResults[0].reportSha256
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      ReusedPlatformReport, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'
    ),
    /must use a distinct report for every platform/
  )

  const InvalidTimestamp = structuredClone(Evidence)
  InvalidTimestamp.generatedAt = '2026-02-30T12:00:00Z'
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      InvalidTimestamp, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'
    ),
    /must be a real RFC3339 UTC timestamp/
  )
})

test('requires the exact supported receipt set and rejects experimental extras', () => {
  const BaselinePolicy = Policy()
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceSet(BaselinePolicy, []),
    /requires at least one supported feature row/
  )
  const PolicyValue = SupportedPolicy(['supply-chain-admission-bundle'])
  const Evidence = Receipt(PolicyValue)
  ValidateKubernetesGraduationEvidenceSet(PolicyValue, [Evidence])

  const ExperimentalExtra = structuredClone(Evidence)
  ExperimentalExtra.featureId = 'gateway-controller'
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceSet(PolicyValue, [Evidence, ExperimentalExtra]),
    /rejects evidence for experimental or unvalidated feature/
  )
})

test('loads only canonical regular evidence files below a non-symlink directory', () => {
  const TemporaryRoot = Fs.mkdtempSync(Path.join(RepoRoot, '.kubernetes-graduation-test-'))
  const Directory = Path.join(TemporaryRoot, 'receipts')
  Fs.mkdirSync(Directory)
  try {
    const Evidence = Receipt(SupportedPolicy(['supply-chain-admission-bundle']))
    const ReceiptPath = Path.relative(RepoRoot, Path.join(Directory, 'supply-chain.json'))
    Fs.writeFileSync(Path.join(Directory, 'supply-chain.json'), CanonicalJson(Evidence))
    Assert.deepEqual(
      LoadKubernetesGraduationEvidenceDirectory(RepoRoot, Path.relative(RepoRoot, Directory)),
      [ReceiptPath.replaceAll(Path.sep, '/')]
    )
    Assert.throws(
      () => ValidateKubernetesGraduationEvidenceFiles(
        RepoRoot, [ReceiptPath, ReceiptPath], GitHead(), 'refs/heads/main', 'candidate'
      ),
      /repeats receipt path/
    )

    Fs.writeFileSync(Path.join(Directory, 'supply-chain.json'), JSON.stringify(Evidence, null, 2))
    Assert.throws(
      () => ValidateKubernetesGraduationEvidenceFiles(
        RepoRoot, [ReceiptPath], GitHead(), 'refs/heads/main', 'candidate'
      ),
      /must contain canonical JSON/
    )

    Fs.unlinkSync(Path.join(Directory, 'supply-chain.json'))
    Fs.symlinkSync('/tmp', Path.join(Directory, 'outside'))
    Assert.throws(
      () => LoadKubernetesGraduationEvidenceDirectory(RepoRoot, Path.relative(RepoRoot, Directory)),
      /unsafe or unsupported entry/
    )
    Fs.unlinkSync(Path.join(Directory, 'outside'))
    Fs.symlinkSync('/tmp', Path.join(TemporaryRoot, 'linked-parent'))
    Assert.throws(
      () => LoadKubernetesGraduationEvidenceDirectory(
        RepoRoot,
        Path.relative(RepoRoot, Path.join(TemporaryRoot, 'linked-parent'))
      ),
      /must not traverse a symlink/
    )
  } finally {
    Fs.rmSync(TemporaryRoot, { recursive: true, force: true })
  }
})

test('keeps domain-independent receipt fields aligned with non-Kubernetes evidence', () => {
  type SchemaNode = {
    const?: unknown
    required?: string[]
    properties?: Record<string, SchemaNode>
    items?: SchemaNode
  }
  const KubernetesSchema = ReadJson(
    'devops/config/kubernetes-feature-graduation-evidence.schema.json'
  ) as SchemaNode
  const FeatureSchema = ReadJson(
    'devops/config/feature-graduation-evidence.schema.json'
  ) as SchemaNode
  Assert.deepEqual(
    [...(KubernetesSchema.required ?? [])].sort(),
    [...(FeatureSchema.required ?? [])].sort()
  )
  Assert.deepEqual(
    [...(KubernetesSchema.properties?.workflow.required ?? [])].sort(),
    [...(FeatureSchema.properties?.workflow.required ?? [])].sort()
  )
  Assert.deepEqual(
    [...(KubernetesSchema.properties?.gateResults.items?.required ?? [])].sort(),
    [...(FeatureSchema.properties?.gateResults.items?.required ?? [])].sort()
  )
  Assert.deepEqual(
    [...(KubernetesSchema.properties?.gateResults.items?.properties?.platformResults.items?.required ?? [])].sort(),
    [...(FeatureSchema.properties?.gateResults.items?.properties?.platformResults.items?.required ?? [])].sort()
  )
  Assert.equal(
    KubernetesSchema.properties?.workflow.properties?.path.const,
    FeatureSchema.properties?.workflow.properties?.path.const
  )
  Assert.equal(
    KubernetesSchema.properties?.gateResults.items?.properties?.platformResults.items?.properties?.result.const,
    FeatureSchema.properties?.gateResults.items?.properties?.platformResults.items?.properties?.result.const
  )
  Assert.equal(
    KubernetesSchema.properties?.result.const,
    FeatureSchema.properties?.result.const
  )
})
