import * as Assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import * as Fs from 'node:fs'
import * as Path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  CanonicalJson,
  FeatureGraduationFeatureIds,
  FeatureGraduationPolicyDefinitionSha256,
  LoadFeatureGraduationEvidenceDirectory,
  ValidateFeatureGraduationEvidenceFiles,
  ValidateFeatureGraduationEvidenceObject,
  ValidateFeatureGraduationEvidenceSet,
  ValidateFeatureGraduationPolicyObject,
  ValidateFeatureGraduationWorkspace,
  type FeatureGraduationEvidenceReceipt,
  type FeatureGraduationPolicy
} from '../sources/feature_graduation.js'

/* oxlint-disable oxibelt/pascal-case -- Fixture fields mirror detached receipt JSON. */
const RepoRoot = Path.resolve(Path.dirname(fileURLToPath(import.meta.url)), '../..')

function ReadJson(RelativePath: string): unknown {
  return JSON.parse(Fs.readFileSync(Path.join(RepoRoot, RelativePath), 'utf8')) as unknown
}

function Policy(): FeatureGraduationPolicy {
  return structuredClone(ValidateFeatureGraduationPolicyObject(
    ReadJson('devops/config/feature-graduation.json'),
    ReadJson('devops/config/feature-graduation.schema.json')
  ))
}

function GitHead(): string {
  return execFileSync('git', ['-C', RepoRoot, 'rev-parse', '--verify', 'HEAD^{commit}'], {
    encoding: 'utf8', maxBuffer: 1024, stdio: ['ignore', 'pipe', 'pipe']
  }).trim()
}

function Receipt(
  PolicyValue: FeatureGraduationPolicy,
  FeatureId: (typeof FeatureGraduationFeatureIds)[number] = 'config-activation-planner'
): FeatureGraduationEvidenceReceipt {
  const Feature = PolicyValue.features.find(Candidate => Candidate.id === FeatureId)
  Assert.notEqual(Feature, undefined)
  if (Feature === undefined) {
    throw new Error(`missing fixture feature ${FeatureId}`)
  }
  const Revision = GitHead()
  const Reports = Feature.qualifiedPlatforms.map((Platform, Index) => ({
    name: `qualification-${Platform.slice('linux/'.length)}.json`,
    sha256: `${Index + 3}`.repeat(64)
  }))
  return {
    schemaVersion: 1,
    policyVersion: PolicyValue.policyVersion,
    policyDefinitionSha256: FeatureGraduationPolicyDefinitionSha256(PolicyValue),
    featureId: Feature.id,
    intendedStatus: 'supported',
    phase: 'candidate',
    targetVersion: '0.8.1',
    repository: 'OxiBelt/OxiBelt',
    sourceRef: 'refs/heads/main',
    sourceRevision: Revision,
    generatedAt: '2026-08-08T12:00:00Z',
    qualifiedPlatforms: Feature.qualifiedPlatforms,
    workflow: {
      repository: 'OxiBelt/OxiBelt',
      path: '.github/workflows/feature-graduation.yml',
      ref: Revision,
      runId: 123,
      runAttempt: 2,
      jobs: Feature.qualifiedPlatforms.map((Platform, Index) => ({
        id: 456 + Index,
        name: `qualification-${Platform}`,
        conclusion: 'success' as const
      }))
    },
    toolVersions: [{ name: 'cargo', version: '1.90.0' }],
    artifactSubjects: [{
      name: 'release-image',
      kind: 'oci-image',
      reference: `ghcr.io/oxibelt/oxibelt@sha256:${'2'.repeat(64)}`,
      digest: `sha256:${'2'.repeat(64)}`
    }],
    reportHashes: Reports,
    logHashes: Feature.qualifiedPlatforms.map((_, Index) => ({
      jobId: 456 + Index,
      sha256: `${Index + 4}`.repeat(64)
    })),
    gateResults: Feature.gateIds.map(id => ({
      id,
      platformResults: Feature.qualifiedPlatforms.map((Platform, Index) => ({
        platform: Platform,
        jobId: 456 + Index,
        reportName: Reports[Index].name,
        reportSha256: Reports[Index].sha256,
        result: 'pass' as const
      }))
    })),
    result: 'pass'
  }
}

function SupportedPolicy(
  FeatureIds: Array<(typeof FeatureGraduationFeatureIds)[number]>
): FeatureGraduationPolicy {
  const Result = Policy()
  for (const Feature of Result.features) {
    if (FeatureIds.includes(Feature.id)) {
      Feature.status = 'supported'
      Feature.lastValidatedVersion = Result.targetVersion
    }
  }
  return ValidateFeatureGraduationPolicyObject(
    Result,
    ReadJson('devops/config/feature-graduation.schema.json')
  )
}

test('accepts the exact experimental registry and FeatureStatus matrix', () => {
  const Loaded = ValidateFeatureGraduationWorkspace(RepoRoot)
  Assert.equal(Loaded.targetVersion, '0.8.1')
  Assert.deepEqual(Loaded.features.map(Feature => Feature.id).sort(), [...FeatureGraduationFeatureIds].sort())
  Assert.ok(Loaded.features.every(Feature => Feature.status === 'experimental'))
  Assert.equal(Loaded.features.length, FeatureGraduationFeatureIds.length)
})

test('rejects unknown properties, unsupported platforms, and unsupported rows without the target version', () => {
  const Schema = ReadJson('devops/config/feature-graduation.schema.json')
  const Unknown = Policy()
  Object.assign(Unknown as unknown as Record<string, unknown>, { ignored: true })
  Assert.throws(() => ValidateFeatureGraduationPolicyObject(Unknown, Schema), /unknown property ignored/)

  const UnsupportedPlatform = Policy()
  UnsupportedPlatform.features[3].qualifiedPlatforms = ['linux/amd64', 'linux/arm64']
  Assert.throws(() => ValidateFeatureGraduationPolicyObject(UnsupportedPlatform, Schema), /qualified platforms must be exactly/)

  const MissingNativePlatform = Policy()
  MissingNativePlatform.features[0].qualifiedPlatforms = ['linux/amd64']
  Assert.throws(() => ValidateFeatureGraduationPolicyObject(MissingNativePlatform, Schema), /qualified platforms must be exactly/)

  const UnsupportedVersion = Policy()
  UnsupportedVersion.features[0].status = 'supported'
  Assert.throws(() => ValidateFeatureGraduationPolicyObject(UnsupportedVersion, Schema), /must bind target version 0.8.1/)

  const UnsupportedDependency = Policy()
  const Sybil = UnsupportedDependency.features.find(Feature => Feature.id === 'sybil-rate-limit-identities')
  Assert.notEqual(Sybil, undefined)
  if (Sybil !== undefined) {
    Sybil.status = 'supported'
    Sybil.lastValidatedVersion = UnsupportedDependency.targetVersion
  }
  Assert.throws(
    () => ValidateFeatureGraduationPolicyObject(UnsupportedDependency, Schema),
    /requires supported dependency client-identity-asn/
  )
})

test('requires a supported exact feature-scoped receipt with immutable, complete evidence', () => {
  const BaselinePolicy = Policy()
  const PolicyValue = SupportedPolicy(['config-activation-planner'])
  const Schema = ReadJson('devops/config/feature-graduation-evidence.schema.json')
  const Evidence = Receipt(PolicyValue)
  ValidateFeatureGraduationEvidenceObject(
    Evidence, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'
  )

  Assert.throws(
    () => ValidateFeatureGraduationEvidenceObject(
      Receipt(BaselinePolicy), Schema, BaselinePolicy, GitHead(), 'refs/heads/main', 'candidate'
    ),
    /may only promote a supported feature/
  )

  const MissingGate = structuredClone(Evidence)
  MissingGate.gateResults.pop()
  Assert.throws(
    () => ValidateFeatureGraduationEvidenceObject(MissingGate, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'),
    /gate results must be exactly/
  )

  const MutableArtifact = structuredClone(Evidence)
  MutableArtifact.artifactSubjects[0].reference = 'ghcr.io/oxibelt/oxibelt:0.8.0'
  Assert.throws(
    () => ValidateFeatureGraduationEvidenceObject(MutableArtifact, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'),
    /must bind an immutable digest reference/
  )

  const MismatchedRef = structuredClone(Evidence)
  MismatchedRef.sourceRef = 'refs/tags/0.8.0-beta.3'
  Assert.throws(
    () => ValidateFeatureGraduationEvidenceObject(MismatchedRef, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'),
    /does not bind the expected source ref/
  )

  const UnknownProducingJob = structuredClone(Evidence)
  UnknownProducingJob.gateResults[0].platformResults[0].jobId = 789
  Assert.throws(
    () => ValidateFeatureGraduationEvidenceObject(UnknownProducingJob, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'),
    /references an unknown producing job/
  )

  const MismatchedReport = structuredClone(Evidence)
  MismatchedReport.gateResults[0].platformResults[0].reportSha256 = '5'.repeat(64)
  Assert.throws(
    () => ValidateFeatureGraduationEvidenceObject(MismatchedReport, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'),
    /does not bind its exact report hash/
  )

  const MissingJobLog = structuredClone(Evidence)
  MissingJobLog.logHashes[0].jobId = 789
  Assert.throws(
    () => ValidateFeatureGraduationEvidenceObject(MissingJobLog, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'),
    /one log hash for every exact workflow job/
  )

  const InvalidTimestamp = structuredClone(Evidence)
  InvalidTimestamp.generatedAt = '2026-02-30T12:00:00Z'
  Assert.throws(
    () => ValidateFeatureGraduationEvidenceObject(InvalidTimestamp, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'),
    /must be a real RFC3339 UTC timestamp/
  )

  const MissingPlatform = structuredClone(Evidence)
  MissingPlatform.gateResults[0].platformResults.pop()
  Assert.throws(
    () => ValidateFeatureGraduationEvidenceObject(MissingPlatform, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'),
    /platforms must be exactly/
  )

  const DuplicatePlatformJob = structuredClone(Evidence)
  DuplicatePlatformJob.gateResults[0].platformResults[1].jobId = DuplicatePlatformJob.gateResults[0].platformResults[0].jobId
  Assert.throws(
    () => ValidateFeatureGraduationEvidenceObject(DuplicatePlatformJob, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'),
    /reuses producing job .* across platforms/
  )

  const DuplicatePlatformReport = structuredClone(Evidence)
  DuplicatePlatformReport.gateResults[0].platformResults[1].reportName =
    DuplicatePlatformReport.gateResults[0].platformResults[0].reportName
  DuplicatePlatformReport.gateResults[0].platformResults[1].reportSha256 =
    DuplicatePlatformReport.gateResults[0].platformResults[0].reportSha256
  Assert.throws(
    () => ValidateFeatureGraduationEvidenceObject(DuplicatePlatformReport, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'),
    /reuses a report across platforms/
  )

  const UnknownPlatform = structuredClone(Evidence)
  UnknownPlatform.gateResults[0].platformResults[0].platform = 'linux/riscv64' as 'linux/amd64'
  Assert.throws(
    () => ValidateFeatureGraduationEvidenceObject(UnknownPlatform, Schema, PolicyValue, GitHead(), 'refs/heads/main', 'candidate'),
    /must be one of/
  )
})

test('requires exact supported receipt sets and rejects baseline or experimental extras', () => {
  const BaselinePolicy = Policy()
  Assert.throws(
    () => ValidateFeatureGraduationEvidenceSet(BaselinePolicy, []),
    /requires at least one supported feature row/
  )
  const PolicyValue = SupportedPolicy(['config-activation-planner'])
  const Evidence = Receipt(PolicyValue)
  ValidateFeatureGraduationEvidenceSet(PolicyValue, [Evidence])

  Assert.throws(
    () => ValidateFeatureGraduationEvidenceSet(PolicyValue, [Evidence, structuredClone(Evidence)]),
    /duplicate evidence for feature/
  )

  const ExperimentalExtra = structuredClone(Evidence)
  ExperimentalExtra.featureId = 'runtime-confinement-contract'
  Assert.throws(
    () => ValidateFeatureGraduationEvidenceSet(PolicyValue, [Evidence, ExperimentalExtra]),
    /rejects evidence for experimental or unvalidated feature/
  )
})

test('CLI rejects caller-selected contracts and mismatched or unresolved exact revisions', Context => {
  const Source = Path.join(RepoRoot, 'devops/sources/feature_graduation.ts')
  const Run = (...Arguments: string[]) => spawnSync(
    process.execPath,
    ['--import', 'tsx', Source, ...Arguments],
    { cwd: RepoRoot, encoding: 'utf8' }
  )
  const Common = [
    'verify', '--workspace-path', '.', '--expected-source-revision', GitHead(),
    '--expected-source-ref', 'refs/heads/main', '--phase', 'candidate',
    '--evidence-dir', 'devops/config'
  ]

  const Override = Run(...Common, '--policy-path', 'devops/config/feature-graduation.json')
  const SpawnError = Override.error as (Error & { code?: string }) | undefined
  if (SpawnError?.code === 'EPERM') {
    Context.skip('the sandbox blocks nested Node process spawning')
    return
  }
  Assert.notEqual(Override.status, 0)
  Assert.match(Override.stderr, /unknown option: --policy-path/)

  const HeadMismatch = Run(
    'verify', '--workspace-path', '.', '--expected-source-revision', '0'.repeat(40),
    '--expected-source-ref', 'refs/heads/main', '--phase', 'candidate',
    '--evidence-dir', 'devops/config'
  )
  Assert.notEqual(HeadMismatch.status, 0)
  Assert.match(HeadMismatch.stderr, /does not match the checked-out Git source revision/)

  const PhaseMismatch = Run(
    'verify', '--workspace-path', '.', '--expected-source-revision', GitHead(),
    '--expected-source-ref', 'refs/tags/0.8.0-beta.999999', '--phase', 'candidate',
    '--evidence-dir', 'devops/config'
  )
  Assert.notEqual(PhaseMismatch.status, 0)
  Assert.match(PhaseMismatch.stderr, /candidate qualification requires refs\/heads\/main/)

  const MissingTag = Run(
    'verify', '--workspace-path', '.', '--expected-source-revision', GitHead(),
    '--expected-source-ref', 'refs/tags/0.8.1-beta.999999', '--phase', 'official_beta',
    '--evidence-dir', 'devops/config'
  )
  Assert.notEqual(MissingTag.status, 0)
  Assert.match(MissingTag.stderr, /could not resolve refs\/tags\/0\.8\.1-beta\.999999/)
})

test('loads only canonical regular evidence files below a non-symlink directory', () => {
  const TemporaryRoot = Fs.mkdtempSync(Path.join(RepoRoot, '.feature-graduation-test-'))
  const Directory = Path.join(TemporaryRoot, 'receipts')
  Fs.mkdirSync(Directory)
  try {
    const Evidence = Receipt(SupportedPolicy(['config-activation-planner']))
    const ReceiptPath = Path.relative(RepoRoot, Path.join(Directory, 'config.json'))
    Fs.writeFileSync(Path.join(Directory, 'config.json'), CanonicalJson(Evidence))
    Assert.deepEqual(
      LoadFeatureGraduationEvidenceDirectory(RepoRoot, Path.relative(RepoRoot, Directory)),
      [ReceiptPath.replaceAll(Path.sep, '/')]
    )
    Assert.throws(
      () => ValidateFeatureGraduationEvidenceFiles(
        RepoRoot, [ReceiptPath, ReceiptPath], GitHead(), 'refs/heads/main', 'candidate'
      ),
      /repeats receipt path/
    )

    Fs.writeFileSync(Path.join(Directory, 'config.json'), JSON.stringify(Evidence, null, 2))
    Assert.throws(
      () => ValidateFeatureGraduationEvidenceFiles(
        RepoRoot, [ReceiptPath], GitHead(), 'refs/heads/main', 'candidate'
      ),
      /must contain canonical JSON/
    )

    Fs.unlinkSync(Path.join(Directory, 'config.json'))
    Fs.symlinkSync('/tmp', Path.join(Directory, 'outside'))
    Assert.throws(
      () => LoadFeatureGraduationEvidenceDirectory(RepoRoot, Path.relative(RepoRoot, Directory)),
      /unsafe or unsupported entry/
    )
    Fs.unlinkSync(Path.join(Directory, 'outside'))
    Fs.symlinkSync('/tmp', Path.join(TemporaryRoot, 'linked-parent'))
    Assert.throws(
      () => LoadFeatureGraduationEvidenceDirectory(
        RepoRoot,
        Path.relative(RepoRoot, Path.join(TemporaryRoot, 'linked-parent'))
      ),
      /must not traverse a symlink/
    )
  } finally {
    Fs.rmSync(TemporaryRoot, { recursive: true, force: true })
  }
})
