import * as Assert from 'node:assert/strict'
import * as Crypto from 'node:crypto'
import * as Fs from 'node:fs'
import * as Path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  FeatureGraduationPredicateType,
  InspectFeatureGraduationPolicies,
  SealFeatureGraduationEvidence,
  VerifyFeatureGraduationAttestationReadback,
  WriteFeatureGraduationExpectations,
  type JobsMetadata,
  type RunMetadata,
  type SealedFeatureGraduation
} from '../sources/feature_graduation_attestation.js'
import {
  CanonicalJson,
  FeatureGraduationPolicyDefinitionSha256,
  ValidateFeatureGraduationPolicyObject,
  type FeatureGraduationPolicy
} from '../sources/feature_graduation.js'
import {
  KubernetesGraduationPolicyDefinitionSha256,
  ValidateKubernetesGraduationPolicyObject,
  type KubernetesGraduationPolicy
} from '../sources/kubernetes_graduation.js'

/* eslint-disable @typescript-eslint/naming-convention -- Fixtures mirror sealed attestation JSON. */
const RepoRoot = Path.resolve(Path.dirname(fileURLToPath(import.meta.url)), '../..')
const Revision = 'a'.repeat(40)

function ReadJson(RelativePath: string): unknown {
  return JSON.parse(Fs.readFileSync(Path.join(RepoRoot, RelativePath), 'utf8')) as unknown
}

function Digest(Value: string | Buffer): string {
  return Crypto.createHash('sha256').update(Value).digest('hex')
}

function CopyPolicyInputs(Root: string): void {
  const Destination = Path.join(Root, 'devops/config')
  Fs.mkdirSync(Destination, { recursive: true })
  for (const Name of [
    'feature-graduation.json',
    'feature-graduation.schema.json',
    'feature-graduation-evidence.schema.json',
    'kubernetes-feature-graduation.json',
    'kubernetes-feature-graduation.schema.json',
    'kubernetes-feature-graduation-evidence.schema.json'
  ]) {
    Fs.copyFileSync(Path.join(RepoRoot, 'devops/config', Name), Path.join(Destination, Name))
  }
}

function SupportedPolicies(Root: string): { features: FeatureGraduationPolicy, kubernetes: KubernetesGraduationPolicy } {
  const FeatureValue = ReadJson('devops/config/feature-graduation.json') as FeatureGraduationPolicy
  const ConfigFeature = FeatureValue.features.find(Feature => Feature.id === 'config-activation-planner')
  Assert.notEqual(ConfigFeature, undefined)
  if (ConfigFeature !== undefined) {
    ConfigFeature.status = 'supported'
    ConfigFeature.lastValidatedVersion = FeatureValue.targetVersion
  }
  const KubernetesValue = ReadJson('devops/config/kubernetes-feature-graduation.json') as KubernetesGraduationPolicy
  const Supply = KubernetesValue.features.find(Feature => Feature.id === 'supply-chain-admission-bundle')
  Assert.notEqual(Supply, undefined)
  if (Supply !== undefined) {
    Supply.status = 'supported'
    Supply.lastValidatedVersion = KubernetesValue.targetVersion
    Supply.blockerIds = []
  }
  const Features = ValidateFeatureGraduationPolicyObject(FeatureValue, ReadJson('devops/config/feature-graduation.schema.json'))
  const Kubernetes = ValidateKubernetesGraduationPolicyObject(KubernetesValue, ReadJson('devops/config/kubernetes-feature-graduation.schema.json'))
  Fs.writeFileSync(Path.join(Root, 'devops/config/feature-graduation.json'), JSON.stringify(Features))
  Fs.writeFileSync(Path.join(Root, 'devops/config/kubernetes-feature-graduation.json'), JSON.stringify(Kubernetes))
  return { features: Features, kubernetes: Kubernetes }
}

function WriteFileAndHash(Root: string, RelativePath: string, Text: string): string {
  const Output = Path.join(Root, RelativePath)
  Fs.mkdirSync(Path.dirname(Output), { recursive: true })
  Fs.writeFileSync(Output, Text)
  return Digest(Text)
}

function FeatureReceipt(Policy: FeatureGraduationPolicy, Reports: Array<{ name: string, sha256: string }>, Logs: Array<{ jobId: number, sha256: string }>): Record<string, unknown> {
  const Feature = Policy.features.find(Candidate => Candidate.id === 'config-activation-planner')
  Assert.notEqual(Feature, undefined)
  if (Feature === undefined) throw new Error('missing config fixture')
  return {
    schemaVersion: 1,
    policyVersion: Policy.policyVersion,
    policyDefinitionSha256: FeatureGraduationPolicyDefinitionSha256(Policy),
    featureId: Feature.id,
    intendedStatus: 'supported', phase: 'candidate', targetVersion: Policy.targetVersion,
    repository: Policy.repository, sourceRef: 'refs/heads/main', sourceRevision: Revision,
    generatedAt: '2026-08-08T12:00:00Z', qualifiedPlatforms: Feature.qualifiedPlatforms,
    workflow: { repository: Policy.repository, path: '.github/workflows/feature-graduation.yml', ref: Revision, runId: 7, runAttempt: 1, jobs: Feature.qualifiedPlatforms.map((Platform, Index) => ({ id: 101 + Index, name: `feature-${Platform}`, conclusion: 'success' })) },
    toolVersions: [{ name: 'cargo', version: '1.90.0' }], artifactSubjects: [], reportHashes: Reports, logHashes: Logs,
    gateResults: Feature.gateIds.map(Id => ({ id: Id, platformResults: Feature.qualifiedPlatforms.map((Platform, Index) => ({ platform: Platform, jobId: 101 + Index, reportName: Reports[Index].name, reportSha256: Reports[Index].sha256, result: 'pass' })) })), result: 'pass'
  }
}

function KubernetesReceipt(Policy: KubernetesGraduationPolicy, Reports: Array<{ name: string, sha256: string }>, Logs: Array<{ jobId: number, sha256: string }>): Record<string, unknown> {
  const Feature = Policy.features.find(Candidate => Candidate.id === 'supply-chain-admission-bundle')
  Assert.notEqual(Feature, undefined)
  if (Feature === undefined) throw new Error('missing supply-chain fixture')
  return {
    schemaVersion: 2,
    policyVersion: Policy.policyVersion,
    policyDefinitionSha256: KubernetesGraduationPolicyDefinitionSha256(Policy),
    featureId: Feature.id,
    intendedStatus: 'supported', phase: 'candidate', targetVersion: Policy.targetVersion,
    repository: Policy.repository, sourceRef: 'refs/heads/main', sourceRevision: Revision,
    generatedAt: '2026-08-08T12:00:00Z', qualifiedPlatforms: Feature.qualifiedPlatforms,
    workflow: { repository: Policy.repository, path: '.github/workflows/feature-graduation.yml', ref: Revision, runId: 7, runAttempt: 1, jobs: Feature.qualifiedPlatforms.map((Platform, Index) => ({ id: 201 + Index, name: `kubernetes-${Platform}`, conclusion: 'success' })) },
    toolVersions: [{ name: 'helm', version: '3.21.3' }],
    artifactSubjects: Feature.requiredArtifacts.map((Requirement, Index) => {
      const digest = `sha256:${String(Index + 2).repeat(64)}`
      return { name: Requirement.name, kind: Requirement.kind, reference: `${Requirement.repository}@${digest}`, digest }
    }),
    reportHashes: Reports, logHashes: Logs,
    gateResults: Feature.gateIds.map(Id => ({ id: Id, platformResults: Feature.qualifiedPlatforms.map((Platform, Index) => ({ platform: Platform, jobId: 201 + Index, reportName: Reports[Index].name, reportSha256: Reports[Index].sha256, result: 'pass' })) })), result: 'pass'
  }
}

function Run(): RunMetadata {
  return { schemaVersion: 1, repository: 'OxiBelt/OxiBelt', workflowPath: '.github/workflows/feature-graduation.yml', workflowRef: Revision, runId: 7, runAttempt: 1, sourceRef: 'refs/heads/main', sourceRevision: Revision, status: 'in_progress', conclusion: null }
}

function Jobs(): JobsMetadata {
  return { schemaVersion: 1, repository: 'OxiBelt/OxiBelt', runId: 7, runAttempt: 1, jobs: [
    { id: 101, name: 'feature-linux/amd64', conclusion: 'success' }, { id: 102, name: 'feature-linux/arm64', conclusion: 'success' },
    { id: 201, name: 'kubernetes-linux/amd64', conclusion: 'success' }, { id: 202, name: 'kubernetes-linux/arm64', conclusion: 'success' }
  ] }
}

function BuildSealedWorkspace(): { root: string, sealed: SealedFeatureGraduation } {
  const Root = Fs.mkdtempSync(Path.join(RepoRoot, '.feature-attestation-test-'))
  CopyPolicyInputs(Root)
  const Policies = SupportedPolicies(Root)
  const Reports = [
    ['feature-amd64.json', 'feature-amd64'], ['feature-arm64.json', 'feature-arm64'],
    ['kubernetes-amd64.json', 'kubernetes-amd64'], ['kubernetes-arm64.json', 'kubernetes-arm64']
  ].map(([Name, Content]) => ({ name: Name, sha256: WriteFileAndHash(Root, `evidence/reports/${Name}`, Content) }))
  const FeatureLogs = [{ jobId: 101, sha256: WriteFileAndHash(Root, 'evidence/logs/101.log', 'feature-amd64-log') }, { jobId: 102, sha256: WriteFileAndHash(Root, 'evidence/logs/102.log', 'feature-arm64-log') }]
  const KubernetesLogs = [{ jobId: 201, sha256: WriteFileAndHash(Root, 'evidence/logs/201.log', 'kubernetes-amd64-log') }, { jobId: 202, sha256: WriteFileAndHash(Root, 'evidence/logs/202.log', 'kubernetes-arm64-log') }]
  WriteFileAndHash(Root, 'evidence/receipts/features/config.json', CanonicalJson(FeatureReceipt(Policies.features, Reports.slice(0, 2), FeatureLogs)))
  WriteFileAndHash(Root, 'evidence/receipts/kubernetes/supply.json', CanonicalJson(KubernetesReceipt(Policies.kubernetes, Reports.slice(2), KubernetesLogs)))
  Fs.writeFileSync(Path.join(Root, 'run.json'), CanonicalJson(Run()))
  Fs.writeFileSync(Path.join(Root, 'jobs.json'), CanonicalJson(Jobs()))
  return { root: Root, sealed: SealFeatureGraduationEvidence({ workspacePath: Root, evidenceDirectory: 'evidence', runMetadataPath: 'run.json', jobsMetadataPath: 'jobs.json', sourceRevision: Revision, sourceRef: 'refs/heads/main', phase: 'candidate' }) }
}

function Attestation(Sealed: SealedFeatureGraduation): unknown {
  return [{ verificationResult: { signature: { certificate: {
    subjectAlternativeName: 'https://github.com/OxiBelt/OxiBelt/.github/workflows/feature-graduation.yml@refs/heads/main',
    sourceRepository: 'https://github.com/OxiBelt/OxiBelt', sourceRepositoryRef: 'refs/heads/main', sourceRepositoryDigest: Revision, buildSignerDigest: Revision, runnerEnvironment: 'github-hosted'
  } }, verifiedTimestamps: [{}], statement: {
    subject: [{ name: Sealed.subject.subjectName, digest: { sha256: Sealed.subjectSha256.slice('sha256:'.length) } }], predicateType: FeatureGraduationPredicateType, predicate: Sealed.predicate
  } } }]
}

test('inspects canonical policies with an explicit zero-supported outcome', () => {
  const Expectations = InspectFeatureGraduationPolicies(RepoRoot)
  Assert.equal(Expectations.result, 'zero_supported')
  Assert.equal(Expectations.features.length, 0)
  Assert.deepEqual(Expectations.policies.map(Policy => Policy.scope), ['features', 'kubernetes'])
})

test('writes expectations to a bounded absolute temporary output path', () => {
  const TemporaryDirectory = Fs.mkdtempSync(Path.join('/tmp', 'feature-attestation-output-'))
  const Output = Path.join(TemporaryDirectory, 'expectations.json')
  try {
    WriteFeatureGraduationExpectations(RepoRoot, Output)
    const Value = JSON.parse(Fs.readFileSync(Output, 'utf8')) as { result: string }
    Assert.equal(Value.result, 'zero_supported')
  } finally {
    Fs.rmSync(TemporaryDirectory, { recursive: true, force: true })
  }
})

test('seals exact receipt, report, log, and authenticated producer-job inventory', () => {
  const { root, sealed } = BuildSealedWorkspace()
  try {
    Assert.equal(sealed.predicate.expectations.result, 'supported')
    Assert.equal(sealed.predicate.inventory.receipts.length, 2)
    Assert.deepEqual(
      sealed.predicate.inventory.receipts.map(Receipt => Receipt.path),
      ['receipts/features/config.json', 'receipts/kubernetes/supply.json']
    )
    Assert.equal(sealed.predicate.inventory.reports.length, 4)
    Assert.deepEqual(sealed.predicate.inventory.logs.map(Log => Log.jobId), [101, 102, 201, 202])
    Assert.match(sealed.subjectSha256, /^sha256:[0-9a-f]{64}$/)
    Assert.equal(sealed.subject.predicateSha256, `sha256:${Digest(sealed.predicateText)}`)

    Fs.appendFileSync(Path.join(root, 'evidence/logs/101.log'), 'changed')
    Assert.throws(
      () => SealFeatureGraduationEvidence({ workspacePath: root, evidenceDirectory: 'evidence', runMetadataPath: 'run.json', jobsMetadataPath: 'jobs.json', sourceRevision: Revision, sourceRef: 'refs/heads/main', phase: 'candidate' }),
      /authenticated log hash mismatch/
    )
  } finally {
    Fs.rmSync(root, { recursive: true, force: true })
  }
})

test('rejects unsafe or incomplete private evidence trees', () => {
  const { root } = BuildSealedWorkspace()
  try {
    Fs.writeFileSync(Path.join(root, 'evidence/reports/extra.txt'), 'extra')
    Assert.throws(
      () => SealFeatureGraduationEvidence({ workspacePath: root, evidenceDirectory: 'evidence', runMetadataPath: 'run.json', jobsMetadataPath: 'jobs.json', sourceRevision: Revision, sourceRef: 'refs/heads/main', phase: 'candidate' }),
      /report artifact paths must be exactly/
    )
  } finally {
    Fs.rmSync(root, { recursive: true, force: true })
  }
  const Symlinked = BuildSealedWorkspace()
  try {
    Fs.symlinkSync('/tmp', Path.join(Symlinked.root, 'evidence/reports/linked'))
    Assert.throws(
      () => SealFeatureGraduationEvidence({ workspacePath: Symlinked.root, evidenceDirectory: 'evidence', runMetadataPath: 'run.json', jobsMetadataPath: 'jobs.json', sourceRevision: Revision, sourceRef: 'refs/heads/main', phase: 'candidate' }),
      /contains a symlink/
    )
  } finally {
    Fs.rmSync(Symlinked.root, { recursive: true, force: true })
  }
})

test('requires every platform producer job and exact report artifact', () => {
  const MissingJob = BuildSealedWorkspace()
  try {
    const Metadata = Jobs()
    Metadata.jobs.pop()
    Fs.writeFileSync(Path.join(MissingJob.root, 'jobs.json'), CanonicalJson(Metadata))
    Assert.throws(
      () => SealFeatureGraduationEvidence({ workspacePath: MissingJob.root, evidenceDirectory: 'evidence', runMetadataPath: 'run.json', jobsMetadataPath: 'jobs.json', sourceRevision: Revision, sourceRef: 'refs/heads/main', phase: 'candidate' }),
      /authenticated producer jobs must be exactly/
    )
  } finally {
    Fs.rmSync(MissingJob.root, { recursive: true, force: true })
  }
  const MissingReport = BuildSealedWorkspace()
  try {
    Fs.unlinkSync(Path.join(MissingReport.root, 'evidence/reports/feature-arm64.json'))
    Assert.throws(
      () => SealFeatureGraduationEvidence({ workspacePath: MissingReport.root, evidenceDirectory: 'evidence', runMetadataPath: 'run.json', jobsMetadataPath: 'jobs.json', sourceRevision: Revision, sourceRef: 'refs/heads/main', phase: 'candidate' }),
      /report artifact paths must be exactly/
    )
  } finally {
    Fs.rmSync(MissingReport.root, { recursive: true, force: true })
  }
})

test('rejects unused authenticated producer jobs and cross-receipt producer-job conflicts', () => {
  const ExtraJob = BuildSealedWorkspace()
  try {
    const Metadata = Jobs()
    Metadata.jobs.push({ id: 999, name: 'unused-producer', conclusion: 'success' })
    Fs.writeFileSync(Path.join(ExtraJob.root, 'jobs.json'), CanonicalJson(Metadata))
    Assert.throws(
      () => SealFeatureGraduationEvidence({ workspacePath: ExtraJob.root, evidenceDirectory: 'evidence', runMetadataPath: 'run.json', jobsMetadataPath: 'jobs.json', sourceRevision: Revision, sourceRef: 'refs/heads/main', phase: 'candidate' }),
      /authenticated producer jobs must be exactly/
    )
  } finally {
    Fs.rmSync(ExtraJob.root, { recursive: true, force: true })
  }
  const ConflictingJob = BuildSealedWorkspace()
  try {
    const ReceiptPath = Path.join(ConflictingJob.root, 'evidence/receipts/kubernetes/supply.json')
    const Receipt = JSON.parse(Fs.readFileSync(ReceiptPath, 'utf8')) as {
      workflow: { jobs: Array<{ id: number }> }
      logHashes: Array<{ jobId: number }>
      gateResults: Array<{ platformResults: Array<{ jobId: number }> }>
    }
    Receipt.workflow.jobs[0].id = 101
    Receipt.logHashes[0].jobId = 101
    for (const Gate of Receipt.gateResults) {
      for (const PlatformResult of Gate.platformResults) {
        if (PlatformResult.jobId === 201) PlatformResult.jobId = 101
      }
    }
    Fs.writeFileSync(ReceiptPath, CanonicalJson(Receipt))
    Assert.throws(
      () => SealFeatureGraduationEvidence({ workspacePath: ConflictingJob.root, evidenceDirectory: 'evidence', runMetadataPath: 'run.json', jobsMetadataPath: 'jobs.json', sourceRevision: Revision, sourceRef: 'refs/heads/main', phase: 'candidate' }),
      /conflicting producer job id\/name mapping/
    )
  } finally {
    Fs.rmSync(ConflictingJob.root, { recursive: true, force: true })
  }
})

test('permits one identical authenticated producer job shared across receipt scopes', () => {
  const SharedJob = BuildSealedWorkspace()
  try {
    const ReceiptPath = Path.join(SharedJob.root, 'evidence/receipts/kubernetes/supply.json')
    const Receipt = JSON.parse(Fs.readFileSync(ReceiptPath, 'utf8')) as {
      workflow: { jobs: Array<{ id: number, name: string, conclusion: 'success' }> }
      logHashes: Array<{ jobId: number, sha256: string }>
      gateResults: Array<{ platformResults: Array<{ jobId: number }> }>
    }
    Receipt.workflow.jobs[0] = { id: 101, name: 'feature-linux/amd64', conclusion: 'success' }
    Receipt.logHashes[0] = { jobId: 101, sha256: Digest('feature-amd64-log') }
    for (const Gate of Receipt.gateResults) {
      for (const PlatformResult of Gate.platformResults) {
        if (PlatformResult.jobId === 201) PlatformResult.jobId = 101
      }
    }
    Fs.writeFileSync(ReceiptPath, CanonicalJson(Receipt))
    const Metadata = Jobs()
    Metadata.jobs = Metadata.jobs.filter(Job => Job.id !== 201)
    Fs.writeFileSync(Path.join(SharedJob.root, 'jobs.json'), CanonicalJson(Metadata))
    Fs.unlinkSync(Path.join(SharedJob.root, 'evidence/logs/201.log'))
    const Sealed = SealFeatureGraduationEvidence({ workspacePath: SharedJob.root, evidenceDirectory: 'evidence', runMetadataPath: 'run.json', jobsMetadataPath: 'jobs.json', sourceRevision: Revision, sourceRef: 'refs/heads/main', phase: 'candidate' })
    Assert.deepEqual(Sealed.predicate.inventory.logs.map(Log => Log.jobId), [101, 102, 202])
  } finally {
    Fs.rmSync(SharedJob.root, { recursive: true, force: true })
  }
})

test('verifies exact attestation readback and rejects signer, subject, predicate, and source drift', () => {
  const { root, sealed } = BuildSealedWorkspace()
  try {
    const Options = {
      attestations: Attestation(sealed), subject: sealed.subject, predicate: sealed.predicate, runMetadata: Run(), verificationContext: 'in_run' as const,
      signerWorkflow: 'OxiBelt/OxiBelt/.github/workflows/feature-graduation.yml@refs/heads/main',
      sourceRepository: 'OxiBelt/OxiBelt', sourceRef: 'refs/heads/main', sourceRevision: Revision
    }
    VerifyFeatureGraduationAttestationReadback(Options)
    VerifyFeatureGraduationAttestationReadback({ ...Options, attestations: [...(Options.attestations as unknown[]), ...(Options.attestations as unknown[])] })
    VerifyFeatureGraduationAttestationReadback({
      ...Options,
      runMetadata: { ...Run(), status: 'completed', conclusion: 'success' },
      verificationContext: 'canonical_consumer'
    })

    const WrongSigner = structuredClone(Options.attestations) as Array<Record<string, unknown>>
    const Certificate = (((WrongSigner[0].verificationResult as Record<string, unknown>).signature as Record<string, unknown>).certificate as Record<string, unknown>)
    Certificate.subjectAlternativeName = 'https://github.com/attacker/workflow@bad'
    Assert.throws(() => VerifyFeatureGraduationAttestationReadback({ ...Options, attestations: WrongSigner }), /unexpected signer workflow/)

    const WrongSource = structuredClone(Options.attestations) as Array<Record<string, unknown>>
    const SourceCertificate = (((WrongSource[0].verificationResult as Record<string, unknown>).signature as Record<string, unknown>).certificate as Record<string, unknown>)
    SourceCertificate.sourceRepositoryRef = 'refs/heads/other'
    Assert.throws(() => VerifyFeatureGraduationAttestationReadback({ ...Options, attestations: WrongSource }), /unexpected source ref or revision/)

    const Conflict = structuredClone(Options.attestations) as Array<Record<string, unknown>>
    const Statement = ((Conflict[0].verificationResult as Record<string, unknown>).statement as Record<string, unknown>)
    Statement.predicate = { changed: true }
    Assert.throws(() => VerifyFeatureGraduationAttestationReadback({ ...Options, attestations: Conflict }), /conflicting predicate/)

    const WrongSubject = structuredClone(Options.attestations) as Array<Record<string, unknown>>
    const Subject = ((((WrongSubject[0].verificationResult as Record<string, unknown>).statement as Record<string, unknown>).subject as Array<Record<string, unknown>>)[0])
    Subject.name = 'other.json'
    Assert.throws(() => VerifyFeatureGraduationAttestationReadback({ ...Options, attestations: WrongSubject }), /no exact feature-graduation subject/)

    Assert.throws(() => VerifyFeatureGraduationAttestationReadback({ ...Options, attestations: { malformed: true } }), /must contain bounded results/)
    Assert.throws(
      () => VerifyFeatureGraduationAttestationReadback({ ...Options, runMetadata: { ...Run(), status: 'completed', conclusion: 'success' } }),
      /does not satisfy in_run state/
    )
  } finally {
    Fs.rmSync(root, { recursive: true, force: true })
  }
})
