import * as Assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import * as Fs from 'node:fs'
import * as Path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  KubernetesGraduationPolicyDefinitionSha256,
  KubernetesGraduationFeatureIds,
  RenderKubernetesGraduationTables,
  ValidateKubernetesGraduationEvidenceObject,
  ValidateKubernetesGraduationPolicyObject,
  ValidateKubernetesGraduationWorkspace,
  type KubernetesGraduationEvidenceReceipt,
  type KubernetesGraduationPolicy
} from '../sources/kubernetes_graduation.js'

const RepoRoot = Path.resolve(Path.dirname(fileURLToPath(import.meta.url)), '../..')

function ReadJson(RelativePath: string): unknown {
  return JSON.parse(Fs.readFileSync(Path.join(RepoRoot, RelativePath), 'utf8')) as unknown
}

function Policy(): KubernetesGraduationPolicy {
  return structuredClone(ValidateKubernetesGraduationPolicyObject(
    ReadJson('devops/config/kubernetes-feature-graduation.json'),
    ReadJson('devops/config/kubernetes-feature-graduation.schema.json')
  ))
}

function GitHead(): string {
  return execFileSync(
    'git',
    ['-C', RepoRoot, 'rev-parse', '--verify', 'HEAD^{commit}'],
    {
      encoding: 'utf8',
      maxBuffer: 1024,
      stdio: ['ignore', 'pipe', 'pipe']
    }
  ).trim()
}

test('accepts the repository policy, generated support document, and lifecycle matrix', () => {
  const Loaded = ValidateKubernetesGraduationWorkspace(RepoRoot)
  Assert.equal(Loaded.schemaVersion, 1)
  Assert.deepEqual(
    Loaded.features.map(Feature => Feature.id).sort(),
    [...KubernetesGraduationFeatureIds].sort()
  )
  Assert.ok(Loaded.features.every(Feature => Feature.status === 'experimental'))
})

test('binds an explicit expected revision to the checked-out Git commit', () => {
  const Revision = GitHead()
  ValidateKubernetesGraduationWorkspace(RepoRoot, undefined, undefined, Revision)
  const MismatchedRevision = `${Revision[0] === '0' ? '1' : '0'}${Revision.slice(1)}`
  Assert.throws(
    () => ValidateKubernetesGraduationWorkspace(
      RepoRoot,
      undefined,
      undefined,
      MismatchedRevision
    ),
    /expected source revision does not match the checked-out Git source revision/
  )
})

test('rejects schema-unknown fields and incomplete supported promotion', () => {
  const Schema = ReadJson('devops/config/kubernetes-feature-graduation.schema.json')
  const Unknown = Policy()
  Object.assign(Unknown as unknown as Record<string, unknown>, { ignored: true })
  Assert.throws(
    () => ValidateKubernetesGraduationPolicyObject(Unknown, Schema),
    /unknown property ignored/
  )

  const Promoted = Policy()
  const Feature = Promoted.features.find(Candidate => Candidate.id === 'gateway-controller')
  Assert.notEqual(Feature, undefined)
  if (Feature === undefined) {
    return
  }
  Feature.status = 'supported'
  Feature.blockerIds = []
  Assert.throws(
    () => ValidateKubernetesGraduationPolicyObject(Promoted, Schema),
    /incomplete mandatory gates/
  )
})

test('rejects mutable or cross-minor Kubernetes representatives', () => {
  const Schema = ReadJson('devops/config/kubernetes-feature-graduation.schema.json')
  const Mutable = Policy()
  Mutable.supportContract.kubernetes.minors[0].kindNodeImage = 'kindest/node:v1.34.8'
  Assert.throws(
    () => ValidateKubernetesGraduationPolicyObject(Mutable, Schema),
    /does not match required pattern/
  )

  const CrossMinor = Policy()
  CrossMinor.supportContract.kubernetes.minors[0].ciVersion = 'v1.35.5'
  Assert.throws(
    () => ValidateKubernetesGraduationPolicyObject(CrossMinor, Schema),
    /representative .* must use the same minor/
  )
})

test('renders the Kubernetes support tables deterministically', () => {
  const Loaded = Policy()
  const First = RenderKubernetesGraduationTables(Loaded)
  const Second = RenderKubernetesGraduationTables(structuredClone(Loaded))
  Assert.equal(First, Second)
  Assert.match(First, /Graduation target Kubernetes matrix/)
  Assert.match(First, /`gateway-controller` \| `experimental`/)
  Assert.match(First, /`native-riscv64` \| `release_candidate` \| `unmet`/)
})

test('requires exact source, immutable image, chart, report, and log bindings in evidence receipts', () => {
  const Loaded = Policy()
  const EvidenceSchema = ReadJson(
    'devops/config/kubernetes-feature-graduation-evidence.schema.json'
  )
  const ExpectedSourceRevision = '1'.repeat(40)
  const Receipt: KubernetesGraduationEvidenceReceipt = {
    schemaVersion: 1,
    policyVersion: Loaded.policyVersion,
    policyDefinitionSha256: KubernetesGraduationPolicyDefinitionSha256(Loaded),
    sourceRevision: ExpectedSourceRevision,
    validatedVersion: 'v0.7.0',
    runId: 123,
    runAttempt: 2,
    generatedAt: '2026-07-24T12:00:00Z',
    jobIds: [456],
    artifactSubjects: [
      {
        name: 'controller',
        kind: 'oci-image',
        reference: `ghcr.io/oxibelt/oxibelt-gateway-controller@sha256:${'2'.repeat(64)}`,
        digest: `sha256:${'2'.repeat(64)}`
      },
      {
        name: 'controller-chart',
        kind: 'helm-chart',
        reference: 'oxibelt-gateway-controller-0.7.0.tgz',
        digest: `sha256:${'3'.repeat(64)}`
      }
    ],
    reports: [
      {
        name: 'conformance.json',
        sha256: '4'.repeat(64)
      }
    ],
    logs: [
      {
        jobId: 456,
        sha256: '5'.repeat(64)
      }
    ],
    gateResults: [
      {
        id: 'policy-contract',
        result: 'passed'
      }
    ]
  }
  ValidateKubernetesGraduationEvidenceObject(
    Receipt,
    EvidenceSchema,
    Loaded,
    ExpectedSourceRevision,
    'v0.7.0'
  )

  const StaleRevision = structuredClone(Receipt)
  StaleRevision.sourceRevision = '6'.repeat(40)
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      StaleRevision,
      EvidenceSchema,
      Loaded,
      ExpectedSourceRevision,
      'v0.7.0'
    ),
    /does not bind the expected source revision/
  )

  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      Receipt,
      EvidenceSchema,
      Loaded,
      'ABC123',
      'v0.7.0'
    ),
    /expected source revision must be a full lowercase Git commit/
  )

  const MissingArtifacts = structuredClone(Receipt)
  MissingArtifacts.artifactSubjects = []
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      MissingArtifacts,
      EvidenceSchema,
      Loaded,
      ExpectedSourceRevision,
      'v0.7.0'
    ),
    /artifactSubjects must contain at least 2 items/
  )

  const MutableImage = structuredClone(Receipt)
  MutableImage.artifactSubjects[0].reference =
    'ghcr.io/oxibelt/oxibelt-gateway-controller:0.7.0'
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      MutableImage,
      EvidenceSchema,
      Loaded,
      ExpectedSourceRevision,
      'v0.7.0'
    ),
    /reference must end with its immutable digest/
  )

  const MissingLog = structuredClone(Receipt)
  MissingLog.logs = [
    {
      jobId: 789,
      sha256: '5'.repeat(64)
    }
  ]
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      MissingLog,
      EvidenceSchema,
      Loaded,
      ExpectedSourceRevision,
      'v0.7.0'
    ),
    /one log hash for every exact job id/
  )

  const ArbitraryVersion = structuredClone(Receipt)
  ArbitraryVersion.validatedVersion = 'v999.999.999'
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      ArbitraryVersion,
      EvidenceSchema,
      Loaded,
      ExpectedSourceRevision,
      'v0.7.0'
    ),
    /does not bind the expected validated product version/
  )

  const MismatchedChartVersion = structuredClone(Receipt)
  MismatchedChartVersion.artifactSubjects[1].reference =
    'oxibelt-gateway-controller-9.9.9.tgz'
  Assert.throws(
    () => ValidateKubernetesGraduationEvidenceObject(
      MismatchedChartVersion,
      EvidenceSchema,
      Loaded,
      ExpectedSourceRevision,
      'v0.7.0'
    ),
    /must bind a Helm chart package for validated version v0.7.0/
  )
})

test('rejects a validated product version without complete qualification gates', () => {
  const Schema = ReadJson('devops/config/kubernetes-feature-graduation.schema.json')
  const Unproven = Policy()
  const Feature = Unproven.features.find(Candidate => Candidate.id === 'gateway-controller')
  Assert.notEqual(Feature, undefined)
  if (Feature === undefined) {
    return
  }
  Feature.lastValidatedVersion = 'v999.999.999'
  Assert.throws(
    () => ValidateKubernetesGraduationPolicyObject(Unproven, Schema),
    /lastValidatedVersion requires complete mandatory gates/
  )
})

test('requires workspace evidence validation before an object can claim passed gates', () => {
  const Schema = ReadJson('devops/config/kubernetes-feature-graduation.schema.json')
  const Untrusted = Policy()
  const Feature = Untrusted.features.find(Candidate => Candidate.id === 'gateway-controller')
  Assert.notEqual(Feature, undefined)
  if (Feature === undefined) {
    return
  }
  for (const Gate of Untrusted.gates) {
    if (Gate.appliesTo.includes(Feature.id)) {
      Gate.status = 'passed'
      Gate.evidenceReceipts = ['evidence/kubernetes-graduation/missing.json']
    }
  }
  Feature.status = 'supported'
  Feature.lastValidatedVersion = 'v999.999.999'
  Feature.blockerIds = []

  Assert.throws(
    () => ValidateKubernetesGraduationPolicyObject(Untrusted, Schema),
    /requires workspace evidence validation/
  )
})
