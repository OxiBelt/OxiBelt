import * as Assert from 'node:assert/strict'
import * as Fs from 'node:fs'
import * as Os from 'node:os'
import * as Path from 'node:path'
import test from 'node:test'
import { ValidateDependencyAdmission } from '../sources/dependency_admission.js'

/* eslint-disable @typescript-eslint/naming-convention -- Test fixtures intentionally mirror external JSON and YAML keys. */
type Fixture = {
  root: string
  policyPath: string
  licenseReportPath: string
  auditReportPath: string
}

const PackageManager = 'pnpm@11.15.1+sha512.81350b07e53c9538a02f1f2303b4290fa2d7be04e56e2a970c4cc4b417dc761de196edabd49d55c7dc9580db81007c44143e4e3d7e462b3000d23c255122d065'
const Integrity = `sha512-${Buffer.alloc(64, 7).toString('base64')}`

function WriteJson(FilePath: string, Value: unknown): void {
  Fs.writeFileSync(FilePath, `${JSON.stringify(Value, null, 2)}\n`)
}

function CreateFixture(): Fixture {
  const Root = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-dependency-admission-'))
  Fs.mkdirSync(Path.join(Root, 'packages'))
  WriteJson(Path.join(Root, 'package.json'), {
    name: 'fixture-root',
    private: true,
    packageManager: PackageManager,
    workspaces: ['packages'],
    dependencies: { alpha: '1.2.3' },
    devDependencies: { esbuild: '0.28.1' }
  })
  WriteJson(Path.join(Root, 'packages', 'package.json'), {
    name: '@fixture/packages',
    private: true,
    dependencies: {}
  })
  Fs.writeFileSync(
    Path.join(Root, 'pnpm-workspace.yaml'),
    `packages:
  - "packages"
registry: "https://registry.npmjs.org/"
blockExoticSubdeps: true
trustLockfile: false
strictDepBuilds: true
minimumReleaseAge: 1440
auditConfig:
  ignoreGhsas: []
allowBuilds:
  "esbuild@0.28.1": true
`
  )
  Fs.writeFileSync(
    Path.join(Root, 'pnpm-lock.yaml'),
    `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      alpha:
        specifier: 1.2.3
        version: 1.2.3
    devDependencies:
      esbuild:
        specifier: 0.28.1
        version: 0.28.1

  packages: {}

packages:

  alpha@1.2.3:
    resolution: {integrity: ${Integrity}}

  esbuild@0.28.1:
    resolution: {integrity: ${Integrity}}

snapshots:

  alpha@1.2.3: {}

  esbuild@0.28.1: {}
`
  )
  const PolicyPath = Path.join(Root, 'dependency-policy.json')
  WriteJson(PolicyPath, {
    schemaVersion: 1,
    rust: { preserved: true },
    node: {
      allowedRegistries: ['https://registry.npmjs.org/'],
      allowedLicenses: ['MIT'],
      lifecycleScripts: [
        {
          package: 'esbuild',
          version: '0.28.1',
          rationale: 'tsx requires the platform-specific esbuild compiler binary.'
        }
      ],
      auditExceptions: []
    }
  })
  const LicenseReportPath = Path.join(Root, 'licenses.json')
  WriteJson(LicenseReportPath, {
    MIT: [{ name: 'alpha', versions: ['1.2.3'], paths: ['/virtual/alpha'] }]
  })
  const AuditReportPath = Path.join(Root, 'audit.json')
  WriteJson(AuditReportPath, {
    advisories: {},
    metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 } }
  })

  return { root: Root, policyPath: 'dependency-policy.json', licenseReportPath: LicenseReportPath, auditReportPath: AuditReportPath }
}

function Cleanup(FixtureValue: Fixture): void {
  Fs.rmSync(FixtureValue.root, { force: true, recursive: true })
}

function Validate(FixtureValue: Fixture): ReturnType<typeof ValidateDependencyAdmission> {
  return ValidateDependencyAdmission({
    workspacePath: FixtureValue.root,
    policyPath: FixtureValue.policyPath,
    licenseReportPath: FixtureValue.licenseReportPath,
    auditReportPath: FixtureValue.auditReportPath,
    now: new Date('2026-07-21T12:00:00.000Z')
  })
}

test('accepts exact manifests, integrity-only lock entries, policy-bound scripts, and clean reports', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))

  Assert.deepEqual(Validate(FixtureValue), {
    manifests: 2,
    lockedPackages: 2,
    lifecycleScripts: 1,
    licenses: 1
  })
})

test('rejects ranged external manifest dependencies', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))
  const ManifestPath = Path.join(FixtureValue.root, 'package.json')
  const Manifest = JSON.parse(Fs.readFileSync(ManifestPath, 'utf8')) as { dependencies: Record<string, string> }
  Manifest.dependencies.alpha = '^1.2.3'
  WriteJson(ManifestPath, Manifest)

  Assert.throws(() => Validate(FixtureValue), /must pin external dependency alpha to an exact semantic version/)
})

test('rejects tarball and other non-integrity lock resolutions', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))
  const LockPath = Path.join(FixtureValue.root, 'pnpm-lock.yaml')
  const Lock = Fs.readFileSync(LockPath, 'utf8').replace(
    `resolution: {integrity: ${Integrity}}`,
    'resolution: {tarball: https://example.invalid/alpha.tgz}'
  )
  Fs.writeFileSync(LockPath, Lock)

  Assert.throws(() => Validate(FixtureValue), /non-registry or non-integrity resolution/)
})

test('requires lifecycle-script approvals to be exact and policy-bound', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))
  const WorkspacePath = Path.join(FixtureValue.root, 'pnpm-workspace.yaml')
  const Workspace = Fs.readFileSync(WorkspacePath, 'utf8').replace('"esbuild@0.28.1": true', 'esbuild: true')
  Fs.writeFileSync(WorkspacePath, Workspace)

  Assert.throws(() => Validate(FixtureValue), /allowBuilds must exactly match node.lifecycleScripts/)
})

test('rejects disallowed licenses and unadmitted advisories', async TestContext => {
  await TestContext.test('license', LicenseContext => {
    const FixtureValue = CreateFixture()
    LicenseContext.after(() => Cleanup(FixtureValue))
    WriteJson(FixtureValue.licenseReportPath, {
      GPL: [{ name: 'alpha', versions: ['1.2.3'] }]
    })

    Assert.throws(() => Validate(FixtureValue), /disallowed or unknown license expression: GPL/)
  })
  await TestContext.test('advisory', AdvisoryContext => {
    const FixtureValue = CreateFixture()
    AdvisoryContext.after(() => Cleanup(FixtureValue))
    WriteJson(FixtureValue.auditReportPath, {
      advisories: {
        123: {
          github_advisory_id: 'GHSA-2345-6789-cfgh',
          module_name: 'alpha',
          vulnerable_versions: '<1.2.4'
        }
      },
      metadata: { vulnerabilities: { low: 1 } }
    })

    Assert.throws(() => Validate(FixtureValue), /unadmitted advisories: GHSA-2345-6789-CFGH:alpha:<1[.]2[.]4/)
  })
})

test('accepts an active audit exception with an exact report and workspace match', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))
  const PolicyPath = Path.join(FixtureValue.root, FixtureValue.policyPath)
  const Policy = JSON.parse(Fs.readFileSync(PolicyPath, 'utf8')) as {
    node: { auditExceptions: Array<Record<string, string>> }
  }
  Policy.node.auditExceptions.push({
    id: 'GHSA-2345-6789-cfgh',
    package: 'alpha',
    versions: '<1.2.4',
    rationale: 'No patched version is currently compatible with the fixture.',
    owner: '@security-team',
    issue: 'https://github.com/example/project/issues/1',
    reviewedOn: '2026-07-01',
    expiresOn: '2026-08-01'
  })
  WriteJson(PolicyPath, Policy)
  const WorkspacePath = Path.join(FixtureValue.root, 'pnpm-workspace.yaml')
  Fs.writeFileSync(
    WorkspacePath,
    Fs.readFileSync(WorkspacePath, 'utf8').replace(
      '  ignoreGhsas: []',
      '  ignoreGhsas:\n    - "GHSA-2345-6789-cfgh"'
    )
  )
  WriteJson(FixtureValue.auditReportPath, {
    advisories: {
      123: {
        github_advisory_id: 'GHSA-2345-6789-cfgh',
        module_name: 'alpha',
        vulnerable_versions: '<1.2.4'
      }
    },
    metadata: { vulnerabilities: { low: 1 } }
  })

  Assert.equal(Validate(FixtureValue).lockedPackages, 2)
})

test('rejects an active policy ignore that is absent from the audit report', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))
  const PolicyPath = Path.join(FixtureValue.root, FixtureValue.policyPath)
  const Policy = JSON.parse(Fs.readFileSync(PolicyPath, 'utf8')) as {
    node: { auditExceptions: Array<Record<string, string>> }
  }
  Policy.node.auditExceptions.push({
    id: 'GHSA-2345-6789-cfgh',
    package: 'alpha',
    versions: '<1.2.4',
    rationale: 'No patched version is currently compatible with the fixture.',
    owner: '@security-team',
    issue: 'https://github.com/example/project/issues/1',
    reviewedOn: '2026-07-01',
    expiresOn: '2026-08-01'
  })
  WriteJson(PolicyPath, Policy)
  const WorkspacePath = Path.join(FixtureValue.root, 'pnpm-workspace.yaml')
  Fs.writeFileSync(
    WorkspacePath,
    Fs.readFileSync(WorkspacePath, 'utf8').replace(
      '  ignoreGhsas: []',
      '  ignoreGhsas:\n    - "GHSA-2345-6789-cfgh"'
    )
  )

  Assert.throws(() => Validate(FixtureValue), /stale or unreported advisories: GHSA-2345-6789-CFGH/)
})

test('rejects expired audit exceptions even when pnpm ignore configuration matches', TestContext => {
  const FixtureValue = CreateFixture()
  TestContext.after(() => Cleanup(FixtureValue))
  const PolicyPath = Path.join(FixtureValue.root, FixtureValue.policyPath)
  const Policy = JSON.parse(Fs.readFileSync(PolicyPath, 'utf8')) as {
    node: { auditExceptions: Array<Record<string, string>> }
  }
  Policy.node.auditExceptions.push({
    id: 'GHSA-2345-6789-cfgh',
    package: 'alpha',
    versions: '<1.2.4',
    rationale: 'No patched version is currently compatible with the fixture.',
    owner: '@security-team',
    issue: 'https://github.com/example/project/issues/1',
    reviewedOn: '2026-07-01',
    expiresOn: '2026-07-20'
  })
  WriteJson(PolicyPath, Policy)
  const WorkspacePath = Path.join(FixtureValue.root, 'pnpm-workspace.yaml')
  Fs.writeFileSync(
    WorkspacePath,
    Fs.readFileSync(WorkspacePath, 'utf8').replace(
      '  ignoreGhsas: []',
      '  ignoreGhsas:\n    - "GHSA-2345-6789-cfgh"'
    )
  )

  Assert.throws(() => Validate(FixtureValue), /expired on 2026-07-20/)
})
