import * as Assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import * as Fs from 'node:fs'
import * as Os from 'node:os'
import * as Path from 'node:path'
import test from 'node:test'
import * as Zlib from 'node:zlib'
import {
  AssertExpectedHelmChartArchiveMembers,
  CanonicalHelmPackagerVersion,
  HelmChartReleasePlanFilename,
  InstallHelmChartReleaseOutputsForTesting,
  InspectHelmChartArchive,
  IsSupportedHelmPackagerVersion,
  MaximumCompressedArchiveBytes,
  MaximumArchiveMemberBytes,
  MaximumArchiveMembers,
  MaximumDecompressedTarBytes,
  MaximumPlanBytes,
  PrepareHelmChartRelease,
  ReadHelmChartTree,
  VerifyHelmChartRelease
} from '../sources/helm_chart_release.js'

const RepoRoot = Path.resolve(Path.dirname(new URL(import.meta.url).pathname), '../..')
const ReleaseRef = 'refs/tags/0.7.1-beta.2'

function Git(Directory: string, ...Arguments: string[]): string {
  return execFileSync('git', ['-C', Directory, ...Arguments], {
    encoding: 'utf8', maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe']
  }).trim()
}

function ReleaseRevision(): string {
  return Git(RepoRoot, 'rev-parse', '--verify', `${ReleaseRef}^{commit}`)
}

function ReleaseEpoch(): number {
  return Number(Git(RepoRoot, 'show', '-s', '--format=%ct', ReleaseRevision()))
}

function Options(OutputDirectory: string) {
  return { workspacePath: RepoRoot, ref: ReleaseRef, revision: ReleaseRevision(), outputDirectory: OutputDirectory }
}

function WriteOctal(Header: Buffer, Offset: number, Length: number, Value: number): void {
  Header.write(`${Value.toString(8).padStart(Length - 1, '0')}\0`, Offset, Length, 'ascii')
}

function TarMember(Name: string, Content: Buffer, Epoch: number, Mode = 0o644, Type = '0'): Buffer {
  const Header = Buffer.alloc(512)
  Header.write(Name, 0, 'utf8')
  WriteOctal(Header, 100, 8, Mode)
  WriteOctal(Header, 124, 12, Content.length)
  WriteOctal(Header, 136, 12, Epoch)
  Header.fill(0x20, 148, 156)
  Header[156] = Type.charCodeAt(0)
  Header.write('ustar\0', 257, 'ascii')
  Header.write('00', 263, 'ascii')
  WriteOctal(Header, 148, 8, Header.reduce((Sum, Byte) => Sum + Byte, 0))
  const Padding = Buffer.alloc((512 - (Content.length % 512)) % 512)
  return Buffer.concat([Header, Content, Padding])
}

function Archive(Members: Buffer[]): Buffer {
  return Zlib.gzipSync(Buffer.concat([...Members, Buffer.alloc(1024)]))
}

function CanonicalJson(Value: unknown): string {
  if (Array.isArray(Value)) return `[${Value.map(CanonicalJson).join(',')}]`
  if (typeof Value === 'object' && Value !== null) {
    const ObjectValue = Value as Record<string, unknown>
    return `{${Object.keys(ObjectValue).sort().map(Key => `${JSON.stringify(Key)}:${CanonicalJson(ObjectValue[Key])}`).join(',')}}`
  }
  return JSON.stringify(Value)
}

function WritePlan(Directory: string, Value: unknown): void {
  Fs.writeFileSync(Path.join(Directory, HelmChartReleasePlanFilename), `${CanonicalJson(Value)}\n`)
}

function FixtureRepository(): string {
  const Directory = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-tree-'))
  Git(Directory, 'init', '--quiet')
  Git(Directory, 'config', 'user.email', 'tests@oxibelt.invalid')
  Git(Directory, 'config', 'user.name', 'OxiBelt tests')
  const ChartDirectory = Path.join(Directory, 'deploy/helm/oxibelt')
  Fs.mkdirSync(ChartDirectory, { recursive: true })
  Fs.writeFileSync(Path.join(ChartDirectory, 'tracked.txt'), 'tracked\n')
  Git(Directory, 'add', '.')
  Git(Directory, 'commit', '--quiet', '--no-gpg-sign', '-m', 'fixture')
  return Directory
}

function CloneWithOrigin(Origin: string): string {
  const Directory = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-origin-clone-'))
  Fs.rmdirSync(Directory)
  execFileSync('git', ['clone', '--shared', '--quiet', RepoRoot, Directory], {
    encoding: 'utf8', maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe']
  })
  Git(Directory, 'remote', 'set-url', 'origin', Origin)
  return Directory
}

test('accepts only Helm 4.2.4 as the canonical chart packager', () => {
  Assert.equal(CanonicalHelmPackagerVersion, 'v4.2.4')
  Assert.equal(IsSupportedHelmPackagerVersion('v4.2.4'), true)
  Assert.equal(IsSupportedHelmPackagerVersion('v4.2.4+g0123456'), true)
  Assert.equal(IsSupportedHelmPackagerVersion('v3.21.3'), false)
  Assert.equal(IsSupportedHelmPackagerVersion('v4.2.3'), false)
  Assert.equal(IsSupportedHelmPackagerVersion('v4.2.5'), false)
})

test('prepares an exact-ref, canonical plan and deterministic transformed archives without touching chart sources', () => {
  const First = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-first-'))
  const Second = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-second-'))
  const WorktreeValues = Fs.readFileSync(Path.join(RepoRoot, 'deploy/helm/oxibelt/values.yaml'))
  try {
    const Plan = PrepareHelmChartRelease(Options(First))
    PrepareHelmChartRelease(Options(Second))
    Assert.equal(Plan.schemaVersion, 1)
    Assert.equal(Plan.repository, 'OxiBelt/OxiBelt')
    Assert.equal(Plan.repositoryProvenance, 'github-workflow-authentication-required')
    Assert.equal(Plan.sourceRef, ReleaseRef)
    Assert.equal(Plan.sourceRevision, ReleaseRevision())
    Assert.equal(Plan.commitEpoch, ReleaseEpoch())
    Assert.equal(Plan.releaseVersion, '0.7.1-beta.2')
    Assert.deepEqual(Plan.charts.map(Chart => Chart.targetOciRepository), [
      'oci://ghcr.io/oxibelt/charts/oxibelt',
      'oci://ghcr.io/oxibelt/charts/oxibelt-gateway-controller'
    ])
    for (const Chart of Plan.charts) {
      Assert.equal(Chart.metadata.version, Plan.releaseVersion)
      Assert.equal(Chart.metadata.appVersion, Plan.releaseVersion)
      Assert.equal(Chart.experimentalStatus, 'experimental')
      Assert.equal(Chart.metadata.annotations['oxibelt.dev/feature-status'], 'experimental')
      Assert.deepEqual(
        Fs.readFileSync(Path.join(First, Chart.filename)),
        Fs.readFileSync(Path.join(Second, Chart.filename))
      )
      for (const Member of InspectHelmChartArchive(Fs.readFileSync(Path.join(First, Chart.filename)))) {
        Assert.equal(Member.mode, 0o644)
        Assert.equal(Member.mtime, Plan.commitEpoch)
      }
    }
    const DataPlane = InspectHelmChartArchive(Fs.readFileSync(Path.join(First, 'oxibelt-0.7.1-beta.2.tgz')))
    Assert.match(DataPlane.find(Member => Member.name === 'oxibelt/values.yaml')?.content.toString() ?? '', /  tag: 0\.7\.1-beta\.2/)
    Assert.match(DataPlane.find(Member => Member.name === 'oxibelt/examples/strict-dataplane-values.yaml')?.content.toString() ?? '', /  tag: 0\.7\.1-beta\.2/)
    Assert.deepEqual(Fs.readFileSync(Path.join(RepoRoot, 'deploy/helm/oxibelt/values.yaml')), WorktreeValues)
    VerifyHelmChartRelease(Options(First))
  } finally {
    Fs.rmSync(First, { recursive: true, force: true })
    Fs.rmSync(Second, { recursive: true, force: true })
  }
})

test('recomputes the entire canonical plan and rejects every tampered field group or extra key', () => {
  const Directory = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-plan-tamper-'))
  try {
    PrepareHelmChartRelease(Options(Directory))
    const Original = JSON.parse(Fs.readFileSync(Path.join(Directory, HelmChartReleasePlanFilename), 'utf8')) as Record<string, unknown>
    const Cases: Array<[string, (Plan: Record<string, unknown>) => void]> = [
      ['schema', Plan => { Plan.schemaVersion = 2 }],
      ['top identity', Plan => { Plan.repository = 'Other/Repository' }],
      ['repository provenance', Plan => { Plan.repositoryProvenance = 'locally-authenticated' }],
      ['ref and revision', Plan => { Plan.sourceRef = 'refs/tags/0.0.0'; Plan.sourceRevision = '0'.repeat(40) }],
      ['epoch and version', Plan => { Plan.commitEpoch = 0; Plan.releaseVersion = '9.9.9' }],
      ['chart filename and source', Plan => { const Chart = (Plan.charts as Array<Record<string, unknown>>)[0]; Chart.filename = 'other.tgz'; Chart.sourceDirectory = 'other' }],
      ['chart name', Plan => { (Plan.charts as Array<Record<string, unknown>>)[0].name = 'other' }],
      ['OCI and digest', Plan => { const Chart = (Plan.charts as Array<Record<string, unknown>>)[0]; Chart.targetOciRepository = 'oci://example.invalid/other'; Chart.archiveSha256 = '0'.repeat(64) }],
      ['metadata and annotations', Plan => { const Chart = (Plan.charts as Array<Record<string, unknown>>)[0]; (Chart.metadata as Record<string, unknown>).version = '9.9.9'; (Chart.metadata as Record<string, unknown>).appVersion = '9.9.9'; ((Chart.metadata as Record<string, unknown>).annotations as Record<string, unknown>)['oxibelt.dev/feature-status'] = 'supported' }],
      ['status and defaults', Plan => { const Chart = (Plan.charts as Array<Record<string, unknown>>)[0]; Chart.experimentalStatus = 'supported'; const Default = (Chart.defaultImages as Array<Record<string, unknown>>)[0]; Default.path = 'other'; Default.from = 'old'; Default.to = '9.9.9' }],
      ['recipe', Plan => { (Plan.charts as Array<Record<string, unknown>>)[0].transformationRecipe = [] }],
      ['top extra key', Plan => { Plan.unexpected = true }],
      ['chart extra key', Plan => { (Plan.charts as Array<Record<string, unknown>>)[0].unexpected = true }]
    ]
    for (const [Label, Mutate] of Cases) {
      const Mutated = structuredClone(Original)
      Mutate(Mutated)
      WritePlan(Directory, Mutated)
      Assert.throws(() => VerifyHelmChartRelease(Options(Directory)), /canonical expected content/, Label)
    }
  } finally {
    Fs.rmSync(Directory, { recursive: true, force: true })
  }
})

test('rejects tree traversal and any symlink or special Git tree entry', () => {
  const Directory = FixtureRepository()
  try {
    const Revision = Git(Directory, 'rev-parse', 'HEAD')
    Fs.writeFileSync(Path.join(Directory, 'deploy/helm/oxibelt/untracked.txt'), 'must not be packaged\n')
    Assert.deepEqual(
      ReadHelmChartTree(Directory, Revision, { directory: 'deploy/helm/oxibelt' }).map(File => File.path),
      ['deploy/helm/oxibelt/tracked.txt']
    )
    Assert.throws(() => ReadHelmChartTree(Directory, Revision, { directory: 'deploy/helm/../outside' }), /unsafe/)

    Fs.symlinkSync('tracked.txt', Path.join(Directory, 'deploy/helm/oxibelt/link'))
    Git(Directory, 'add', 'deploy/helm/oxibelt/link')
    Git(Directory, 'commit', '--quiet', '--no-gpg-sign', '-m', 'symlink')
    Assert.throws(() => ReadHelmChartTree(Directory, Git(Directory, 'rev-parse', 'HEAD'), { directory: 'deploy/helm/oxibelt' }), /regular files/)

    Git(Directory, 'rm', '--quiet', 'deploy/helm/oxibelt/link')
    const Commit = Git(Directory, 'rev-parse', 'HEAD')
    Git(Directory, 'update-index', '--add', '--cacheinfo', `160000,${Commit},deploy/helm/oxibelt/submodule`)
    Git(Directory, 'commit', '--quiet', '--no-gpg-sign', '-m', 'special')
    Assert.throws(() => ReadHelmChartTree(Directory, Git(Directory, 'rev-parse', 'HEAD'), { directory: 'deploy/helm/oxibelt' }), /regular files/)
  } finally {
    Fs.rmSync(Directory, { recursive: true, force: true })
  }
})

test('rejects traversal, special, unexpected, and partial archive members', () => {
  const Epoch = 1785332178
  const Expected = new Map([['oxibelt/values.yaml', Buffer.from('image:\n')]])
  Assert.throws(() => InspectHelmChartArchive(Archive([TarMember('../escape', Buffer.alloc(0), Epoch)])), /unsafe/)
  Assert.throws(() => AssertExpectedHelmChartArchiveMembers(
    Archive([TarMember('oxibelt/values.yaml', Buffer.from('image:\n'), Epoch, 0o644, '2')]), Expected, Epoch
  ), /regular file/)
  Assert.throws(() => AssertExpectedHelmChartArchiveMembers(
    Archive([TarMember('oxibelt/values.yaml', Buffer.from('image:\n'), Epoch), TarMember('oxibelt/unexpected.yaml', Buffer.alloc(0), Epoch)]), Expected, Epoch
  ), /unexpected/)
  Assert.throws(() => AssertExpectedHelmChartArchiveMembers(
    Archive([]), Expected, Epoch
  ), /empty/)
  Assert.throws(() => InspectHelmChartArchive(
    Zlib.gzipSync(TarMember('oxibelt/values.yaml', Buffer.from('image:\n'), Epoch))
  ), /missing tar terminator/)
  const CorruptChecksum = TarMember('oxibelt/values.yaml', Buffer.from('image:\n'), Epoch)
  CorruptChecksum[0] ^= 0xff
  Assert.throws(() => InspectHelmChartArchive(Archive([CorruptChecksum])), /checksum/)
  Assert.throws(() => InspectHelmChartArchive(
    Zlib.gzipSync(Buffer.alloc(MaximumDecompressedTarBytes + 1))
  ), /maxOutputLength|larger/)
  Assert.throws(() => InspectHelmChartArchive(Buffer.alloc(MaximumCompressedArchiveBytes + 1)), /compressed bytes/)
  const OversizedHeader = TarMember('oxibelt/values.yaml', Buffer.alloc(0), Epoch)
  WriteOctal(OversizedHeader, 124, 12, MaximumArchiveMemberBytes + 1)
  OversizedHeader.fill(0x20, 148, 156)
  WriteOctal(OversizedHeader, 148, 8, OversizedHeader.subarray(0, 512).reduce((Sum, Byte, Index) => Sum + (Index >= 148 && Index < 156 ? 0x20 : Byte), 0))
  Assert.throws(() => InspectHelmChartArchive(Archive([OversizedHeader])), /member exceeds/)
  const TooMany = Array.from({ length: MaximumArchiveMembers + 1 }, (Unused, Index) => {
    void Unused
    return TarMember(`oxibelt/${Index}.yaml`, Buffer.alloc(0), Epoch)
  })
  Assert.throws(() => InspectHelmChartArchive(Archive(TooMany)), /exceeds.*members/)
  Assert.throws(() => AssertExpectedHelmChartArchiveMembers(
    Archive([TarMember('oxibelt/values.yaml', Buffer.from('image:\n'), Epoch, 0o755)]), Expected, Epoch
  ), /normalized mode/)
})

test('uses origin only as a structural guard, not repository provenance authentication', () => {
  const NonRepository = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-not-git-'))
  const GitRepository = FixtureRepository()
  const Output = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-origin-output-'))
  try {
    Assert.throws(() => PrepareHelmChartRelease({ ...Options(Output), workspacePath: NonRepository }), /not a git repository|Git repository top-level/)
    Assert.throws(() => PrepareHelmChartRelease({ ...Options(Output), workspacePath: GitRepository }), /supported OxiBelt origin remote/)
    Git(GitRepository, 'remote', 'add', 'origin', 'https://github.com/Other/Repository.git')
    Assert.throws(() => PrepareHelmChartRelease({ ...Options(Output), workspacePath: GitRepository }), /supported OxiBelt clone URL/)
    Git(GitRepository, 'remote', 'set-url', 'origin', 'https://github.com/OxiBelt/OxiBelt.git')
    Assert.throws(
      () => PrepareHelmChartRelease({ ...Options(Output), workspacePath: GitRepository }),
      ErrorValue => ErrorValue instanceof Error && !/origin|provenance|authenticated/i.test(ErrorValue.message)
    )
  } finally {
    Fs.rmSync(NonRepository, { recursive: true, force: true })
    Fs.rmSync(GitRepository, { recursive: true, force: true })
    Fs.rmSync(Output, { recursive: true, force: true })
  }
})

test('normalizes accepted HTTPS and SSH origin spellings out of the plan bytes', () => {
  const Origins = [
    'https://github.com/OxiBelt/OxiBelt',
    'https://github.com/OxiBelt/OxiBelt.git',
    'git@github.com:OxiBelt/OxiBelt.git',
    'ssh://git@github.com/OxiBelt/OxiBelt.git'
  ]
  const Clones: string[] = []
  const Outputs: string[] = []
  try {
    const Plans = Origins.map(Origin => {
      const Clone = CloneWithOrigin(Origin)
      const Output = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-origin-plan-'))
      Clones.push(Clone)
      Outputs.push(Output)
      return PrepareHelmChartRelease({ ...Options(Output), workspacePath: Clone })
    })
    for (const Plan of Plans.slice(1)) Assert.deepEqual(Plan, Plans[0])
    Assert.equal(Plans[0].repository, 'OxiBelt/OxiBelt')
    Assert.equal(Plans[0].repositoryProvenance, 'github-workflow-authentication-required')
  } finally {
    for (const Directory of Clones) Fs.rmSync(Directory, { recursive: true, force: true })
    for (const Directory of Outputs) Fs.rmSync(Directory, { recursive: true, force: true })
  }
})

test('requires an empty or exact complete regular output inventory and preserves prior outputs on failure', () => {
  const Directory = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-inventory-'))
  try {
    Fs.writeFileSync(Path.join(Directory, 'unexpected'), 'x')
    Assert.throws(() => PrepareHelmChartRelease(Options(Directory)), /exactly the complete expected inventory/)
    Fs.unlinkSync(Path.join(Directory, 'unexpected'))
    Fs.symlinkSync('/tmp', Path.join(Directory, 'linked'))
    Assert.throws(() => PrepareHelmChartRelease(Options(Directory)), /exactly the complete expected inventory/)
    Fs.unlinkSync(Path.join(Directory, 'linked'))
    Fs.mkdirSync(Path.join(Directory, 'directory'))
    Assert.throws(() => PrepareHelmChartRelease(Options(Directory)), /exactly the complete expected inventory/)
    Fs.rmdirSync(Path.join(Directory, 'directory'))
    const Plan = PrepareHelmChartRelease(Options(Directory))
    const Snapshot = new Map(Plan.charts.map(Chart => [Chart.filename, Fs.readFileSync(Path.join(Directory, Chart.filename))]))
    const Archives = new Map(Plan.charts.map(Chart => [Chart.name, Snapshot.get(Chart.filename) as Buffer]))
    Fs.unlinkSync(Path.join(Directory, Plan.charts[0].filename))
    Fs.symlinkSync(HelmChartReleasePlanFilename, Path.join(Directory, Plan.charts[0].filename))
    Assert.throws(() => PrepareHelmChartRelease(Options(Directory)), /only regular files/)
    Assert.throws(() => VerifyHelmChartRelease(Options(Directory)), /only regular files/)
    Fs.unlinkSync(Path.join(Directory, Plan.charts[0].filename))
    Fs.writeFileSync(Path.join(Directory, Plan.charts[0].filename), Snapshot.get(Plan.charts[0].filename) as Buffer)
    Fs.unlinkSync(Path.join(Directory, Plan.charts[1].filename))
    Fs.mkdirSync(Path.join(Directory, Plan.charts[1].filename))
    Assert.throws(() => PrepareHelmChartRelease(Options(Directory)), /only regular files/)
    Fs.rmdirSync(Path.join(Directory, Plan.charts[1].filename))
    Fs.writeFileSync(Path.join(Directory, Plan.charts[1].filename), Snapshot.get(Plan.charts[1].filename) as Buffer)
    Fs.unlinkSync(Path.join(Directory, Plan.charts[0].filename))
    Assert.throws(() => PrepareHelmChartRelease(Options(Directory)), /exactly the complete expected inventory/)
    Fs.writeFileSync(Path.join(Directory, Plan.charts[0].filename), Snapshot.get(Plan.charts[0].filename) as Buffer)
    Fs.writeFileSync(Path.join(Directory, 'unexpected'), 'x')
    Assert.throws(() => VerifyHelmChartRelease(Options(Directory)), /exactly the complete expected inventory/)
    Fs.unlinkSync(Path.join(Directory, 'unexpected'))
    Assert.throws(() => PrepareHelmChartRelease({ ...Options(Directory), revision: '0'.repeat(40) }), /ref .* supplied revision/)
    let RenameCalls = 0
    Assert.throws(() => InstallHelmChartReleaseOutputsForTesting(
      Directory, Archives, Plan, (OldPath, NewPath) => {
        RenameCalls += 1
        if (RenameCalls === 2) throw new Error('injected install failure')
        Fs.renameSync(OldPath, NewPath)
      }
    ), /injected install failure/)
    for (const [Filename, Content] of Snapshot) Assert.deepEqual(Fs.readFileSync(Path.join(Directory, Filename)), Content)
  } finally {
    Fs.rmSync(Directory, { recursive: true, force: true })
  }
})

test('rejects an oversized plan before parsing it', () => {
  const Directory = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-plan-size-'))
  try {
    PrepareHelmChartRelease(Options(Directory))
    Fs.writeFileSync(Path.join(Directory, HelmChartReleasePlanFilename), Buffer.alloc(MaximumPlanBytes + 1, 0x20))
    Assert.throws(() => VerifyHelmChartRelease(Options(Directory)), /exceeds/)
  } finally {
    Fs.rmSync(Directory, { recursive: true, force: true })
  }
})

test('independent verification detects missing and mutated release outputs', () => {
  const Directory = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-verify-'))
  try {
    const Plan = PrepareHelmChartRelease(Options(Directory))
    const Original = Fs.readFileSync(Path.join(Directory, Plan.charts[0].filename))
    Fs.unlinkSync(Path.join(Directory, Plan.charts[0].filename))
    Assert.throws(() => VerifyHelmChartRelease(Options(Directory)), /exactly the complete expected inventory/)
    Fs.writeFileSync(Path.join(Directory, Plan.charts[0].filename), Original)
    PrepareHelmChartRelease(Options(Directory))
    const ArchivePath = Path.join(Directory, Plan.charts[0].filename)
    const Mutated = Fs.readFileSync(ArchivePath)
    Mutated[32] ^= 0xff
    Fs.writeFileSync(ArchivePath, Mutated)
    Assert.throws(() => VerifyHelmChartRelease(Options(Directory)), /byte-for-byte reproducible/)
    Assert.ok(Fs.existsSync(Path.join(Directory, HelmChartReleasePlanFilename)))
  } finally {
    Fs.rmSync(Directory, { recursive: true, force: true })
  }
})
