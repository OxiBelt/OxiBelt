import { execFileSync } from 'node:child_process'
import * as Crypto from 'node:crypto'
import * as Fs from 'node:fs'
import * as Os from 'node:os'
import * as Path from 'node:path'
import * as Process from 'node:process'
import { pathToFileURL } from 'node:url'
import * as Zlib from 'node:zlib'
import { ParseReleaseRef, ParseReleaseTag } from './docker_image_release.js'

/* eslint-disable @typescript-eslint/naming-convention -- Canonical release-plan JSON uses stable lower-camel-case keys. */

export const HelmChartReleasePlanSchemaVersion = 1
export const HelmChartReleasePlanFilename = 'helm-chart-release-plan.json'
export const MaximumGitChartFiles = 256
export const MaximumGitChartFileBytes = 1024 * 1024
export const MaximumGitChartBytes = 8 * 1024 * 1024
export const MaximumCompressedArchiveBytes = 16 * 1024 * 1024
export const MaximumDecompressedTarBytes = 32 * 1024 * 1024
export const MaximumArchiveMembers = 256
export const MaximumArchiveMemberBytes = 4 * 1024 * 1024
export const MaximumArchiveContentBytes = 16 * 1024 * 1024
export const MaximumPlanBytes = 128 * 1024
export const MaximumCliOutputBytes = 64 * 1024

const FullRevision = /^[0-9a-f]{40}$/
const Semver = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/
const Repository = 'OxiBelt/OxiBelt'
const CanonicalOrigin = /^(?:https:\/\/github[.]com\/OxiBelt\/OxiBelt(?:[.]git)?|git@github[.]com:OxiBelt\/OxiBelt(?:[.]git)?|ssh:\/\/git@github[.]com\/OxiBelt\/OxiBelt(?:[.]git)?)$/
const SupportedHelmVersion = /^v(?:3[.]21[.]3|4[.]2[.]3)(?:\+[0-9A-Za-z.-]+)?$/

type ChartSpec = {
  directory: string
  name: string
  ociRepository: string
  defaultImageFiles: string[]
}

const ChartSpecs: ChartSpec[] = [
  {
    directory: 'deploy/helm/oxibelt',
    name: 'oxibelt',
    ociRepository: 'oci://ghcr.io/oxibelt/charts/oxibelt',
    defaultImageFiles: [
      'deploy/helm/oxibelt/values.yaml',
      'deploy/helm/oxibelt/examples/strict-dataplane-values.yaml'
    ]
  },
  {
    directory: 'deploy/helm/oxibelt-gateway-controller',
    name: 'oxibelt-gateway-controller',
    ociRepository: 'oci://ghcr.io/oxibelt/charts/oxibelt-gateway-controller',
    defaultImageFiles: ['deploy/helm/oxibelt-gateway-controller/values.yaml']
  }
]

export type HelmChartReleasePlan = {
  schemaVersion: 1
  repository: string
  repositoryProvenance: 'github-workflow-authentication-required'
  sourceRef: string
  sourceRevision: string
  commitEpoch: number
  releaseVersion: string
  charts: Array<{
    name: string
    sourceDirectory: string
    targetOciRepository: string
    filename: string
    archiveSha256: string
    metadata: { version: string, appVersion: string, annotations: Record<string, string> }
    experimentalStatus: 'experimental'
    defaultImages: Array<{ path: string, from: 'latest', to: string }>
    transformationRecipe: string[]
  }>
}

export type HelmChartReleaseOptions = {
  workspacePath: string
  ref: string
  revision: string
  outputDirectory: string
}

type GitTreeFile = { path: string, mode: string, object: string, content: Buffer }
type ArchiveMember = { name: string, mode: number, mtime: number, type: string, content: Buffer }

function RunGit(WorkspacePath: string, Arguments: string[], MaximumOutputBytes = MaximumCliOutputBytes): string {
  return execFileSync('git', ['-C', WorkspacePath, ...Arguments], {
    encoding: 'utf8',
    maxBuffer: MaximumOutputBytes,
    stdio: ['ignore', 'pipe', 'pipe']
  }).trim()
}

function RunGitBuffer(WorkspacePath: string, Arguments: string[], MaximumOutputBytes: number): Buffer {
  return execFileSync('git', ['-C', WorkspacePath, ...Arguments], {
    encoding: 'buffer', maxBuffer: MaximumOutputBytes, stdio: ['ignore', 'pipe', 'pipe']
  })
}

function ResolveWorkspace(WorkspacePath: string): string {
  const Resolved = Path.resolve(WorkspacePath)
  const Metadata = Fs.lstatSync(Resolved)
  if (Metadata.isSymbolicLink() || !Metadata.isDirectory()) {
    throw new Error(`workspace path must be a non-symlink directory: ${WorkspacePath}`)
  }
  const Canonical = Fs.realpathSync(Resolved)
  const TopLevel = RunGit(Canonical, ['rev-parse', '--show-toplevel'])
  if (Fs.realpathSync(TopLevel) !== Canonical) throw new Error('workspace path must be the Git repository top-level')
  return Canonical
}

// This is only a local structural guard against preparing an obvious wrong checkout.
// A mutable local remote URL does not authenticate repository provenance; the later
// GitHub workflow must authenticate the intended repository and release revision.
function AssertStructuralOxiBeltOrigin(WorkspacePath: string): void {
  let Origin: string
  try {
    Origin = RunGit(WorkspacePath, ['config', '--get', 'remote.origin.url'])
  } catch {
    throw new Error('workspace must define a supported OxiBelt origin remote')
  }
  if (!CanonicalOrigin.test(Origin)) throw new Error(`workspace origin is not a supported OxiBelt clone URL for ${Repository}`)
}

function ResolveOutputDirectory(Value: string): string {
  const Resolved = Path.resolve(Value)
  const Metadata = Fs.lstatSync(Resolved)
  if (Metadata.isSymbolicLink() || !Metadata.isDirectory()) {
    throw new Error(`output directory must be a non-symlink directory: ${Value}`)
  }
  return Fs.realpathSync(Resolved)
}

function AssertSafeRelativePath(Value: string, Label: string): void {
  if (Value === '' || Path.isAbsolute(Value) || Value.includes('\\') || Value.split('/').some(Part => Part === '' || Part === '.' || Part === '..')) {
    throw new Error(`${Label} is unsafe: ${Value}`)
  }
}

function ResolveRevision(WorkspacePath: string, Ref: string, Revision: string): string {
  if (!FullRevision.test(Revision)) throw new Error('revision must be a full lowercase Git SHA')
  const Resolved = RunGit(WorkspacePath, ['rev-parse', '--verify', `${Ref}^{commit}`]).toLowerCase()
  if (!FullRevision.test(Resolved) || Resolved !== Revision) {
    throw new Error(`ref ${Ref} must resolve exactly to supplied revision ${Revision}`)
  }
  return Resolved
}

function CommitEpoch(WorkspacePath: string, Revision: string): number {
  const Value = RunGit(WorkspacePath, ['show', '-s', '--format=%ct', Revision])
  if (!/^[0-9]+$/.test(Value)) throw new Error('Git commit epoch must be a nonnegative integer')
  const Epoch = Number(Value)
  if (!Number.isSafeInteger(Epoch) || Epoch < 0) throw new Error('Git commit epoch is outside the supported range')
  return Epoch
}

export function ReadHelmChartTree(WorkspacePath: string, Revision: string, Spec: Pick<ChartSpec, 'directory'>): GitTreeFile[] {
  AssertSafeRelativePath(Spec.directory, 'chart directory')
  const Prefix = `${Spec.directory}/`
  const Output = RunGitBuffer(WorkspacePath, ['ls-tree', '-r', '-z', Revision, '--', Spec.directory], MaximumCliOutputBytes)
  const Files: GitTreeFile[] = []
  let TotalBytes = 0
  for (const Record of Output.toString('utf8').split('\0').filter(Boolean)) {
    const Match = /^(\d+) (\w+) ([0-9a-f]{40})\t(.+)$/.exec(Record)
    if (Match === null) throw new Error(`invalid Git tree record below ${Spec.directory}`)
    const [, Mode, Type, Object, FilePath] = Match
    AssertSafeRelativePath(FilePath, 'Git tree path')
    if (!FilePath.startsWith(Prefix)) throw new Error(`Git tree path escapes chart directory: ${FilePath}`)
    if (Type !== 'blob' || (Mode !== '100644' && Mode !== '100755')) {
      throw new Error(`chart source must contain only tracked regular files: ${FilePath}`)
    }
    if (Files.length >= MaximumGitChartFiles) throw new Error(`chart source exceeds ${MaximumGitChartFiles} files`)
    const Content = RunGitBuffer(WorkspacePath, ['cat-file', 'blob', Object], MaximumGitChartFileBytes)
    if (Content.length > MaximumGitChartFileBytes) throw new Error(`chart source file exceeds ${MaximumGitChartFileBytes} bytes: ${FilePath}`)
    if (TotalBytes > MaximumGitChartBytes - Content.length) throw new Error(`chart source exceeds ${MaximumGitChartBytes} bytes`)
    TotalBytes += Content.length
    Files.push({ path: FilePath, mode: Mode, object: Object, content: Content })
  }
  if (Files.length === 0) throw new Error(`chart source has no tracked files: ${Spec.directory}`)
  Files.sort((Left, Right) => Left.path.localeCompare(Right.path))
  return Files
}

function ReplaceOneLatest(Content: Buffer, FilePath: string, Version: string): Buffer {
  const Text = Content.toString('utf8')
  if (!Buffer.from(Text, 'utf8').equals(Content)) throw new Error(`${FilePath} must be UTF-8 text`)
  const Matches = Text.match(/^  tag: latest$/gm) ?? []
  if (Matches.length !== 1) throw new Error(`${FilePath} must contain exactly one default image.tag: latest`)
  return Buffer.from(Text.replace(/^  tag: latest$/m, `  tag: ${Version}`), 'utf8')
}

function ReleaseChartYaml(Content: Buffer, FilePath: string, Version: string): Buffer {
  const Text = Content.toString('utf8')
  if (!Buffer.from(Text, 'utf8').equals(Content)) throw new Error(`${FilePath} must be UTF-8 text`)
  const VersionMatches = Text.match(/^version: 0\.0\.0$/gm) ?? []
  const AppVersionMatches = Text.match(/^appVersion: "0\.0\.0"$/gm) ?? []
  if (VersionMatches.length !== 1 || AppVersionMatches.length !== 1) {
    throw new Error(`${FilePath} must retain exactly one committed 0.0.0 version and appVersion sentinel`)
  }
  return Buffer.from(
    Text.replace(/^version: 0\.0\.0$/m, `version: ${Version}`).replace(/^appVersion: "0\.0\.0"$/m, `appVersion: "${Version}"`),
    'utf8'
  )
}

function ParseChartDocument(Content: Buffer, FilePath: string): { apiVersion: string, name: string, description: string, type: string, version: string, appVersion: string, annotations: Record<string, string> } {
  const Text = Content.toString('utf8')
  const Scalar = (Key: string): string | undefined => new RegExp(`^${Key}: ?(?:"([^"\\n]+)"|([^\\s]+(?: [^\\n]+)?))$`, 'm').exec(Text)?.slice(1).find(Value => Value !== undefined)
  const ApiVersion = Scalar('apiVersion')
  const Name = Scalar('name')
  const Description = Scalar('description')
  const Type = Scalar('type')
  const Version = Scalar('version')
  const AppVersion = Scalar('appVersion')
  if ([ApiVersion, Name, Description, Type, Version, AppVersion].some(Value => Value === undefined)) throw new Error(`${FilePath} has invalid chart metadata`)
  const Annotations: Record<string, string> = {}
  const Block = /^annotations:\n((?:  [^\n]+\n?)*)/m.exec(Text)?.[1]
  if (Block === undefined) throw new Error(`${FilePath} must define annotations`)
  for (const Line of Block.split('\n').filter(Boolean)) {
    const Match = /^  ([^:]+):\s*"?([^"\n]+?)"?$/.exec(Line)
    if (Match === null) throw new Error(`${FilePath} has invalid annotation: ${Line}`)
    Annotations[Match[1]] = Match[2]
  }
  return { apiVersion: ApiVersion as string, name: Name as string, description: Description as string, type: Type as string, version: Version as string, appVersion: AppVersion as string, annotations: Annotations }
}

function TransformedFiles(Files: GitTreeFile[], Spec: ChartSpec, Version: string): Map<string, Buffer> {
  const Values = new Set(Spec.defaultImageFiles)
  const Result = new Map<string, Buffer>()
  for (const File of Files) {
    let Content = File.content
    if (File.path === `${Spec.directory}/Chart.yaml`) Content = ReleaseChartYaml(Content, File.path, Version)
    if (Values.has(File.path)) Content = ReplaceOneLatest(Content, File.path, Version)
    Result.set(File.path, Content)
  }
  for (const FilePath of Values) {
    if (!Result.has(FilePath)) throw new Error(`missing required default image file in Git tree: ${FilePath}`)
  }
  return Result
}

function WriteStagedChart(Directory: string, Files: GitTreeFile[], Content: Map<string, Buffer>, Spec: ChartSpec, Epoch: number): string {
  const ChartDirectory = Path.join(Directory, Spec.name)
  Fs.mkdirSync(ChartDirectory, { recursive: true, mode: 0o755 })
  for (const File of Files) {
    const Relative = File.path.slice(Spec.directory.length + 1)
    AssertSafeRelativePath(Relative, 'staged chart path')
    const Destination = Path.join(ChartDirectory, ...Relative.split('/'))
    const Parent = Path.dirname(Destination)
    Fs.mkdirSync(Parent, { recursive: true, mode: 0o755 })
    const FileContent = Content.get(File.path)
    if (FileContent === undefined) throw new Error(`missing transformed Git content: ${File.path}`)
    Fs.writeFileSync(Destination, FileContent, { flag: 'wx', mode: 0o644 })
    Fs.chmodSync(Destination, 0o644)
    Fs.utimesSync(Destination, Epoch, Epoch)
  }
  NormalizeDirectoryMetadata(ChartDirectory, Epoch)
  return ChartDirectory
}

function NormalizeDirectoryMetadata(Directory: string, Epoch: number): void {
  for (const Entry of Fs.readdirSync(Directory, { withFileTypes: true })) {
    const Child = Path.join(Directory, Entry.name)
    if (Entry.isDirectory()) NormalizeDirectoryMetadata(Child, Epoch)
    Fs.chmodSync(Child, Entry.isDirectory() ? 0o755 : 0o644)
    Fs.utimesSync(Child, Epoch, Epoch)
  }
  Fs.chmodSync(Directory, 0o755)
  Fs.utimesSync(Directory, Epoch, Epoch)
}

function AssertSupportedHelm(): void {
  const Version = execFileSync('helm', ['version', '--short'], {
    encoding: 'utf8', maxBuffer: MaximumCliOutputBytes, stdio: ['ignore', 'pipe', 'pipe']
  }).trim()
  if (!SupportedHelmVersion.test(Version)) throw new Error(`unsupported Helm version: ${Version}`)
}

function RunHelmPackage(StageRoot: string, ChartDirectory: string, Version: string): Buffer {
  const PackageDirectory = Path.join(StageRoot, 'package')
  Fs.mkdirSync(PackageDirectory, { mode: 0o755 })
  execFileSync('helm', ['package', ChartDirectory, '--version', Version, '--app-version', Version, '--destination', PackageDirectory], {
    encoding: 'utf8', maxBuffer: MaximumCliOutputBytes, stdio: ['ignore', 'pipe', 'pipe']
  })
  const Expected = Path.join(PackageDirectory, `${Path.basename(ChartDirectory)}-${Version}.tgz`)
  const Metadata = Fs.lstatSync(Expected)
  if (Metadata.isSymbolicLink() || !Metadata.isFile()) throw new Error('helm package did not produce a regular chart archive')
  if (Metadata.size > MaximumCompressedArchiveBytes) throw new Error(`helm package archive exceeds ${MaximumCompressedArchiveBytes} bytes`)
  return Fs.readFileSync(Expected)
}

function ReadTarString(BufferValue: Buffer): string {
  const Nul = BufferValue.indexOf(0)
  return BufferValue.subarray(0, Nul === -1 ? BufferValue.length : Nul).toString('utf8')
}

function ReadTarOctal(BufferValue: Buffer, Label: string): number {
  const Text = ReadTarString(BufferValue).trim()
  if (Text === '') return 0
  if (!/^[0-7]+$/.test(Text)) throw new Error(`archive ${Label} is not octal`)
  const Value = Number.parseInt(Text, 8)
  if (!Number.isSafeInteger(Value) || Value < 0) throw new Error(`archive ${Label} is outside the safe integer range`)
  return Value
}

function AssertTarHeaderChecksum(Header: Buffer): void {
  const Stored = ReadTarOctal(Header.subarray(148, 156), 'header checksum')
  let Calculated = 0
  for (let Index = 0; Index < Header.length; Index += 1) {
    Calculated += Index >= 148 && Index < 156 ? 0x20 : Header[Index]
  }
  if (Stored !== Calculated) throw new Error('archive tar header checksum is invalid')
}

export function InspectHelmChartArchive(Archive: Buffer): ArchiveMember[] {
  if (Archive.length > MaximumCompressedArchiveBytes) throw new Error(`chart archive exceeds ${MaximumCompressedArchiveBytes} compressed bytes`)
  const Tar = Zlib.gunzipSync(Archive, { maxOutputLength: MaximumDecompressedTarBytes })
  if (Tar.length > MaximumDecompressedTarBytes) throw new Error(`chart archive exceeds ${MaximumDecompressedTarBytes} decompressed bytes`)
  const Members: ArchiveMember[] = []
  let Offset = 0
  let Terminated = false
  let TotalContentBytes = 0
  while (Offset < Tar.length) {
    const Header = Tar.subarray(Offset, Offset + 512)
    if (Header.length !== 512) throw new Error('archive has a partial tar header')
    if (Header.every(Byte => Byte === 0)) {
      if (Tar.length - Offset < 1024 || !Tar.subarray(Offset).every(Byte => Byte === 0)) throw new Error('archive has invalid tar terminator or padding')
      Terminated = true
      break
    }
    AssertTarHeaderChecksum(Header)
    if (Members.length >= MaximumArchiveMembers) throw new Error(`chart archive exceeds ${MaximumArchiveMembers} members`)
    const Prefix = ReadTarString(Header.subarray(345, 500))
    const Name = `${Prefix === '' ? '' : `${Prefix}/`}${ReadTarString(Header.subarray(0, 100))}`
    AssertSafeRelativePath(Name, 'archive member path')
    const Size = ReadTarOctal(Header.subarray(124, 136), 'member size')
    if (Size > MaximumArchiveMemberBytes) throw new Error(`archive member exceeds ${MaximumArchiveMemberBytes} bytes: ${Name}`)
    if (TotalContentBytes > MaximumArchiveContentBytes - Size) throw new Error(`chart archive content exceeds ${MaximumArchiveContentBytes} bytes`)
    TotalContentBytes += Size
    const ContentStart = Offset + 512
    if (!Number.isSafeInteger(ContentStart) || ContentStart > Tar.length) throw new Error(`archive member offset is unsafe: ${Name}`)
    const ContentEnd = ContentStart + Size
    if (!Number.isSafeInteger(ContentEnd) || ContentEnd > Tar.length) throw new Error(`archive member is partial: ${Name}`)
    Members.push({
      name: Name,
      mode: ReadTarOctal(Header.subarray(100, 108), 'member mode'),
      mtime: ReadTarOctal(Header.subarray(136, 148), 'member mtime'),
      type: String.fromCharCode(Header[156] === 0 ? 48 : Header[156]),
      content: Buffer.from(Tar.subarray(ContentStart, ContentEnd))
    })
    const PaddedSize = Math.ceil(Size / 512) * 512
    if (!Number.isSafeInteger(PaddedSize) || PaddedSize < Size || ContentStart > Number.MAX_SAFE_INTEGER - PaddedSize) throw new Error(`archive member padding is unsafe: ${Name}`)
    Offset = ContentStart + PaddedSize
    if (Offset > Tar.length) throw new Error(`archive member padding is partial: ${Name}`)
  }
  if (!Terminated) throw new Error('archive is partial: missing tar terminator')
  if (Members.length === 0) throw new Error('chart archive is empty')
  return Members
}

function ExpectedArchiveMembers(Files: GitTreeFile[], Content: Map<string, Buffer>, Spec: ChartSpec): Map<string, Buffer> {
  const Expected = new Map<string, Buffer>()
  for (const File of Files) {
    const Relative = File.path.slice(Spec.directory.length + 1)
    Expected.set(`${Spec.name}/${Relative}`, Content.get(File.path) as Buffer)
  }
  return Expected
}

export function AssertExpectedHelmChartArchiveMembers(Archive: Buffer, Expected: Map<string, Buffer>, Epoch: number): ArchiveMember[] {
  const Members = InspectHelmChartArchive(Archive)
  const Seen = new Set<string>()
  for (const Member of Members) {
    if (Member.type !== '0') throw new Error(`archive member must be a regular file: ${Member.name}`)
    if (Member.mode !== 0o644 || Member.mtime !== Epoch) {
      throw new Error(`archive member must use normalized mode and commit epoch: ${Member.name}`)
    }
    if (!Expected.has(Member.name)) throw new Error(`archive contains unexpected member: ${Member.name}`)
    if (Seen.has(Member.name)) throw new Error(`archive repeats member: ${Member.name}`)
    Seen.add(Member.name)
  }
  if (Seen.size !== Expected.size) throw new Error(`archive is partial: expected ${Expected.size} files but found ${Seen.size}`)
  return Members
}

function VerifyArchive(Archive: Buffer, Files: GitTreeFile[], Content: Map<string, Buffer>, Spec: ChartSpec, Epoch: number): void {
  const Expected = ExpectedArchiveMembers(Files, Content, Spec)
  const Members = AssertExpectedHelmChartArchiveMembers(Archive, Expected, Epoch)
  for (const Member of Members) {
    const ExpectedContent = Expected.get(Member.name)
    if (ExpectedContent === undefined) throw new Error(`archive member was not expected: ${Member.name}`)
    if (Member.name === `${Spec.name}/Chart.yaml`) {
      const ExpectedChart = ParseChartDocument(ExpectedContent, Member.name)
      const ActualChart = ParseChartDocument(Member.content, Member.name)
      if (CanonicalJson(ExpectedChart) !== CanonicalJson(ActualChart)) {
        throw new Error(`archive Chart.yaml differs from transformed Git metadata: ${Member.name}`)
      }
    } else if (!ExpectedContent.equals(Member.content)) {
      throw new Error(`archive member content differs from transformed Git content: ${Member.name}`)
    }
  }
}

function Sha256(Value: Buffer): string {
  return Crypto.createHash('sha256').update(Value).digest('hex')
}

function CanonicalJson(Value: unknown): string {
  if (Array.isArray(Value)) return `[${Value.map(CanonicalJson).join(',')}]`
  if (typeof Value === 'object' && Value !== null) {
    const ObjectValue = Value as Record<string, unknown>
    return `{${Object.keys(ObjectValue).sort().map(Key => `${JSON.stringify(Key)}:${CanonicalJson(ObjectValue[Key])}`).join(',')}}`
  }
  return JSON.stringify(Value)
}

function BuildPlan(WorkspacePath: string, Ref: string, Revision: string, Epoch: number, Version: string, Archives: Map<string, Buffer>): HelmChartReleasePlan {
  const Charts = ChartSpecs.map(Spec => {
    const Files = ReadHelmChartTree(WorkspacePath, Revision, Spec)
    const Content = TransformedFiles(Files, Spec, Version)
    const ChartYaml = Content.get(`${Spec.directory}/Chart.yaml`)
    if (ChartYaml === undefined) throw new Error(`missing Chart.yaml in ${Spec.directory}`)
    const Metadata = ParseChartDocument(ChartYaml, `${Spec.directory}/Chart.yaml`)
    if (Metadata.version !== Version || Metadata.appVersion !== Version || Metadata.annotations['oxibelt.dev/feature-status'] !== 'experimental') {
      throw new Error(`release chart metadata must retain experimental status and bind ${Version}: ${Spec.name}`)
    }
    const Filename = `${Spec.name}-${Version}.tgz`
    const Archive = Archives.get(Spec.name)
    if (Archive === undefined) throw new Error(`missing staged archive: ${Filename}`)
    VerifyArchive(Archive, Files, Content, Spec, Epoch)
    return {
      name: Spec.name,
      sourceDirectory: Spec.directory,
      targetOciRepository: Spec.ociRepository,
      filename: Filename,
      archiveSha256: Sha256(Archive),
      metadata: { version: Metadata.version, appVersion: Metadata.appVersion, annotations: Metadata.annotations },
      experimentalStatus: 'experimental' as const,
      defaultImages: Spec.defaultImageFiles.map(FilePath => ({ path: FilePath, from: 'latest' as const, to: Version })),
      transformationRecipe: [
        'read only Git-tracked regular blobs from the exact commit tree',
        'normalize staged directories to 0755 and staged files to 0644 at commit epoch',
        'replace only declared image.tag latest defaults with the exact release SemVer',
        'helm package with exact --version and --app-version',
        'reject noncanonical, unexpected, duplicate, or partial archive members'
      ]
    }
  })
  return { schemaVersion: HelmChartReleasePlanSchemaVersion, repository: Repository, repositoryProvenance: 'github-workflow-authentication-required', sourceRef: Ref, sourceRevision: Revision, commitEpoch: Epoch, releaseVersion: Version, charts: Charts }
}

function BuildArchives(WorkspacePath: string, Revision: string, Epoch: number, Version: string): Map<string, Buffer> {
  const StageRoot = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-chart-release-'))
  try {
    AssertSupportedHelm()
    const Archives = new Map<string, Buffer>()
    for (const Spec of ChartSpecs) {
      const Files = ReadHelmChartTree(WorkspacePath, Revision, Spec)
      const Content = TransformedFiles(Files, Spec, Version)
      const ChartDirectory = WriteStagedChart(Path.join(StageRoot, Spec.name), Files, Content, Spec, Epoch)
      Archives.set(Spec.name, RunHelmPackage(Path.join(StageRoot, Spec.name), ChartDirectory, Version))
    }
    return Archives
  } finally {
    Fs.rmSync(StageRoot, { recursive: true, force: true })
  }
}

type RenameFile = (OldPath: string, NewPath: string) => void

function InstallOutputs(OutputDirectory: string, Archives: Map<string, Buffer>, Plan: HelmChartReleasePlan, Rename: RenameFile = Fs.renameSync): void {
  const Planned = [
    ...Plan.charts.map(Chart => ({ path: Path.join(OutputDirectory, Chart.filename), content: Archives.get(Chart.name) as Buffer })),
    { path: Path.join(OutputDirectory, HelmChartReleasePlanFilename), content: Buffer.from(`${CanonicalJson(Plan)}\n`, 'utf8') }
  ]
  const Staged = Fs.mkdtempSync(Path.join(OutputDirectory, '.oxibelt-helm-chart-release-'))
  const Backups: Array<{ path: string, backup: string, installed: boolean }> = []
  try {
    for (const Item of Planned) {
      const Base = Path.basename(Item.path)
      if (Item.path !== Path.join(OutputDirectory, Base)) throw new Error('release output path must stay directly under output directory')
      if (Fs.existsSync(Item.path)) {
        const Metadata = Fs.lstatSync(Item.path)
        if (Metadata.isSymbolicLink() || !Metadata.isFile()) throw new Error(`release output must be a regular file: ${Base}`)
      }
      const Next = Path.join(Staged, `${Base}.next`)
      Fs.writeFileSync(Next, Item.content, { flag: 'wx', mode: 0o644 })
      Backups.push({ path: Item.path, backup: Path.join(Staged, `${Base}.backup`), installed: false })
    }
    for (let Index = 0; Index < Planned.length; Index += 1) {
      const Entry = Backups[Index]
      if (Fs.existsSync(Entry.path)) Rename(Entry.path, Entry.backup)
      Rename(Path.join(Staged, `${Path.basename(Entry.path)}.next`), Entry.path)
      Entry.installed = true
    }
  } catch (ErrorValue) {
    for (const Entry of [...Backups].reverse()) {
      if (Entry.installed && Fs.existsSync(Entry.path)) Fs.unlinkSync(Entry.path)
      if (Fs.existsSync(Entry.backup)) Rename(Entry.backup, Entry.path)
    }
    throw ErrorValue
  } finally {
    Fs.rmSync(Staged, { recursive: true, force: true })
  }
}

export function InstallHelmChartReleaseOutputsForTesting(
  OutputDirectory: string,
  Archives: Map<string, Buffer>,
  Plan: HelmChartReleasePlan,
  Rename: RenameFile
): void {
  InstallOutputs(OutputDirectory, Archives, Plan, Rename)
}

function ExpectedOutputFilenames(Version: string): string[] {
  return [...ChartSpecs.map(Spec => `${Spec.name}-${Version}.tgz`), HelmChartReleasePlanFilename].sort()
}

function AssertOutputInventory(OutputDirectory: string, Expected: string[], AllowEmpty: boolean): void {
  const Entries = Fs.readdirSync(OutputDirectory, { withFileTypes: true })
  if (AllowEmpty && Entries.length === 0) return
  const Actual = Entries.map(Entry => Entry.name).sort()
  if (Actual.join(',') !== Expected.join(',')) throw new Error('release output directory must be empty or contain exactly the complete expected inventory')
  for (const Entry of Entries) {
    const Metadata = Fs.lstatSync(Path.join(OutputDirectory, Entry.name))
    if (Metadata.isSymbolicLink() || !Metadata.isFile()) throw new Error(`release output inventory must contain only regular files: ${Entry.name}`)
  }
}

function ComputeExpectedRelease(Options: HelmChartReleaseOptions): { workspacePath: string, outputDirectory: string, revision: string, version: string, archives: Map<string, Buffer>, plan: HelmChartReleasePlan, planBytes: Buffer } {
  const WorkspacePath = ResolveWorkspace(Options.workspacePath)
  const OutputDirectory = ResolveOutputDirectory(Options.outputDirectory)
  AssertStructuralOxiBeltOrigin(WorkspacePath)
  const Version = ParseReleaseTag(ParseReleaseRef(Options.ref).tag).tag
  if (!Semver.test(Version)) throw new Error(`release version must be exact SemVer: ${Version}`)
  const Revision = ResolveRevision(WorkspacePath, Options.ref, Options.revision)
  const Epoch = CommitEpoch(WorkspacePath, Revision)
  const Archives = BuildArchives(WorkspacePath, Revision, Epoch, Version)
  const Plan = BuildPlan(WorkspacePath, Options.ref, Revision, Epoch, Version, Archives)
  const PlanBytes = Buffer.from(`${CanonicalJson(Plan)}\n`, 'utf8')
  if (PlanBytes.length > MaximumPlanBytes) throw new Error(`chart release plan exceeds ${MaximumPlanBytes} bytes`)
  return { workspacePath: WorkspacePath, outputDirectory: OutputDirectory, revision: Revision, version: Version, archives: Archives, plan: Plan, planBytes: PlanBytes }
}

function ReadReleaseOutput(OutputDirectory: string, Filename: string, MaximumBytes: number): Buffer {
  const OutputPath = Path.join(OutputDirectory, Filename)
  let Metadata: Fs.Stats
  try {
    Metadata = Fs.lstatSync(OutputPath)
  } catch (ErrorValue) {
    if ((ErrorValue as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(`release output is missing: ${Filename}`)
    }
    throw ErrorValue
  }
  if (Metadata.isSymbolicLink() || !Metadata.isFile()) throw new Error(`release output must be a regular file: ${Filename}`)
  if (Metadata.size > MaximumBytes) throw new Error(`release output exceeds ${MaximumBytes} bytes: ${Filename}`)
  return Fs.readFileSync(OutputPath)
}

export function PrepareHelmChartRelease(Options: HelmChartReleaseOptions): HelmChartReleasePlan {
  const Version = ParseReleaseTag(ParseReleaseRef(Options.ref).tag).tag
  const OutputDirectory = ResolveOutputDirectory(Options.outputDirectory)
  AssertOutputInventory(OutputDirectory, ExpectedOutputFilenames(Version), true)
  const Expected = ComputeExpectedRelease(Options)
  InstallOutputs(Expected.outputDirectory, Expected.archives, Expected.plan)
  return Expected.plan
}

export function VerifyHelmChartRelease(Options: HelmChartReleaseOptions): HelmChartReleasePlan {
  const Version = ParseReleaseTag(ParseReleaseRef(Options.ref).tag).tag
  const OutputDirectory = ResolveOutputDirectory(Options.outputDirectory)
  AssertOutputInventory(OutputDirectory, ExpectedOutputFilenames(Version), false)
  const ActualPlan = ReadReleaseOutput(OutputDirectory, HelmChartReleasePlanFilename, MaximumPlanBytes)
  const Expected = ComputeExpectedRelease(Options)
  if (!ActualPlan.equals(Expected.planBytes)) throw new Error('chart release plan is not byte-for-byte canonical expected content')
  for (const Chart of Expected.plan.charts) {
    const Actual = ReadReleaseOutput(OutputDirectory, Chart.filename, MaximumCompressedArchiveBytes)
    const Rebuilt = Expected.archives.get(Chart.name)
    if (Rebuilt === undefined || !Actual.equals(Rebuilt)) throw new Error(`chart archive is not byte-for-byte reproducible: ${Chart.filename}`)
    if (Sha256(Actual) !== Chart.archiveSha256) throw new Error(`chart archive digest differs from plan: ${Chart.filename}`)
  }
  return Expected.plan
}

function ParseCli(Argv: string[]): { mode: 'prepare' | 'verify', options: HelmChartReleaseOptions } {
  const Mode = Argv[2]
  if (Mode !== 'prepare' && Mode !== 'verify') throw new Error('usage: helm_chart_release.ts <prepare|verify> --workspace-path <path> --ref <ref> --revision <sha> --output-directory <path>')
  const Values: Partial<HelmChartReleaseOptions> = {}
  const Start = Argv[3] === '--' ? 4 : 3
  for (let Index = Start; Index < Argv.length; Index += 2) {
    const Option = Argv[Index]
    const Value = Argv[Index + 1]
    if (Value === undefined || !Option.startsWith('--')) throw new Error(`missing value for ${Option}`)
    if (Option === '--workspace-path') Values.workspacePath = Value
    else if (Option === '--ref') Values.ref = Value
    else if (Option === '--revision') Values.revision = Value
    else if (Option === '--output-directory') Values.outputDirectory = Value
    else throw new Error(`unknown option: ${Option}`)
  }
  for (const Key of ['workspacePath', 'ref', 'revision', 'outputDirectory'] as const) {
    if (Values[Key] === undefined || Values[Key] === '') throw new Error(`helm chart release requires --${Key.replace(/[A-Z]/g, Letter => `-${Letter.toLowerCase()}`)}`)
  }
  return { mode: Mode, options: Values as HelmChartReleaseOptions }
}

if (Process.argv[1] !== undefined && import.meta.url === pathToFileURL(Process.argv[1]).href) {
  try {
    const { mode, options } = ParseCli(Process.argv)
    const Plan = mode === 'prepare' ? PrepareHelmChartRelease(options) : VerifyHelmChartRelease(options)
    console.log(`${mode} Helm chart release ${Plan.releaseVersion} passed for ${Plan.sourceRevision}`)
  } catch (ErrorValue) {
    console.error(ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue))
    Process.exit(1)
  }
}
