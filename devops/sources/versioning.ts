import * as Fs from 'node:fs'
import * as Path from 'node:path'
import * as Process from 'node:process'
import { pathToFileURL } from 'node:url'
import {
  AssertBuildTagMatchesRevision,
  AssertReleaseEventAllowed,
  BuildImageReleasePlan,
  ParseReleaseRef,
  ParseReleaseTag
} from './docker_image_release.js'
import {
  AssertRepositoryVersionPolicy,
  ProductionPackageNames,
  RepositoryVersionPolicy
} from './repository_version_policy.js'

/* eslint-disable @typescript-eslint/naming-convention -- CLI options and release results use stable lower-camel-case keys. */
type CliParameters = {
  workspacePath?: string
  manifestPath?: string
  lockfilePath?: string
  packageName?: string
  ref?: string
  revision?: string
  eventName?: string
  releasePrerelease?: string
  releasePublish: boolean
  imagePlanOutput?: string
}

export type VersioningOptions = {
  workspacePath: string
  manifestPath: string
  lockfilePath: string
  packageName: string
  ref?: string
  revision?: string
  eventName?: string
  releasePrerelease?: boolean
  releasePublish: boolean
  imagePlanOutput?: string
}

export type VersioningResult = {
  mode: 'check' | 'release'
  packageName: string
  version: string
}

type PlannedWrite = {
  path: string
  content: string
}

type StagedWrite = PlannedWrite & {
  stagingDirectory: string
  stagedPath: string
  backupPath: string
  originalExists: boolean
  originalMoved: boolean
  installed: boolean
}
/* eslint-enable @typescript-eslint/naming-convention */

function FormatError(ErrorValue: unknown): string {
  if (ErrorValue instanceof Error) {
    return ErrorValue.message
  }

  return String(ErrorValue)
}

function ResolveWorkspacePath(WorkspacePath: string): string {
  const Resolved = Path.resolve(WorkspacePath)

  if (!Fs.existsSync(Resolved) || !Fs.statSync(Resolved).isDirectory()) {
    throw new Error(`workspace path is not a directory: ${WorkspacePath}`)
  }

  return Resolved
}

function ResolveWorkspaceFile(WorkspacePath: string, RelativePath: string, Label: string): string {
  if (Path.isAbsolute(RelativePath)) {
    throw new Error(`${Label} must be relative to the repository root: ${RelativePath}`)
  }

  const Resolved = Path.resolve(WorkspacePath, RelativePath)
  const Relative = Path.relative(WorkspacePath, Resolved)

  if (Relative === '' || Relative.startsWith('..') || Path.isAbsolute(Relative)) {
    throw new Error(`${Label} must stay inside the repository root: ${RelativePath}`)
  }

  if (!Fs.existsSync(Resolved) || !Fs.statSync(Resolved).isFile()) {
    throw new Error(`${Label} does not exist: ${RelativePath}`)
  }

  return Resolved
}

function WorkspacePackageSectionRange(Content: string, ManifestPath: string): [number, number] {
  const PackageMatch = /^\[workspace[.]package\]\s*$/m.exec(Content)

  if (PackageMatch === null || PackageMatch.index === undefined) {
    throw new Error(`${ManifestPath} must contain a [workspace.package] table`)
  }

  const Start = PackageMatch.index
  const AfterPackageHeader = Start + PackageMatch[0].length
  const NextTableMatch = /^\[.+\]\s*$/m.exec(Content.slice(AfterPackageHeader))
  const End = NextTableMatch === null ? Content.length : AfterPackageHeader + NextTableMatch.index

  return [Start, End]
}

function ReplaceWorkspacePackageVersion(Content: string, ManifestPath: string, Version: string): string {
  const [Start, End] = WorkspacePackageSectionRange(Content, ManifestPath)
  const Section = Content.slice(Start, End)
  const NextSection = Section.replace(/^[ \t]*version[ \t]*=[ \t]*"[^"]*"[ \t]*$/m, `version = "${Version}"`)

  if (NextSection === Section) {
    throw new Error(`${ManifestPath} [workspace.package] table must contain a version field`)
  }

  return `${Content.slice(0, Start)}${NextSection}${Content.slice(End)}`
}

function LockPackageBlockRanges(Content: string): Array<[number, number]> {
  const Ranges: Array<[number, number]> = []
  const Header = /^\[\[package\]\]\s*$/gm
  const Starts: number[] = []
  let Match: RegExpExecArray | null

  while ((Match = Header.exec(Content)) !== null) {
    Starts.push(Match.index)
  }

  for (let Index = 0; Index < Starts.length; Index += 1) {
    Ranges.push([Starts[Index], Starts[Index + 1] ?? Content.length])
  }

  return Ranges
}

function EscapeRegExp(Value: string): string {
  return Value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function LockPackageBlockRange(Content: string, LockfilePath: string, PackageName: string): [number, number] {
  const Ranges = LockPackageBlockRanges(Content)
  const MatchingRanges = Ranges.filter(([Start, End]) => {
    const Block = Content.slice(Start, End)
    return new RegExp(`^name\\s*=\\s*"${EscapeRegExp(PackageName)}"\\s*$`, 'm').test(Block)
  })

  if (MatchingRanges.length !== 1) {
    throw new Error(`${LockfilePath} must contain exactly one ${PackageName} package block`)
  }

  return MatchingRanges[0]
}

function UpdateLockPackageVersion(
  Content: string,
  LockfilePath: string,
  PackageName: string,
  Version: string
): string {
  const [Start, End] = LockPackageBlockRange(Content, LockfilePath, PackageName)
  const Block = Content.slice(Start, End)
  const NextBlock = Block.replace(/^[ \t]*version[ \t]*=[ \t]*"[^"]*"[ \t]*$/m, `version = "${Version}"`)

  if (NextBlock === Block) {
    throw new Error(`${LockfilePath} ${PackageName} package block must contain a version field`)
  }

  return `${Content.slice(0, Start)}${NextBlock}${Content.slice(End)}`
}

function UpdateProductionLockVersions(Content: string, LockfilePath: string, Version: string): string {
  return ProductionPackageNames.reduce(
    (Current, PackageName) => UpdateLockPackageVersion(Current, LockfilePath, PackageName, Version),
    Content
  )
}

function AssertCanonicalPolicyFile(
  WorkspacePath: string,
  ResolvedPath: string,
  ExpectedRelativePath: string,
  Label: string
): void {
  if (ResolvedPath !== Path.resolve(WorkspacePath, ExpectedRelativePath)) {
    throw new Error(`${Label} must be ${ExpectedRelativePath}`)
  }
}

function ResolveImagePlanOutput(
  Value: string | undefined,
  WorkspacePath: string,
  ManifestPath: string,
  LockfilePath: string
): string | undefined {
  if (Value === undefined) {
    return undefined
  }
  if (Value.trim() === '') {
    throw new Error('image plan output must not be empty')
  }

  const Resolved = Path.isAbsolute(Value)
    ? Path.resolve(Value)
    : Path.resolve(WorkspacePath, Value)
  const Parent = Path.dirname(Resolved)
  if (!Fs.existsSync(Parent) || !Fs.statSync(Parent).isDirectory()) {
    throw new Error(`image plan output directory does not exist: ${Parent}`)
  }

  const Canonical = Path.join(Fs.realpathSync(Parent), Path.basename(Resolved))
  const ProtectedPaths = [ManifestPath, LockfilePath].map(ProtectedPath => Fs.realpathSync(ProtectedPath))
  if (ProtectedPaths.includes(Canonical)) {
    throw new Error('image plan output must not overwrite Cargo.toml or Cargo.lock')
  }

  if (Fs.existsSync(Resolved)) {
    const Metadata = Fs.lstatSync(Resolved)
    if (Metadata.isSymbolicLink() || !Metadata.isFile()) {
      throw new Error(`image plan output must be a regular file: ${Value}`)
    }
    if (ProtectedPaths.includes(Fs.realpathSync(Resolved))) {
      throw new Error('image plan output must not overwrite Cargo.toml or Cargo.lock')
    }
  }
  return Resolved
}

function CleanupStagedWrites(Writes: StagedWrite[]): void {
  for (const Write of Writes) {
    Fs.rmSync(Write.stagingDirectory, { force: true, recursive: true })
  }
}

function ApplyPlannedWrites(Writes: PlannedWrite[]): void {
  const UniquePaths = new Set(Writes.map(Write => Write.path))
  if (UniquePaths.size !== Writes.length) {
    throw new Error('release outputs must use distinct paths')
  }

  const Staged: StagedWrite[] = []
  try {
    for (const Write of Writes) {
      const OriginalExists = Fs.existsSync(Write.path)
      if (OriginalExists) {
        const Metadata = Fs.lstatSync(Write.path)
        if (Metadata.isSymbolicLink() || !Metadata.isFile()) {
          throw new Error(`release output must be a regular file: ${Write.path}`)
        }
      }

      const StagingDirectory = Fs.mkdtempSync(
        Path.join(Path.dirname(Write.path), '.oxibelt-versioning-')
      )
      const StagedPath = Path.join(StagingDirectory, 'next')
      const BackupPath = Path.join(StagingDirectory, 'original')
      Staged.push({
        ...Write,
        stagingDirectory: StagingDirectory,
        stagedPath: StagedPath,
        backupPath: BackupPath,
        originalExists: OriginalExists,
        originalMoved: false,
        installed: false
      })
      Fs.writeFileSync(StagedPath, Write.content, {
        flag: 'wx',
        mode: OriginalExists ? Fs.statSync(Write.path).mode : 0o600
      })
    }
  } catch (ErrorValue) {
    CleanupStagedWrites(Staged)
    throw ErrorValue
  }

  try {
    for (const Write of Staged) {
      if (Write.originalExists) {
        Fs.renameSync(Write.path, Write.backupPath)
        Write.originalMoved = true
      }
      Fs.renameSync(Write.stagedPath, Write.path)
      Write.installed = true
    }
  } catch (ErrorValue) {
    const RollbackErrors: string[] = []
    for (const Write of [...Staged].reverse()) {
      try {
        if (Write.installed && Fs.existsSync(Write.path)) {
          Fs.unlinkSync(Write.path)
        }
        if (Write.originalMoved && Fs.existsSync(Write.backupPath)) {
          Fs.renameSync(Write.backupPath, Write.path)
        }
      } catch (RollbackError) {
        RollbackErrors.push(FormatError(RollbackError))
      }
    }
    if (RollbackErrors.length === 0) {
      CleanupStagedWrites(Staged)
    }
    const Suffix = RollbackErrors.length === 0
      ? ''
      : `; rollback also failed and staging backups were retained: ${RollbackErrors.join('; ')}`
    throw new Error(`release output commit failed: ${FormatError(ErrorValue)}${Suffix}`)
  }

  CleanupStagedWrites(Staged)
}

export function RunVersioning(Options: VersioningOptions): VersioningResult {
  const WorkspacePath = ResolveWorkspacePath(Options.workspacePath)
  const ManifestPath = ResolveWorkspaceFile(WorkspacePath, Options.manifestPath, 'manifest path')
  const LockfilePath = ResolveWorkspaceFile(WorkspacePath, Options.lockfilePath, 'lockfile path')
  AssertCanonicalPolicyFile(
    WorkspacePath,
    ManifestPath,
    RepositoryVersionPolicy.manifestPath,
    'manifest path'
  )
  AssertCanonicalPolicyFile(
    WorkspacePath,
    LockfilePath,
    RepositoryVersionPolicy.lockfilePath,
    'lockfile path'
  )
  if (Options.packageName !== 'oxibelt') {
    throw new Error('release package name must be oxibelt')
  }
  const CommittedVersion = AssertRepositoryVersionPolicy(WorkspacePath)

  if (!Options.releasePublish) {
    return {
      mode: 'check',
      packageName: Options.packageName,
      version: CommittedVersion
    }
  }

  if (Options.ref === undefined) {
    throw new Error('release mode requires --ref')
  }

  if (Options.revision === undefined) {
    throw new Error('release mode requires --revision')
  }

  const ReleaseTag = ParseReleaseRef(Options.ref)
  AssertBuildTagMatchesRevision(ReleaseTag, Options.revision)
  AssertReleaseEventAllowed(ReleaseTag, Options.eventName, Options.releasePrerelease)

  const Version = ReleaseTag.tag
  const NextManifest = ReplaceWorkspacePackageVersion(
    Fs.readFileSync(ManifestPath, 'utf8'),
    ManifestPath,
    Version
  )
  const NextLockfile = UpdateProductionLockVersions(
    Fs.readFileSync(LockfilePath, 'utf8'),
    LockfilePath,
    Version
  )
  const ImagePlanOutput = ResolveImagePlanOutput(
    Options.imagePlanOutput,
    WorkspacePath,
    ManifestPath,
    LockfilePath
  )
  const NextImagePlan = ImagePlanOutput === undefined
    ? undefined
    : `${JSON.stringify(BuildImageReleasePlan({
        releaseTag: ReleaseTag,
        revision: Options.revision,
        source: 'https://github.com/OxiBelt/OxiBelt'
      }), null, 2)}\n`

  const Writes: PlannedWrite[] = [
    { path: ManifestPath, content: NextManifest },
    { path: LockfilePath, content: NextLockfile }
  ]
  if (ImagePlanOutput !== undefined && NextImagePlan !== undefined) {
    Writes.push({ path: ImagePlanOutput, content: NextImagePlan })
  }
  ApplyPlannedWrites(Writes)

  return {
    mode: 'release',
    packageName: Options.packageName,
    version: Version
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
  const Parameters: CliParameters = {
    releasePublish: false
  }

  for (let Index = 2; Index < Argv.length; Index += 1) {
    const Option = Argv[Index]

    if (Option === '--release-publish') {
      Parameters.releasePublish = true
      continue
    }

    const Value = Argv[Index + 1]

    if (!Option.startsWith('--')) {
      throw new Error(`unexpected argument: ${Option}`)
    }

    if (Value === undefined || Value.startsWith('--')) {
      throw new Error(`missing value for ${Option}`)
    }

    Index += 1

    switch (Option) {
      case '--workspace-path':
        Parameters.workspacePath = Value
        break
      case '--manifest-path':
        Parameters.manifestPath = Value
        break
      case '--lockfile-path':
        Parameters.lockfilePath = Value
        break
      case '--package-name':
        Parameters.packageName = Value
        break
      case '--ref':
        Parameters.ref = Value
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
      case '--image-plan-output':
        Parameters.imagePlanOutput = Value
        break
      default:
        throw new Error(`unknown option: ${Option}`)
    }
  }

  return Parameters
}

function RequireParameter(Value: string | undefined, Name: string): string {
  if (Value === undefined || Value === '') {
    throw new Error(`versioning requires ${Name}`)
  }

  return Value
}

function RunCli(): void {
  const Parameters = ParseCliParameters(Process.argv)
  const Result = RunVersioning({
    workspacePath: RequireParameter(Parameters.workspacePath, '--workspace-path'),
    manifestPath: RequireParameter(Parameters.manifestPath, '--manifest-path'),
    lockfilePath: RequireParameter(Parameters.lockfilePath, '--lockfile-path'),
    packageName: RequireParameter(Parameters.packageName, '--package-name'),
    ref: Parameters.ref,
    revision: Parameters.revision,
    eventName: Parameters.eventName,
    releasePrerelease: ParseBool(Parameters.releasePrerelease),
    releasePublish: Parameters.releasePublish,
    imagePlanOutput: Parameters.imagePlanOutput
  })

  ParseReleaseTag(Result.version)
  console.log(`${Result.mode} versioning passed for ${Result.packageName} ${Result.version}`)
}

if (Process.argv[1] !== undefined && import.meta.url === pathToFileURL(Process.argv[1]).href) {
  try {
    RunCli()
  } catch (ErrorValue) {
    console.error(FormatError(ErrorValue))
    Process.exit(1)
  }
}
