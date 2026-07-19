import * as Fs from 'node:fs'
import * as Path from 'node:path'
import * as Process from 'node:process'
import { pathToFileURL } from 'node:url'
import * as Semver from 'semver'
import * as Toml from 'smol-toml'
import {
  AssertBuildTagMatchesRevision,
  AssertReleaseEventAllowed,
  BuildImageReleasePlan,
  ParseReleaseRef,
  ParseReleaseTag
} from './docker_image_release.js'

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
/* eslint-enable @typescript-eslint/naming-convention */

type TomlRecord = Record<string, unknown>

const ProductionPackageNames = [
  'oxibelt',
  'oxibelt-dataplane-strict',
  'oxibelt-control-http',
  'oxibelt-control-protocol',
  'oxibelt-deployment-diagnostics',
  'oxibelt-gateway-controller',
  'oxibelt-keysigner',
  'oxibelt-netport-switcher',
  'oxibeltctl'
]

function IsRecord(Value: unknown): Value is TomlRecord {
  return typeof Value === 'object' && Value !== null && !Array.isArray(Value)
}

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

function ParseToml(Content: string, FilePath: string): TomlRecord {
  try {
    const Parsed = Toml.parse(Content)
    if (!IsRecord(Parsed)) {
      throw new Error('top-level TOML value is not an object')
    }

    return Parsed
  } catch (ErrorValue) {
    throw new Error(`${FilePath} is not valid TOML: ${FormatError(ErrorValue)}`)
  }
}

function WorkspacePackageTable(Manifest: TomlRecord, ManifestPath: string): TomlRecord {
  const Workspace = Manifest.workspace
  if (!IsRecord(Workspace)) {
    throw new Error(`${ManifestPath} must contain a [workspace] table`)
  }
  const PackageData = Workspace.package

  if (!IsRecord(PackageData)) {
    throw new Error(`${ManifestPath} must contain a [workspace.package] table`)
  }

  return PackageData
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

function WorkspacePackageStringField(PackageData: TomlRecord, ManifestPath: string, FieldName: string): string {
  const Value = PackageData[FieldName]

  if (typeof Value !== 'string') {
    throw new Error(`${ManifestPath} [workspace.package] table must contain string ${FieldName}`)
  }

  return Value
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

function LockPackageTable(Lockfile: TomlRecord, LockfilePath: string, PackageName: string): TomlRecord {
  const Packages = Lockfile.package

  if (!Array.isArray(Packages)) {
    throw new Error(`${LockfilePath} must contain [[package]] entries`)
  }

  const Matches = Packages.filter((Entry): Entry is TomlRecord => {
    return IsRecord(Entry) && Entry.name === PackageName
  })

  if (Matches.length !== 1) {
    throw new Error(`${LockfilePath} must contain exactly one ${PackageName} package entry`)
  }

  return Matches[0]
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

function LockPackageVersion(Lockfile: TomlRecord, LockfilePath: string, PackageName: string): string {
  const PackageData = LockPackageTable(Lockfile, LockfilePath, PackageName)
  const Version = PackageData.version

  if (typeof Version !== 'string') {
    throw new Error(`${LockfilePath} ${PackageName} package block must contain a string version field`)
  }

  return Version
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

function IsStrictStableSemver(Version: string): boolean {
  const Parsed = Semver.parse(Version)

  return Parsed !== null &&
    Parsed.version === Version &&
    Parsed.prerelease.length === 0 &&
    Parsed.build.length === 0
}

function AssertCommittedState(
  ManifestPath: string,
  LockfilePath: string,
  PackageName: string
): string {
  const Manifest = ParseToml(Fs.readFileSync(ManifestPath, 'utf8'), ManifestPath)
  const Lockfile = ParseToml(Fs.readFileSync(LockfilePath, 'utf8'), LockfilePath)
  const ManifestPackage = WorkspacePackageTable(Manifest, ManifestPath)
  const ManifestVersion = WorkspacePackageStringField(ManifestPackage, ManifestPath, 'version')

  if (PackageName !== 'oxibelt') {
    throw new Error('release package name must be oxibelt')
  }

  if (!IsStrictStableSemver(ManifestVersion)) {
    throw new Error(`${ManifestPath} committed package version must use strict stable SemVer`)
  }

  for (const ProductionPackageName of ProductionPackageNames) {
    const LockVersion = LockPackageVersion(Lockfile, LockfilePath, ProductionPackageName)
    if (LockVersion !== ManifestVersion) {
      throw new Error(`${LockfilePath} ${ProductionPackageName} version must match ${ManifestPath}`)
    }
  }

  return ManifestVersion
}

export function RunVersioning(Options: VersioningOptions): VersioningResult {
  const WorkspacePath = ResolveWorkspacePath(Options.workspacePath)
  const ManifestPath = ResolveWorkspaceFile(WorkspacePath, Options.manifestPath, 'manifest path')
  const LockfilePath = ResolveWorkspaceFile(WorkspacePath, Options.lockfilePath, 'lockfile path')
  const CommittedVersion = AssertCommittedState(ManifestPath, LockfilePath, Options.packageName)

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

  Fs.writeFileSync(ManifestPath, NextManifest)
  Fs.writeFileSync(LockfilePath, NextLockfile)

  if (Options.imagePlanOutput !== undefined) {
    const Plan = BuildImageReleasePlan({
      releaseTag: ReleaseTag,
      revision: Options.revision,
      source: 'https://github.com/OxiBelt/OxiBelt'
    })
    Fs.writeFileSync(Options.imagePlanOutput, `${JSON.stringify(Plan, null, 2)}\n`)
  }

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
