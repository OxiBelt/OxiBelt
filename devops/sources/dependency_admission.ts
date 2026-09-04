import * as Fs from 'node:fs'
import * as Path from 'node:path'
import * as Process from 'node:process'
import { pathToFileURL } from 'node:url'
import * as Semver from 'semver'

/* oxlint-disable oxibelt/pascal-case -- Policy, manifest, lockfile, and report keys are stable external interfaces. */
type JsonRecord = Record<string, unknown>

type CliParameters = {
  workspacePath?: string
  policyPath?: string
  licenseReportPath?: string
  auditReportPath?: string
}

export type DependencyAdmissionOptions = {
  workspacePath: string
  policyPath: string
  licenseReportPath?: string
  auditReportPath?: string
  now?: Date
}

export type DependencyAdmissionResult = {
  manifests: number
  lockedPackages: number
  lifecycleScripts: number
  licenses?: number
}

type LifecycleScript = {
  package: string
  version: string
  rationale: string
}

type AuditException = {
  id: string
  package: string
  versions: string
  rationale: string
  owner: string
  issue: string
  reviewedOn: string
  expiresOn: string
}

type NodePolicy = {
  allowedRegistries: string[]
  allowedLicenses: string[]
  lifecycleScripts: LifecycleScript[]
  auditExceptions: AuditException[]
}

type ManifestData = {
  path: string
  importer: string
  packageName: string
  dependencies: Map<string, string>
}

type LockDependency = {
  specifier: string
  version: string
}
/* oxlint-enable oxibelt/pascal-case */

const DependencyFields = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const
const KnownNodePolicyFields = ['allowedRegistries', 'allowedLicenses', 'lifecycleScripts', 'auditExceptions']
const KnownLifecycleFields = ['package', 'version', 'rationale']
const KnownAuditExceptionFields = [
  'id',
  'package',
  'versions',
  'rationale',
  'owner',
  'issue',
  'reviewedOn',
  'expiresOn'
]
const RequiredWorkspaceSettings = new Map<string, string>([
  ['registry', 'https://registry.npmjs.org/'],
  ['blockExoticSubdeps', 'true'],
  ['trustLockfile', 'false'],
  ['strictDepBuilds', 'true'],
  ['minimumReleaseAge', '1440']
])
const MaxReportBytes = 10 * 1024 * 1024
const MaxAuditErrorCodeCharacters = 64
const MaxAuditErrorMessageCharacters = 512
const MaxExceptionDays = 90

function IsRecord(Value: unknown): Value is JsonRecord {
  return typeof Value === 'object' && Value !== null && !Array.isArray(Value)
}

function FormatError(ErrorValue: unknown): string {
  return ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)
}

function BoundedInlineText(Value: string, MaxCharacters: number): string {
  const Sanitized = Value.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ')
  const Characters = [...Sanitized]
  if (Characters.length <= MaxCharacters) {
    return Sanitized
  }

  return `${Characters.slice(0, MaxCharacters - 3).join('')}...`
}

function RejectAuditErrorEnvelope(ErrorValue: unknown): never {
  if (!IsRecord(ErrorValue)) {
    throw new Error('pnpm audit report contains a malformed error envelope')
  }
  const Code = ErrorValue.code
  const Message = ErrorValue.message
  if (
    !((typeof Code === 'string' && Code.trim().length > 0) || (typeof Code === 'number' && Number.isFinite(Code))) ||
    typeof Message !== 'string' ||
    Message.trim().length === 0
  ) {
    throw new Error('pnpm audit report contains a malformed error envelope')
  }
  const SafeCode = BoundedInlineText(String(Code), MaxAuditErrorCodeCharacters)
  const SafeMessage = BoundedInlineText(Message, MaxAuditErrorMessageCharacters)
  if (SafeCode.trim().length === 0 || SafeMessage.trim().length === 0) {
    throw new Error('pnpm audit report contains a malformed error envelope')
  }

  throw new Error(`pnpm audit command returned an error report (code ${SafeCode}): ${SafeMessage}`)
}

function ReadBoundedFile(FilePath: string, Label: string): string {
  const Stats = Fs.statSync(FilePath)
  if (!Stats.isFile()) {
    throw new Error(`${Label} is not a regular file: ${FilePath}`)
  }
  if (Stats.size > MaxReportBytes) {
    throw new Error(`${Label} exceeds the ${MaxReportBytes}-byte limit: ${FilePath}`)
  }

  return Fs.readFileSync(FilePath, 'utf8')
}

function ParseJson(Content: string, Label: string): unknown {
  try {
    return JSON.parse(Content) as unknown
  } catch (ErrorValue) {
    throw new Error(`${Label} is not valid JSON: ${FormatError(ErrorValue)}`)
  }
}

function ResolveWorkspace(WorkspacePath: string): string {
  const Resolved = Fs.realpathSync(Path.resolve(WorkspacePath))
  if (!Fs.statSync(Resolved).isDirectory()) {
    throw new Error(`workspace path is not a directory: ${WorkspacePath}`)
  }

  return Resolved
}

function ResolveWorkspaceFile(Workspace: string, RelativePath: string, Label: string): string {
  if (Path.isAbsolute(RelativePath)) {
    throw new Error(`${Label} must be relative to the repository root: ${RelativePath}`)
  }
  const Resolved = Path.resolve(Workspace, RelativePath)
  const Relative = Path.relative(Workspace, Resolved)
  if (Relative === '' || Relative.startsWith('..') || Path.isAbsolute(Relative)) {
    throw new Error(`${Label} must stay inside the repository root: ${RelativePath}`)
  }
  if (!Fs.existsSync(Resolved) || !Fs.statSync(Resolved).isFile()) {
    throw new Error(`${Label} does not exist: ${RelativePath}`)
  }

  return Resolved
}

function AssertKnownFields(Value: JsonRecord, KnownFields: string[], Label: string): void {
  const Unknown = Object.keys(Value).filter(Key => !KnownFields.includes(Key)).sort()
  if (Unknown.length > 0) {
    throw new Error(`${Label} contains unknown fields: ${Unknown.join(', ')}`)
  }
}

function RequiredString(Value: JsonRecord, Field: string, Label: string): string {
  const FieldValue = Value[Field]
  if (typeof FieldValue !== 'string' || FieldValue.trim() === '') {
    throw new Error(`${Label}.${Field} must be a non-empty string`)
  }

  return FieldValue
}

function UniqueStringArray(Value: unknown, Label: string): string[] {
  if (!Array.isArray(Value) || Value.length === 0 || Value.some(Item => typeof Item !== 'string' || Item === '')) {
    throw new Error(`${Label} must be a non-empty array of strings`)
  }
  const Strings = Value as string[]
  if (new Set(Strings).size !== Strings.length) {
    throw new Error(`${Label} must not contain duplicates`)
  }

  return Strings
}

function ParseIsoDate(Value: string, Label: string): Date {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(Value)) {
    throw new Error(`${Label} must use YYYY-MM-DD`)
  }
  const Parsed = new Date(`${Value}T00:00:00.000Z`)
  if (Number.isNaN(Parsed.valueOf()) || Parsed.toISOString().slice(0, 10) !== Value) {
    throw new Error(`${Label} is not a valid date`)
  }

  return Parsed
}

function ValidateNodePolicy(PolicyDocument: unknown, Now: Date): NodePolicy {
  if (!IsRecord(PolicyDocument) || !IsRecord(PolicyDocument.node)) {
    throw new Error('dependency policy must contain a node object')
  }
  const NodeValue = PolicyDocument.node
  AssertKnownFields(NodeValue, KnownNodePolicyFields, 'dependency policy node object')
  const AllowedRegistries = UniqueStringArray(NodeValue.allowedRegistries, 'node.allowedRegistries')
  const AllowedLicenses = UniqueStringArray(NodeValue.allowedLicenses, 'node.allowedLicenses')
  if (!Array.isArray(NodeValue.lifecycleScripts)) {
    throw new Error('node.lifecycleScripts must be an array')
  }
  if (!Array.isArray(NodeValue.auditExceptions)) {
    throw new Error('node.auditExceptions must be an array')
  }

  const LifecycleScripts = NodeValue.lifecycleScripts.map((Entry, Index): LifecycleScript => {
    if (!IsRecord(Entry)) {
      throw new Error(`node.lifecycleScripts[${Index}] must be an object`)
    }
    AssertKnownFields(Entry, KnownLifecycleFields, `node.lifecycleScripts[${Index}]`)
    const PackageName = RequiredString(Entry, 'package', `node.lifecycleScripts[${Index}]`)
    const Version = RequiredString(Entry, 'version', `node.lifecycleScripts[${Index}]`)
    const Rationale = RequiredString(Entry, 'rationale', `node.lifecycleScripts[${Index}]`)
    if (Semver.valid(Version) === null) {
      throw new Error(`node.lifecycleScripts[${Index}].version must be an exact semantic version`)
    }
    if (Rationale.length < 20) {
      throw new Error(`node.lifecycleScripts[${Index}].rationale must contain at least 20 characters`)
    }

    return { package: PackageName, version: Version, rationale: Rationale }
  })

  const AuditExceptions = NodeValue.auditExceptions.map((Entry, Index): AuditException => {
    if (!IsRecord(Entry)) {
      throw new Error(`node.auditExceptions[${Index}] must be an object`)
    }
    AssertKnownFields(Entry, KnownAuditExceptionFields, `node.auditExceptions[${Index}]`)
    const Exception = Object.fromEntries(
      KnownAuditExceptionFields.map(Field => [Field, RequiredString(Entry, Field, `node.auditExceptions[${Index}]`)])
    ) as AuditException
    if (!/^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/i.test(Exception.id)) {
      throw new Error(`node.auditExceptions[${Index}].id must be a GHSA identifier`)
    }
    if (!Exception.owner.startsWith('@') || Exception.owner.length < 2) {
      throw new Error(`node.auditExceptions[${Index}].owner must be a GitHub owner beginning with @`)
    }
    if (!/^https:\/\/github[.]com\/.+\/issues\/\d+$/.test(Exception.issue)) {
      throw new Error(`node.auditExceptions[${Index}].issue must be a GitHub issue URL`)
    }
    const ReviewedOn = ParseIsoDate(Exception.reviewedOn, `node.auditExceptions[${Index}].reviewedOn`)
    const ExpiresOn = ParseIsoDate(Exception.expiresOn, `node.auditExceptions[${Index}].expiresOn`)
    const DurationDays = (ExpiresOn.valueOf() - ReviewedOn.valueOf()) / 86_400_000
    if (DurationDays <= 0 || DurationDays > MaxExceptionDays) {
      throw new Error(`node.auditExceptions[${Index}] must expire within ${MaxExceptionDays} days of review`)
    }
    if (ExpiresOn.valueOf() < Date.UTC(Now.getUTCFullYear(), Now.getUTCMonth(), Now.getUTCDate())) {
      throw new Error(`node.auditExceptions[${Index}] expired on ${Exception.expiresOn}`)
    }

    return Exception
  })

  for (const [Label, Values] of [
    ['node.lifecycleScripts', LifecycleScripts.map(Entry => `${Entry.package}@${Entry.version}`)],
    ['node.auditExceptions', AuditExceptions.map(Entry => Entry.id.toUpperCase())]
  ] as const) {
    if (new Set(Values).size !== Values.length) {
      throw new Error(`${Label} must not contain duplicate identities`)
    }
  }

  return {
    allowedRegistries: AllowedRegistries,
    allowedLicenses: AllowedLicenses,
    lifecycleScripts: LifecycleScripts,
    auditExceptions: AuditExceptions
  }
}

function ParseManifest(FilePath: string, Importer: string): ManifestData {
  const Parsed = ParseJson(ReadBoundedFile(FilePath, 'package manifest'), FilePath)
  if (!IsRecord(Parsed)) {
    throw new Error(`${FilePath} must contain a JSON object`)
  }
  const PackageName = RequiredString(Parsed, 'name', FilePath)
  const Dependencies = new Map<string, string>()
  for (const Field of DependencyFields) {
    const Section = Parsed[Field]
    if (Section === undefined) {
      continue
    }
    if (!IsRecord(Section)) {
      throw new Error(`${FilePath}.${Field} must be an object`)
    }
    for (const [Name, Specifier] of Object.entries(Section)) {
      if (typeof Specifier !== 'string' || Specifier === '') {
        throw new Error(`${FilePath}.${Field}.${Name} must be a non-empty string`)
      }
      if (Dependencies.has(Name)) {
        throw new Error(`${FilePath} declares ${Name} in more than one dependency section`)
      }
      Dependencies.set(Name, Specifier)
    }
  }

  return { path: FilePath, importer: Importer, packageName: PackageName, dependencies: Dependencies }
}

function ExpandWorkspaceManifests(Workspace: string, RootManifest: JsonRecord): ManifestData[] {
  const WorkspacePatterns = RootManifest.workspaces
  if (!Array.isArray(WorkspacePatterns) || WorkspacePatterns.length === 0 || WorkspacePatterns.some(Item => typeof Item !== 'string')) {
    throw new Error('root package.json workspaces must be a non-empty array of strings')
  }
  const Patterns = WorkspacePatterns as string[]
  if (new Set(Patterns).size !== Patterns.length) {
    throw new Error('root package.json workspaces must not contain duplicates')
  }

  const Importers = new Set<string>()
  for (const Pattern of Patterns) {
    if (Pattern.endsWith('/*')) {
      const ParentRelative = Pattern.slice(0, -2)
      const Parent = Path.resolve(Workspace, ParentRelative)
      const Relative = Path.relative(Workspace, Parent)
      if (Relative.startsWith('..') || Path.isAbsolute(Relative) || !Fs.statSync(Parent).isDirectory()) {
        throw new Error(`workspace pattern is not a repository directory: ${Pattern}`)
      }
      for (const Entry of Fs.readdirSync(Parent, { withFileTypes: true })) {
        const Importer = Path.posix.join(ParentRelative.replaceAll(Path.sep, '/'), Entry.name)
        if (Entry.isDirectory() && Fs.existsSync(Path.join(Parent, Entry.name, 'package.json'))) {
          Importers.add(Importer)
        }
      }
    } else if (!Pattern.includes('*')) {
      const ManifestPath = Path.resolve(Workspace, Pattern, 'package.json')
      const Relative = Path.relative(Workspace, ManifestPath)
      if (Relative.startsWith('..') || Path.isAbsolute(Relative) || !Fs.existsSync(ManifestPath)) {
        throw new Error(`workspace package manifest does not exist: ${Pattern}/package.json`)
      }
      Importers.add(Pattern.replaceAll(Path.sep, '/'))
    } else {
      throw new Error(`unsupported workspace glob; only terminal /* is allowed: ${Pattern}`)
    }
  }

  const RootPath = Path.join(Workspace, 'package.json')
  const Manifests = [ParseManifest(RootPath, '.')]
  for (const Importer of [...Importers].sort()) {
    Manifests.push(ParseManifest(Path.join(Workspace, Importer, 'package.json'), Importer))
  }

  return Manifests
}

function ParseYamlScalar(Value: string, Label: string): string {
  if (Value.startsWith('"')) {
    const Parsed = ParseJson(Value, Label)
    if (typeof Parsed !== 'string') {
      throw new Error(`${Label} must be a string scalar`)
    }
    return Parsed
  }
  if (Value.startsWith('\'') && Value.endsWith('\'')) {
    return Value.slice(1, -1).replaceAll('\'\'', '\'')
  }
  if (Value === '' || /[\s#{}[\],]/.test(Value)) {
    throw new Error(`${Label} contains an unsupported YAML scalar: ${Value}`)
  }

  return Value
}

function ParseLockImporters(Content: string): Map<string, Map<string, LockDependency>> {
  const Lines = Content.split(/\r?\n/)
  const Start = Lines.indexOf('importers:')
  const End = Lines.indexOf('packages:')
  if (Start < 0 || End <= Start) {
    throw new Error('pnpm-lock.yaml must contain importers before packages')
  }
  const Importers = new Map<string, Map<string, LockDependency>>()
  let Importer: string | undefined
  let DependencyGroup: string | undefined
  let DependencyName: string | undefined
  let Specifier: string | undefined
  let Version: string | undefined

  const FinishDependency = (): void => {
    if (DependencyName === undefined) {
      return
    }
    if (Importer === undefined || DependencyGroup === undefined || Specifier === undefined || Version === undefined) {
      throw new Error(`pnpm-lock.yaml importer dependency ${DependencyName} is incomplete`)
    }
    const Dependencies = Importers.get(Importer)
    if (Dependencies === undefined || Dependencies.has(DependencyName)) {
      throw new Error(`pnpm-lock.yaml importer ${Importer} repeats dependency ${DependencyName}`)
    }
    Dependencies.set(DependencyName, { specifier: Specifier, version: Version })
    DependencyName = undefined
    Specifier = undefined
    Version = undefined
  }

  for (const Line of Lines.slice(Start + 1, End)) {
    const ImporterMatch = /^ {2}([^ ].*?):(?: \{\})?$/.exec(Line)
    if (ImporterMatch !== null) {
      FinishDependency()
      Importer = ParseYamlScalar(ImporterMatch[1], 'pnpm-lock.yaml importer')
      if (Importers.has(Importer)) {
        throw new Error(`pnpm-lock.yaml repeats importer ${Importer}`)
      }
      Importers.set(Importer, new Map())
      DependencyGroup = undefined
      continue
    }
    const GroupMatch = /^ {4}(dependencies|devDependencies|optionalDependencies|peerDependencies):$/.exec(Line)
    if (GroupMatch !== null) {
      FinishDependency()
      DependencyGroup = GroupMatch[1]
      continue
    }
    const DependencyMatch = /^ {6}([^ ].*):$/.exec(Line)
    if (DependencyMatch !== null) {
      FinishDependency()
      if (Importer === undefined || DependencyGroup === undefined) {
        throw new Error('pnpm-lock.yaml dependency appears outside an importer dependency group')
      }
      DependencyName = ParseYamlScalar(DependencyMatch[1], 'pnpm-lock.yaml dependency name')
      continue
    }
    const SpecifierMatch = /^ {8}specifier: (.+)$/.exec(Line)
    if (SpecifierMatch !== null) {
      Specifier = ParseYamlScalar(SpecifierMatch[1], 'pnpm-lock.yaml specifier')
      continue
    }
    const VersionMatch = /^ {8}version: (.+)$/.exec(Line)
    if (VersionMatch !== null) {
      Version = ParseYamlScalar(VersionMatch[1], 'pnpm-lock.yaml version')
    }
  }
  FinishDependency()

  return Importers
}

function ValidateManifestSpecifiers(Manifests: ManifestData[]): Set<string> {
  const WorkspaceNames = new Set(Manifests.map(Manifest => Manifest.packageName))
  for (const Manifest of Manifests) {
    for (const [Name, Specifier] of Manifest.dependencies) {
      if (Specifier.startsWith('workspace:')) {
        if (!WorkspaceNames.has(Name) || !/^workspace:(?:\*|\^|~|\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/.test(Specifier)) {
          throw new Error(`${Manifest.path} has invalid internal workspace dependency ${Name}: ${Specifier}`)
        }
      } else if (Semver.valid(Specifier) === null) {
        throw new Error(`${Manifest.path} must pin external dependency ${Name} to an exact semantic version: ${Specifier}`)
      }
    }
  }

  return WorkspaceNames
}

function ValidateLockImporters(Content: string, Manifests: ManifestData[]): void {
  const Importers = ParseLockImporters(Content)
  if (Importers.size !== Manifests.length) {
    throw new Error(`pnpm-lock.yaml has ${Importers.size} importers but ${Manifests.length} package manifests were discovered`)
  }
  for (const Manifest of Manifests) {
    const Locked = Importers.get(Manifest.importer)
    if (Locked === undefined) {
      throw new Error(`pnpm-lock.yaml is missing importer ${Manifest.importer}`)
    }
    if (Locked.size !== Manifest.dependencies.size) {
      throw new Error(`pnpm-lock.yaml importer ${Manifest.importer} does not match its package manifest dependency count`)
    }
    for (const [Name, Specifier] of Manifest.dependencies) {
      const Entry = Locked.get(Name)
      if (Entry === undefined || Entry.specifier !== Specifier) {
        throw new Error(`pnpm-lock.yaml importer ${Manifest.importer} does not exactly pin ${Name} to ${Specifier}`)
      }
      if (!Specifier.startsWith('workspace:') && Entry.version !== Specifier && !Entry.version.startsWith(`${Specifier}(`)) {
        throw new Error(`pnpm-lock.yaml importer ${Manifest.importer} resolved ${Name} outside exact version ${Specifier}`)
      }
    }
  }
}

function ValidateLockPackages(Content: string): Set<string> {
  const Lines = Content.split(/\r?\n/)
  const Start = Lines.indexOf('packages:')
  const End = Lines.indexOf('snapshots:')
  if (Start < 0 || End <= Start) {
    throw new Error('pnpm-lock.yaml must contain packages before snapshots')
  }
  const Packages = new Set<string>()
  let PackageIdentity: string | undefined
  let ResolutionCount = 0

  const FinishPackage = (): void => {
    if (PackageIdentity === undefined) {
      return
    }
    if (ResolutionCount !== 1) {
      throw new Error(`pnpm-lock.yaml package ${PackageIdentity} must contain exactly one integrity-only resolution`)
    }
  }

  for (const Line of Lines.slice(Start + 1, End)) {
    const Header = /^ {2}([^ ].*):$/.exec(Line)
    if (Header !== null) {
      FinishPackage()
      PackageIdentity = ParseYamlScalar(Header[1], 'pnpm-lock.yaml package identity')
      const VersionSeparator = PackageIdentity.lastIndexOf('@')
      const PackageName = PackageIdentity.slice(0, VersionSeparator)
      const Version = PackageIdentity.slice(VersionSeparator + 1)
      if (PackageName === '' || Semver.valid(Version) === null) {
        throw new Error(`pnpm-lock.yaml package is not an exact registry identity: ${PackageIdentity}`)
      }
      if (Packages.has(PackageIdentity)) {
        throw new Error(`pnpm-lock.yaml repeats package ${PackageIdentity}`)
      }
      Packages.add(PackageIdentity)
      ResolutionCount = 0
      continue
    }
    const Resolution = /^ {4}resolution: \{integrity: (sha512-[A-Za-z0-9+/]+={0,2})\}$/.exec(Line)
    if (Resolution !== null) {
      if (PackageIdentity === undefined) {
        throw new Error('pnpm-lock.yaml resolution appears before a package')
      }
      const Encoded = Resolution[1].slice('sha512-'.length)
      const Digest = Buffer.from(Encoded, 'base64')
      if (Digest.length !== 64 || Digest.toString('base64') !== Encoded) {
        throw new Error(`pnpm-lock.yaml package ${PackageIdentity} has a malformed SHA-512 integrity`)
      }
      ResolutionCount += 1
    } else if (/^ {4}resolution:/.test(Line)) {
      throw new Error(`pnpm-lock.yaml package ${PackageIdentity ?? '<unknown>'} has a non-registry or non-integrity resolution`)
    }
  }
  FinishPackage()
  if (Packages.size === 0) {
    throw new Error('pnpm-lock.yaml packages section must not be empty')
  }

  return Packages
}

function ParseTopLevelScalar(Lines: string[], Name: string): string {
  const Matches = Lines.flatMap(Line => {
    const Match = new RegExp(`^${Name}: (.+)$`).exec(Line)
    return Match === null ? [] : [ParseYamlScalar(Match[1], `pnpm-workspace.yaml ${Name}`)]
  })
  if (Matches.length !== 1) {
    throw new Error(`pnpm-workspace.yaml must contain exactly one top-level ${Name}`)
  }

  return Matches[0]
}

function ParseYamlStringList(Lines: string[], Header: string, Indent: number): string[] {
  const HeaderLine = `${' '.repeat(Indent)}${Header}:`
  const Start = Lines.indexOf(HeaderLine)
  if (Start < 0) {
    return []
  }
  const ItemIndent = ' '.repeat(Indent + 2)
  const Values: string[] = []
  for (const Line of Lines.slice(Start + 1)) {
    if (Line.trim() === '') {
      continue
    }
    if (!Line.startsWith(ItemIndent)) {
      break
    }
    const Match = new RegExp(`^${ItemIndent}- (.+)$`).exec(Line)
    if (Match !== null) {
      Values.push(ParseYamlScalar(Match[1], `pnpm-workspace.yaml ${Header} entry`))
    }
  }

  return Values
}

function ParseAllowBuilds(Lines: string[]): Set<string> {
  const Start = Lines.indexOf('allowBuilds:')
  if (Start < 0) {
    throw new Error('pnpm-workspace.yaml must contain allowBuilds')
  }
  const Allowed = new Set<string>()
  for (const Line of Lines.slice(Start + 1)) {
    if (Line.trim() === '') {
      continue
    }
    if (!Line.startsWith('  ')) {
      break
    }
    const Match = /^ {2}([^ ].*): true$/.exec(Line)
    if (Match === null) {
      throw new Error(`pnpm-workspace.yaml allowBuilds contains an unsupported entry: ${Line.trim()}`)
    }
    const Identity = ParseYamlScalar(Match[1], 'pnpm-workspace.yaml allowBuilds identity')
    if (Allowed.has(Identity)) {
      throw new Error(`pnpm-workspace.yaml repeats allowBuilds identity ${Identity}`)
    }
    Allowed.add(Identity)
  }

  return Allowed
}

function ParseAuditIgnores(Lines: string[]): string[] {
  const AuditHeaders = Lines.flatMap((Line, Index) => Line === 'auditConfig:' ? [Index] : [])
  if (AuditHeaders.length !== 1) {
    throw new Error('pnpm-workspace.yaml must contain exactly one auditConfig object')
  }
  const Start = AuditHeaders[0]
  const AuditLines: string[] = []
  for (const Line of Lines.slice(Start + 1)) {
    if (Line.trim() === '') {
      continue
    }
    if (!Line.startsWith('  ')) {
      break
    }
    AuditLines.push(Line)
  }
  if (AuditLines.length === 1 && AuditLines[0] === '  ignoreGhsas: []') {
    return []
  }
  if (!AuditLines.includes('  ignoreGhsas:')) {
    throw new Error('pnpm-workspace.yaml auditConfig must explicitly declare ignoreGhsas')
  }
  const Values = ParseYamlStringList(Lines, 'ignoreGhsas', 2)
  if (Values.length === 0) {
    throw new Error('pnpm-workspace.yaml auditConfig.ignoreGhsas must use [] when empty')
  }

  return Values
}

function ValidateWorkspaceConfig(Content: string, RootManifest: JsonRecord, Policy: NodePolicy): void {
  const Lines = Content.split(/\r?\n/)
  for (const [Name, Expected] of RequiredWorkspaceSettings) {
    const Actual = ParseTopLevelScalar(Lines, Name)
    if (Actual !== Expected || (Name === 'registry' && !Policy.allowedRegistries.includes(Actual))) {
      throw new Error(`pnpm-workspace.yaml ${Name} must be ${Expected}`)
    }
  }
  if (/^(?:dangerouslyAllowAllBuilds|onlyBuiltDependencies|ignoredBuiltDependencies):/m.test(Content)) {
    throw new Error('pnpm-workspace.yaml contains a forbidden lifecycle-script bypass setting')
  }
  const ManifestWorkspaces = RootManifest.workspaces
  if (!Array.isArray(ManifestWorkspaces)) {
    throw new Error('root package.json workspaces must be an array')
  }
  const ConfiguredPackages = ParseYamlStringList(Lines, 'packages', 0)
  if (JSON.stringify(ConfiguredPackages) !== JSON.stringify(ManifestWorkspaces)) {
    throw new Error('pnpm-workspace.yaml packages must exactly match package.json workspaces')
  }

  const ConfiguredBuilds = ParseAllowBuilds(Lines)
  const PolicyBuilds = new Set(Policy.lifecycleScripts.map(Entry => `${Entry.package}@${Entry.version}`))
  if (ConfiguredBuilds.size !== PolicyBuilds.size || [...ConfiguredBuilds].some(Identity => !PolicyBuilds.has(Identity))) {
    throw new Error('pnpm-workspace.yaml allowBuilds must exactly match node.lifecycleScripts')
  }
  const ConfiguredIgnores = ParseAuditIgnores(Lines).map(Value => Value.toUpperCase()).sort()
  const PolicyIgnores = Policy.auditExceptions.map(Entry => Entry.id.toUpperCase()).sort()
  if (JSON.stringify(ConfiguredIgnores) !== JSON.stringify(PolicyIgnores)) {
    throw new Error('pnpm-workspace.yaml auditConfig.ignoreGhsas must exactly match node.auditExceptions')
  }
}

function ValidatePackageManager(RootManifest: JsonRecord): void {
  const PackageManager = RootManifest.packageManager
  if (typeof PackageManager !== 'string' || !/^pnpm@\d+\.\d+\.\d+\+sha512[.][a-f0-9]{128}$/.test(PackageManager)) {
    throw new Error('root package.json packageManager must pin pnpm to an exact version and SHA-512 integrity')
  }
}

function LicenseIdentifiers(Expression: string): string[] {
  const WithoutOperators = Expression.replace(/[()]/g, ' ').split(/\s+(?:AND|OR|WITH)\s+/i)
  return WithoutOperators.map(Value => Value.trim()).filter(Value => Value !== '')
}

function ValidateLicenseReport(FilePath: string, Policy: NodePolicy): number {
  const Parsed = ParseJson(ReadBoundedFile(FilePath, 'pnpm license report'), 'pnpm license report')
  if (!IsRecord(Parsed) || Object.keys(Parsed).length === 0) {
    throw new Error('pnpm license report must be a non-empty object grouped by license')
  }
  let Packages = 0
  for (const [Expression, Entries] of Object.entries(Parsed)) {
    const Licenses = LicenseIdentifiers(Expression)
    if (Licenses.length === 0 || Licenses.some(License => !Policy.allowedLicenses.includes(License))) {
      throw new Error(`pnpm license report contains disallowed or unknown license expression: ${Expression}`)
    }
    if (!Array.isArray(Entries) || Entries.length === 0) {
      throw new Error(`pnpm license report ${Expression} entry must contain packages`)
    }
    for (const Entry of Entries) {
      if (!IsRecord(Entry) || typeof Entry.name !== 'string' || !Array.isArray(Entry.versions) || Entry.versions.length === 0) {
        throw new Error(`pnpm license report ${Expression} contains an invalid package record`)
      }
      if (Entry.versions.some(Version => typeof Version !== 'string' || Semver.valid(Version) === null)) {
        throw new Error(`pnpm license report ${Expression} contains a non-exact package version`)
      }
      Packages += 1
    }
  }

  return Packages
}

function ValidateAuditReport(FilePath: string, Policy: NodePolicy): void {
  const Parsed = ParseJson(ReadBoundedFile(FilePath, 'pnpm audit report'), 'pnpm audit report')
  if (IsRecord(Parsed) && Object.hasOwn(Parsed, 'error')) {
    RejectAuditErrorEnvelope(Parsed.error)
  }
  if (!IsRecord(Parsed) || !IsRecord(Parsed.advisories) || !IsRecord(Parsed.metadata)) {
    throw new Error('pnpm audit report must contain advisories and metadata objects')
  }
  const ReportedExceptions = new Set<string>()
  const Unadmitted: string[] = []
  Object.values(Parsed.advisories).forEach((Entry, Index) => {
    if (
      !IsRecord(Entry) ||
      typeof Entry.github_advisory_id !== 'string' ||
      typeof Entry.module_name !== 'string' ||
      typeof Entry.vulnerable_versions !== 'string'
    ) {
      throw new Error(`pnpm audit report advisory ${Index} is malformed`)
    }
    const AdvisoryId = Entry.github_advisory_id.toUpperCase()
    const Exception = Policy.auditExceptions.find(Candidate => Candidate.id.toUpperCase() === AdvisoryId)
    if (
      Exception === undefined ||
      Exception.package !== Entry.module_name ||
      Exception.versions !== Entry.vulnerable_versions
    ) {
      Unadmitted.push(`${AdvisoryId}:${Entry.module_name}:${Entry.vulnerable_versions}`)
      return
    }
    ReportedExceptions.add(AdvisoryId)
  })
  if (Unadmitted.length > 0) {
    throw new Error(`pnpm audit report contains unadmitted advisories: ${Unadmitted.sort().join(', ')}`)
  }
  const Stale = Policy.auditExceptions
    .map(Entry => Entry.id.toUpperCase())
    .filter(Id => !ReportedExceptions.has(Id))
    .sort()
  if (Stale.length > 0) {
    throw new Error(`node.auditExceptions contains stale or unreported advisories: ${Stale.join(', ')}`)
  }
}

export function ValidateDependencyAdmission(Options: DependencyAdmissionOptions): DependencyAdmissionResult {
  const Workspace = ResolveWorkspace(Options.workspacePath)
  const RootManifestPath = ResolveWorkspaceFile(Workspace, 'package.json', 'root package manifest')
  const RootManifestValue = ParseJson(ReadBoundedFile(RootManifestPath, 'root package manifest'), RootManifestPath)
  if (!IsRecord(RootManifestValue)) {
    throw new Error('root package.json must contain an object')
  }
  if (Fs.existsSync(Path.join(Workspace, 'npm-workspace.yaml'))) {
    throw new Error('stale npm-workspace.yaml is forbidden; package.json and pnpm-workspace.yaml are authoritative')
  }
  ValidatePackageManager(RootManifestValue)
  const PolicyPath = ResolveWorkspaceFile(Workspace, Options.policyPath, 'dependency policy')
  const Policy = ValidateNodePolicy(ParseJson(ReadBoundedFile(PolicyPath, 'dependency policy'), PolicyPath), Options.now ?? new Date())
  const Manifests = ExpandWorkspaceManifests(Workspace, RootManifestValue)
  ValidateManifestSpecifiers(Manifests)
  const WorkspaceConfigPath = ResolveWorkspaceFile(Workspace, 'pnpm-workspace.yaml', 'pnpm workspace configuration')
  ValidateWorkspaceConfig(ReadBoundedFile(WorkspaceConfigPath, 'pnpm workspace configuration'), RootManifestValue, Policy)
  const LockfilePath = ResolveWorkspaceFile(Workspace, 'pnpm-lock.yaml', 'pnpm lockfile')
  const Lockfile = ReadBoundedFile(LockfilePath, 'pnpm lockfile')
  ValidateLockImporters(Lockfile, Manifests)
  const LockedPackages = ValidateLockPackages(Lockfile)
  for (const Lifecycle of Policy.lifecycleScripts) {
    if (!LockedPackages.has(`${Lifecycle.package}@${Lifecycle.version}`)) {
      throw new Error(`node.lifecycleScripts admits package absent from pnpm-lock.yaml: ${Lifecycle.package}@${Lifecycle.version}`)
    }
  }

  const Result: DependencyAdmissionResult = {
    manifests: Manifests.length,
    lockedPackages: LockedPackages.size,
    lifecycleScripts: Policy.lifecycleScripts.length
  }
  if (Options.licenseReportPath !== undefined) {
    Result.licenses = ValidateLicenseReport(Path.resolve(Options.licenseReportPath), Policy)
  }
  if (Options.auditReportPath !== undefined) {
    ValidateAuditReport(Path.resolve(Options.auditReportPath), Policy)
  }

  return Result
}

function ParseArguments(ArgumentsValue: string[]): CliParameters {
  const Parameters: CliParameters = {}
  for (let Index = 0; Index < ArgumentsValue.length; Index += 1) {
    const Flag = ArgumentsValue[Index]
    const Value = ArgumentsValue[Index + 1]
    if (!['--workspace-path', '--policy-path', '--license-report-path', '--audit-report-path'].includes(Flag) || Value === undefined) {
      throw new Error(`unsupported or incomplete dependency-admission argument: ${Flag}`)
    }
    if (Flag === '--workspace-path') Parameters.workspacePath = Value
    if (Flag === '--policy-path') Parameters.policyPath = Value
    if (Flag === '--license-report-path') Parameters.licenseReportPath = Value
    if (Flag === '--audit-report-path') Parameters.auditReportPath = Value
    Index += 1
  }

  return Parameters
}

function Main(): void {
  const Parameters = ParseArguments(Process.argv.slice(2))
  if (Parameters.workspacePath === undefined || Parameters.policyPath === undefined) {
    throw new Error('--workspace-path and --policy-path are required')
  }
  const Result = ValidateDependencyAdmission({
    workspacePath: Parameters.workspacePath,
    policyPath: Parameters.policyPath,
    licenseReportPath: Parameters.licenseReportPath,
    auditReportPath: Parameters.auditReportPath
  })
  Process.stdout.write(`${JSON.stringify(Result)}\n`)
}

const InvokedPath = Process.argv[1] === undefined ? undefined : pathToFileURL(Path.resolve(Process.argv[1])).href
if (InvokedPath === import.meta.url) {
  try {
    Main()
  } catch (ErrorValue) {
    Process.stderr.write(`dependency admission failed: ${FormatError(ErrorValue)}\n`)
    Process.exit(1)
  }
}
