import * as Crypto from 'node:crypto'
import * as Fs from 'node:fs'
import * as Path from 'node:path'
import * as Process from 'node:process'
import { execFileSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'
import * as Semver from 'semver'
import {
  AssertBuildTagMatchesRevision,
  ParseReleaseRef,
  type ReleaseKind,
  type ReleaseTagInfo
} from './docker_image_release.js'

const StableChangelogPath = 'CHANGELOG.md'
const BetaChangelogPath = 'CHANGELOG-beta.md'
const ForbiddenBuildChangelogPath = 'CHANGELOG-build.md'
const UpgradeGuidePath = 'docs/Upgrading.md'
const RepositoryUrl = 'https://github.com/OxiBelt/OxiBelt'
const MaximumChangelogBytes = 1024 * 1024
const MaximumUpgradeGuideBytes = 1024 * 1024
const MaximumReleaseBodyBytes = 256 * 1024
const FullRevision = /^[0-9a-f]{40}$/
const IsoDate = /^\d{4}-\d{2}-\d{2}$/
const Heading = /^## \[([^\]]+)\] - (\d{4}-\d{2}-\d{2})[ \t]*$/gm
const EmptySectionLine = '- No changes for this release.'
const KnownIssuesEmptyLine = '- None known at release cut.'
const PlaceholderText = /\b(?:TODO|TBD|FIXME|coming soon|placeholder)\b/i

export const RequiredReleaseSections = [
  'Configuration',
  'Schema epochs',
  'Deprecations and removals',
  'Admin API',
  'Feature lifecycle',
  'Rulepack compatibility',
  'Executables and images',
  'Storage and state',
  'Upgrade validation',
  'Rollback and irreversible steps',
  'Known issues',
  'Security'
] as const

type RequiredReleaseSection = (typeof RequiredReleaseSections)[number]

/* eslint-disable @typescript-eslint/naming-convention -- Parsed Markdown, CLI, receipt, and GitHub JSON records use stable lower-camel-case keys. */
type ReleaseEntry = {
  version: string
  date: string
  body: string
  raw: string
  historical: boolean
  changesSince?: string
  supportedUpgradeSources: string[]
  upgradeGuide?: string
  upgradeGuideAnchor?: string
  sections: Map<RequiredReleaseSection, string>
}

type Ledger = {
  path: string
  kind: 'stable' | 'beta'
  content: string
  entries: ReleaseEntry[]
}

export type ReleaseContractCheckOptions = {
  workspacePath: string
  changeBase?: string
  changeHead?: string
}

export type ReleaseCandidateOptions = {
  workspacePath: string
  ref: string
  revision: string
}

export type VerifyReleaseOptions = {
  receipt: ReleaseContractReceipt
  release: unknown
  expectedState: 'draft' | 'published'
  expectedBody: string
}

export type ReleaseContractReceipt = {
  schemaVersion: 1
  kind: ReleaseKind
  version: string
  ref: string
  revision: string
  baseVersion: string | null
  baseRevision: string | null
  supportedUpgradeSources: string[]
  ledgerPath: string | null
  entrySha256: string | null
  bodySha256: string | null
}

type GitHubRelease = {
  tag_name: string
  name: string | null
  body: string | null
  draft: boolean
  prerelease: boolean
}

type CliParameters = {
  workspacePath?: string
  changeBase?: string
  changeHead?: string
  ref?: string
  revision?: string
  receiptOutput?: string
  bodyOutput?: string
  receipt?: string
  release?: string
  expectedState?: string
  expectedBody?: string
}

type CompatibilitySurface = {
  section: RequiredReleaseSection
  patterns: RegExp[]
}

type LoadedContract = {
  stable: Ledger
  beta: Ledger
  upgradeGuide: string
}

type ReleaseCandidateResult = {
  receipt: ReleaseContractReceipt
  body: string
}

type ParsedCli = {
  command: string
  parameters: CliParameters
}
/* eslint-enable @typescript-eslint/naming-convention */

const CompatibilitySurfaceSections: CompatibilitySurface[] = [
  {
    section: 'Configuration',
    patterns: [
      /^source\/src\/config(?:\.rs|\/)/,
      /^source\/config\//,
      /^source\/assets\/oxibelt-config-v\d+\.schema\.json$/
    ]
  },
  {
    section: 'Schema epochs',
    patterns: [
      /^source\/src\/config\/schema\.rs$/,
      /^source\/apps\/oxibeltctl\/src\/config_(?:migrate|schema)\.rs$/,
      /^source\/assets\/oxibelt-config-v\d+\.schema\.json$/
    ]
  },
  {
    section: 'Admin API',
    patterns: [
      /^source\/assets\/admin-openapi\.json$/,
      /^source\/src\/admin(?:[_.].*|\/)/,
      /^source\/src\/server\/admin(?:[_.].*|\/)/,
      /^source\/src\/ipm\/admin(?:[_.].*|\/)/,
      /^source\/crates\/oxibelt-control-(?:http|protocol)\//
    ]
  },
  {
    section: 'Feature lifecycle',
    patterns: [
      /^docs\/FeatureStatus\.md$/,
      /^docs\/KubernetesSupport\.md$/,
      /^devops\/config\/kubernetes-feature-graduation(?:-evidence)?(?:\.schema)?\.json$/,
      /^devops\/sources\/kubernetes_graduation\.ts$/
    ]
  },
  {
    section: 'Rulepack compatibility',
    patterns: [
      /^source\/src\/waf\/rulepacks(?:[_.].*|\/)/,
      /^source\/apps\/oxibeltctl\/src\/rulepack(?:[_.].*|\/)/
    ]
  },
  {
    section: 'Executables and images',
    patterns: [
      /^source\/apps\//,
      /^source\/ops\/Dockerfile\.alpine$/,
      /^deploy\/helm\/oxibelt\//
    ]
  },
  {
    section: 'Storage and state',
    patterns: [
      /^deploy\/postgres\//,
      /(?:^|\/)store_schema\.rs$/,
      /^source\/src\/(?:admin_(?:audit|mutation)|server\/admin_operations)\/.*store/,
      /^source\/src\/shared_state(?:\.rs|\/)/
    ]
  }
]

function FormatError(ErrorValue: unknown): string {
  return ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)
}

function Sha256(Content: string): string {
  return Crypto.createHash('sha256').update(Content, 'utf8').digest('hex')
}

function NormalizeReleaseBody(Body: string): string {
  const Normalized = Body.replace(/\r\n/g, '\n')
  return Normalized.endsWith('\n') ? Normalized.slice(0, -1) : Normalized
}

function IsPathWithin(Parent: string, Candidate: string): boolean {
  const Relative = Path.relative(Parent, Candidate)
  return Relative === '' || (!Relative.startsWith(`..${Path.sep}`) && Relative !== '..' && !Path.isAbsolute(Relative))
}

function ResolveWorkspace(WorkspacePath: string): string {
  const Root = Fs.realpathSync(WorkspacePath)
  const Stat = Fs.statSync(Root)
  if (!Stat.isDirectory()) {
    throw new Error(`workspace path is not a directory: ${WorkspacePath}`)
  }
  return Root
}

function ResolveInputPath(Root: string, RelativePath: string): string {
  const Candidate = Path.resolve(Root, RelativePath)
  if (!IsPathWithin(Root, Candidate)) {
    throw new Error(`repository input escapes the workspace: ${RelativePath}`)
  }
  return Candidate
}

function ReadBoundedRepositoryFile(
  Root: string,
  RelativePath: string,
  MaximumBytes: number
): string {
  const Candidate = ResolveInputPath(Root, RelativePath)
  const Stat = Fs.lstatSync(Candidate)
  if (!Stat.isFile() || Stat.isSymbolicLink()) {
    throw new Error(`repository input must be a regular non-symlink file: ${RelativePath}`)
  }
  if (Stat.size > MaximumBytes) {
    throw new Error(`repository input exceeds ${MaximumBytes} bytes: ${RelativePath}`)
  }
  const Content = Fs.readFileSync(Candidate, 'utf8')
  if (Content.includes('\0')) {
    throw new Error(`repository input contains a NUL byte: ${RelativePath}`)
  }
  return Content
}

function ReadBoundedJsonFile(FilePath: string, MaximumBytes: number): unknown {
  return JSON.parse(ReadBoundedTextFile(FilePath, MaximumBytes, 'JSON input')) as unknown
}

function ReadBoundedTextFile(FilePath: string, MaximumBytes: number, Label: string): string {
  const Stat = Fs.lstatSync(FilePath)
  if (!Stat.isFile() || Stat.isSymbolicLink()) {
    throw new Error(`${Label} must be a regular non-symlink file: ${FilePath}`)
  }
  if (Stat.size > MaximumBytes) {
    throw new Error(`${Label} exceeds ${MaximumBytes} bytes: ${FilePath}`)
  }
  const Content = Fs.readFileSync(FilePath, 'utf8')
  if (Content.includes('\0')) {
    throw new Error(`${Label} contains a NUL byte: ${FilePath}`)
  }
  return Content
}

function AssertOutputPath(FilePath: string): void {
  const Parent = Fs.realpathSync(Path.dirname(Path.resolve(FilePath)))
  if (!Fs.statSync(Parent).isDirectory()) {
    throw new Error(`output parent is not a directory: ${Parent}`)
  }
  if (Fs.existsSync(FilePath)) {
    const Stat = Fs.lstatSync(FilePath)
    if (!Stat.isFile() || Stat.isSymbolicLink()) {
      throw new Error(`output must be a regular non-symlink file: ${FilePath}`)
    }
  }
}

function WriteOutput(FilePath: string, Content: string): void {
  AssertOutputPath(FilePath)
  const Flags = Fs.constants.O_WRONLY |
    Fs.constants.O_CREAT |
    Fs.constants.O_TRUNC |
    (Fs.constants.O_NOFOLLOW ?? 0)
  const Descriptor = Fs.openSync(FilePath, Flags, 0o600)
  try {
    Fs.writeFileSync(Descriptor, Content, { encoding: 'utf8' })
  } finally {
    Fs.closeSync(Descriptor)
  }
}

function IsRealDate(DateValue: string): boolean {
  if (!IsoDate.test(DateValue)) {
    return false
  }
  const Parsed = new Date(`${DateValue}T00:00:00Z`)
  return !Number.isNaN(Parsed.valueOf()) && Parsed.toISOString().slice(0, 10) === DateValue
}

function MaskFencedBlocks(Content: string): string {
  let FenceCharacter: '`' | '~' | undefined
  let FenceLength = 0
  return Content.split(/(?<=\n)/).map(Line => {
    const WithoutNewline = Line.endsWith('\n') ? Line.slice(0, -1) : Line
    const Newline = Line.endsWith('\n') ? '\n' : ''
    const Candidate = WithoutNewline.match(/^[ \t]{0,3}(`{3,}|~{3,})/)
    const IsClosing = FenceCharacter !== undefined &&
      new RegExp(`^[ \\t]{0,3}${FenceCharacter}{${FenceLength},}[ \\t]*$`).test(WithoutNewline)
    if (FenceCharacter === undefined && Candidate !== null) {
      FenceCharacter = Candidate[1][0] as '`' | '~'
      FenceLength = Candidate[1].length
      return `${' '.repeat(WithoutNewline.length)}${Newline}`
    }
    if (FenceCharacter !== undefined) {
      if (IsClosing) {
        FenceCharacter = undefined
        FenceLength = 0
      }
      return `${' '.repeat(WithoutNewline.length)}${Newline}`
    }
    return Line
  }).join('')
}

function ExtractSections(Body: string, Version: string): Map<RequiredReleaseSection, string> {
  const Matches = [...MaskFencedBlocks(Body).matchAll(/^### (.+?)[ \t]*$/gm)]
  const Sections = new Map<RequiredReleaseSection, string>()
  for (let Index = 0; Index < Matches.length; Index += 1) {
    const Match = Matches[Index]
    const Name = Match[1]
    if (!RequiredReleaseSections.includes(Name as RequiredReleaseSection)) {
      throw new Error(`release ${Version} contains an unknown level-three section: ${Name}`)
    }
    const SectionName = Name as RequiredReleaseSection
    if (RequiredReleaseSections[Index] !== SectionName) {
      throw new Error(
        `release ${Version} section ${SectionName} is out of order; expected ${RequiredReleaseSections[Index] ?? 'no additional section'}`
      )
    }
    if (Sections.has(SectionName)) {
      throw new Error(`release ${Version} repeats section: ${SectionName}`)
    }
    const Start = (Match.index ?? 0) + Match[0].length
    const End = Matches[Index + 1]?.index ?? Body.length
    Sections.set(SectionName, Body.slice(Start, End).trim())
  }
  return Sections
}

function ParseUpgradeSources(Value: string, Version: string): string[] {
  const Sources = [...Value.matchAll(/`([^`]+)`/g)].map(Match => Match[1])
  const Residual = Value.replace(/`[^`]+`/g, '').replace(/[\s,]/g, '')
  if (Sources.length === 0 || Residual !== '') {
    throw new Error(
      `release ${Version} Supported upgrade sources must be a comma-separated list of backticked SemVer versions`
    )
  }
  const Unique = new Set<string>()
  for (const Source of Sources) {
    let SourceTag: ReleaseTagInfo
    try {
      SourceTag = ParseReleaseRef(`refs/tags/${Source}`)
    } catch {
      throw new Error(`release ${Version} has an invalid supported upgrade source: ${Source}`)
    }
    if (
      Semver.valid(Source) !== Source ||
      SourceTag.kind === 'build' ||
      (SourceTag.kind === 'beta' && Number(SourceTag.betaNumber) < 1)
    ) {
      throw new Error(`release ${Version} has an invalid supported upgrade source: ${Source}`)
    }
    if (Unique.has(Source)) {
      throw new Error(`release ${Version} repeats supported upgrade source: ${Source}`)
    }
    Unique.add(Source)
  }
  return Sources
}

function ParseEntry(Version: string, DateValue: string, Body: string, Raw: string): ReleaseEntry {
  if (!IsRealDate(DateValue)) {
    throw new Error(`release ${Version} has an invalid calendar date: ${DateValue}`)
  }
  const Historical = /^> Historical baseline\./m.test(Body)
  if (Historical) {
    return {
      version: Version,
      date: DateValue,
      body: Body.trim(),
      raw: Raw,
      historical: true,
      supportedUpgradeSources: [],
      sections: new Map()
    }
  }

  if (PlaceholderText.test(Body)) {
    throw new Error(`release ${Version} contains placeholder wording`)
  }

  const StructuralBody = MaskFencedBlocks(Body)
  const ChangesMatch = StructuralBody.match(/^- Changes since: `([^`]+)`[ \t]*$/m)
  const SourcesMatch = StructuralBody.match(/^- Supported upgrade sources: (.+?)[ \t]*$/m)
  const GuideMatch = StructuralBody.match(
    /^- Upgrade guide: \[[^\]]+\]\((docs\/Upgrading\.md#([a-z0-9-]+))\)[ \t]*$/m
  )
  if (ChangesMatch === null) {
    throw new Error(`release ${Version} is missing "- Changes since: \`VERSION\`"`)
  }
  if (SourcesMatch === null) {
    throw new Error(`release ${Version} is missing "- Supported upgrade sources:"`)
  }
  if (GuideMatch === null) {
    throw new Error(`release ${Version} must link to an anchor in docs/Upgrading.md`)
  }

  const ChangesSince = ChangesMatch[1]
  if (Semver.valid(ChangesSince) !== ChangesSince) {
    throw new Error(`release ${Version} has an invalid Changes since version: ${ChangesSince}`)
  }
  const Sections = ExtractSections(Body, Version)
  for (const RequiredSection of RequiredReleaseSections) {
    const SectionBody = Sections.get(RequiredSection)
    if (SectionBody === undefined || SectionBody === '') {
      throw new Error(`release ${Version} is missing substantive section: ${RequiredSection}`)
    }
  }

  const Validation = Sections.get('Upgrade validation') ?? ''
  const CommandBlocks = [...Validation.matchAll(/```(?:sh|bash)\n([\s\S]*?)\n```/g)]
  const HasCommand = CommandBlocks.some(Block =>
    Block[1].split('\n').some(Line => Line.trim() !== '' && !Line.trimStart().startsWith('#'))
  )
  if (!HasCommand) {
    throw new Error(`release ${Version} Upgrade validation must contain a non-empty sh or bash command block`)
  }
  const Rollback = Sections.get('Rollback and irreversible steps') ?? ''
  if (Rollback === EmptySectionLine || Rollback.length < 40) {
    throw new Error(`release ${Version} must state concrete rollback or irreversible-step guidance`)
  }
  const KnownIssues = Sections.get('Known issues') ?? ''
  if (KnownIssues === EmptySectionLine) {
    throw new Error(`release ${Version} must use "${KnownIssuesEmptyLine}" when no known issues exist`)
  }
  for (const Section of RequiredReleaseSections.filter(Name => Name !== 'Known issues')) {
    if (Sections.get(Section) === KnownIssuesEmptyLine) {
      throw new Error(`release ${Version} may use "${KnownIssuesEmptyLine}" only in Known issues`)
    }
  }

  const SubstantiveSections = [
    ...RequiredReleaseSections.slice(0, 8),
    'Security' as const
  ].filter(Section => Sections.get(Section) !== EmptySectionLine)
  if (SubstantiveSections.length === 0) {
    throw new Error(`release ${Version} is placeholder-only`)
  }

  return {
    version: Version,
    date: DateValue,
    body: Body.trim(),
    raw: Raw,
    historical: false,
    changesSince: ChangesSince,
    supportedUpgradeSources: ParseUpgradeSources(SourcesMatch[1], Version),
    upgradeGuide: GuideMatch[1],
    upgradeGuideAnchor: GuideMatch[2],
    sections: Sections
  }
}

function ParseLedger(PathValue: string, Kind: 'stable' | 'beta', Content: string): Ledger {
  const MaskedContent = MaskFencedBlocks(Content)
  const Matches = [...MaskedContent.matchAll(Heading)]
  const ReleaseLookingHeadings = [...MaskedContent.matchAll(/^## \[[^\n]+$/gm)]
  if (Matches.length !== ReleaseLookingHeadings.length) {
    throw new Error(`${PathValue} contains a malformed release heading`)
  }
  const Entries: ReleaseEntry[] = []
  for (let Index = 0; Index < Matches.length; Index += 1) {
    const Match = Matches[Index]
    const Version = Match[1]
    const DateValue = Match[2]
    const Start = (Match.index ?? 0) + Match[0].length
    const End = Matches[Index + 1]?.index ?? Content.length
    let ReleaseTag: ReleaseTagInfo
    try {
      ReleaseTag = ParseReleaseRef(`refs/tags/${Version}`)
    } catch (ErrorValue) {
      throw new Error(`${PathValue} contains an invalid release heading ${Version}: ${FormatError(ErrorValue)}`)
    }
    if (ReleaseTag.kind !== Kind) {
      throw new Error(`${PathValue} contains ${ReleaseTag.kind} version ${Version}; expected ${Kind} only`)
    }
    if (ReleaseTag.kind === 'beta' && Number(ReleaseTag.betaNumber) < 1) {
      throw new Error(`${PathValue} beta versions must start at beta.1: ${Version}`)
    }
    const Body = Content.slice(Start, End).trim()
    Entries.push(ParseEntry(Version, DateValue, Body, Match[0] + Content.slice(Start, End)))
  }

  const HistoricalEntries = Entries.filter(Entry => Entry.historical)
  if (
    HistoricalEntries.length > 1 ||
    HistoricalEntries.some(Entry => Kind !== 'stable' || Entry.version !== '0.6.5')
  ) {
    throw new Error(`${PathValue} may mark only stable 0.6.5 as the historical baseline`)
  }
  for (let Index = 1; Index < Entries.length; Index += 1) {
    if (!Semver.gt(Entries[Index - 1].version, Entries[Index].version)) {
      throw new Error(`${PathValue} entries must be in strict descending SemVer order`)
    }
  }
  if (Kind === 'stable' && Entries.length === 0) {
    throw new Error(`${PathValue} must contain at least the historical stable baseline`)
  }
  return { path: PathValue, kind: Kind, content: Content, entries: Entries }
}

function HasMarkdownAnchor(Content: string, Anchor: string): boolean {
  const Slugs = new Set<string>()
  for (const Match of MaskFencedBlocks(Content).matchAll(/^#{1,6} (.+?)[ \t]*$/gm)) {
    const Slug = Match[1]
      .trim()
      .toLowerCase()
      .replace(/[`*_~]/g, '')
      .replace(/[^\p{L}\p{N}\s-]/gu, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '')
    Slugs.add(Slug)
  }
  return Slugs.has(Anchor)
}

function PreviousStable(Stable: Ledger, Version: string): ReleaseEntry {
  const Previous = Stable.entries.find(Entry => Semver.lt(Entry.version, Version))
  if (Previous === undefined) {
    throw new Error(`release ${Version} has no preceding stable changelog entry`)
  }
  return Previous
}

function AssertEntryBase(
  Entry: ReleaseEntry,
  Tag: ReleaseTagInfo,
  Stable: Ledger,
  Beta: Ledger
): string {
  const PreviousStableEntry = PreviousStable(Stable, Entry.version)
  let ExpectedBase = PreviousStableEntry.version
  if (Tag.kind === 'beta' && Number(Tag.betaNumber ?? '0') > 1) {
    const PreviousBeta = `${Tag.major}.${Tag.minor}.${Tag.patch}-beta.${Number(Tag.betaNumber) - 1}`
    if (!Beta.entries.some(Candidate => Candidate.version === PreviousBeta)) {
      throw new Error(`release ${Entry.version} requires the preceding beta entry ${PreviousBeta}`)
    }
    ExpectedBase = PreviousBeta
  }
  if (Entry.changesSince !== ExpectedBase) {
    throw new Error(
      `release ${Entry.version} must declare Changes since ${ExpectedBase}, found ${Entry.changesSince ?? 'nothing'}`
    )
  }
  const RequiredSources = Tag.kind === 'beta' && Number(Tag.betaNumber ?? '0') > 1
    ? [ExpectedBase, PreviousStableEntry.version]
    : [ExpectedBase]
  for (const RequiredSource of RequiredSources) {
    if (!Entry.supportedUpgradeSources.includes(RequiredSource)) {
      throw new Error(`release ${Entry.version} must support upgrade source ${RequiredSource}`)
    }
  }
  const TargetCore = `${Tag.major}.${Tag.minor}.${Tag.patch}`
  for (const SupportedSource of Entry.supportedUpgradeSources) {
    const SourceTag = ParseReleaseRef(`refs/tags/${SupportedSource}`)
    if (SourceTag.kind === 'stable' && SupportedSource !== PreviousStableEntry.version) {
      throw new Error(
        `release ${Entry.version} may name only immediately preceding stable ${PreviousStableEntry.version} as a stable source`
      )
    }
    if (
      SourceTag.kind === 'beta' &&
      (
        `${SourceTag.major}.${SourceTag.minor}.${SourceTag.patch}` !== TargetCore ||
        !Beta.entries.some(Candidate => Candidate.version === SupportedSource) ||
        !Semver.lt(SupportedSource, Entry.version)
      )
    ) {
      throw new Error(
        `release ${Entry.version} has unsupported beta upgrade source ${SupportedSource}`
      )
    }
  }
  return ExpectedBase
}

function LoadContract(Root: string): LoadedContract {
  if (Fs.existsSync(ResolveInputPath(Root, ForbiddenBuildChangelogPath))) {
    throw new Error(`${ForbiddenBuildChangelogPath} is forbidden; build tags have no changelog ledger`)
  }
  const Stable = ParseLedger(
    StableChangelogPath,
    'stable',
    ReadBoundedRepositoryFile(Root, StableChangelogPath, MaximumChangelogBytes)
  )
  const Beta = ParseLedger(
    BetaChangelogPath,
    'beta',
    ReadBoundedRepositoryFile(Root, BetaChangelogPath, MaximumChangelogBytes)
  )
  const UpgradeGuide = ReadBoundedRepositoryFile(Root, UpgradeGuidePath, MaximumUpgradeGuideBytes)
  for (const Entry of [...Stable.entries, ...Beta.entries]) {
    if (!Entry.historical && !HasMarkdownAnchor(UpgradeGuide, Entry.upgradeGuideAnchor ?? '')) {
      throw new Error(
        `release ${Entry.version} links to missing ${UpgradeGuidePath} anchor ${Entry.upgradeGuideAnchor ?? ''}`
      )
    }
  }
  for (const Entry of Stable.entries.filter(Candidate => !Candidate.historical)) {
    AssertEntryBase(Entry, ParseReleaseRef(`refs/tags/${Entry.version}`), Stable, Beta)
  }
  for (const Entry of Beta.entries) {
    AssertEntryBase(Entry, ParseReleaseRef(`refs/tags/${Entry.version}`), Stable, Beta)
  }
  return { stable: Stable, beta: Beta, upgradeGuide: UpgradeGuide }
}

function RunGit(Root: string, Arguments: string[]): string {
  return execFileSync('git', ['-C', Root, ...Arguments], {
    encoding: 'utf8',
    maxBuffer: 2 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe']
  }).trim()
}

function ResolveRevision(Root: string, Revisionish: string): string {
  const Revision = RunGit(Root, ['rev-parse', '--verify', `${Revisionish}^{commit}`]).toLowerCase()
  if (!FullRevision.test(Revision)) {
    throw new Error(`git did not resolve ${Revisionish} to a full lowercase revision`)
  }
  return Revision
}

function ChangedPaths(Root: string, Base: string, Head: string): string[] {
  const Output = RunGit(Root, ['diff', '--name-only', '--diff-filter=ACMR', `${Base}..${Head}`, '--'])
  return Output === '' ? [] : Output.split('\n')
}

function RequiredSectionsForPaths(Paths: string[]): Set<RequiredReleaseSection> {
  const Required = new Set<RequiredReleaseSection>()
  for (const PathValue of Paths) {
    for (const Surface of CompatibilitySurfaceSections) {
      if (Surface.patterns.some(Pattern => Pattern.test(PathValue))) {
        Required.add(Surface.section)
      }
    }
  }
  return Required
}

function AssertCompatibilityDocumentation(Paths: string[]): void {
  const RequiredSections = RequiredSectionsForPaths(Paths)
  if (RequiredSections.size === 0) {
    return
  }
  const ContractPaths = new Set([StableChangelogPath, BetaChangelogPath, UpgradeGuidePath])
  if (!Paths.some(PathValue => ContractPaths.has(PathValue))) {
    throw new Error(
      `compatibility surfaces changed (${[...RequiredSections].join(', ')}) without updating a changelog ledger or ${UpgradeGuidePath}`
    )
  }
}

function AssertCandidateSections(Entry: ReleaseEntry, Paths: string[]): void {
  for (const RequiredSection of RequiredSectionsForPaths(Paths)) {
    if (Entry.sections.get(RequiredSection) === EmptySectionLine) {
      throw new Error(
        `release ${Entry.version} changes the ${RequiredSection} compatibility surface but marks that section unchanged`
      )
    }
  }
}

export function ValidateRepositoryReleaseContract(Options: ReleaseContractCheckOptions): void {
  const Root = ResolveWorkspace(Options.workspacePath)
  LoadContract(Root)
  if ((Options.changeBase === undefined) !== (Options.changeHead === undefined)) {
    throw new Error('release-contract check requires both changeBase and changeHead when either is supplied')
  }
  if (Options.changeBase !== undefined && Options.changeHead !== undefined) {
    if (!FullRevision.test(Options.changeBase) || !FullRevision.test(Options.changeHead)) {
      throw new Error('release-contract changeBase and changeHead must be full lowercase Git revisions')
    }
    const Base = ResolveRevision(Root, Options.changeBase)
    const Head = ResolveRevision(Root, Options.changeHead)
    AssertCompatibilityDocumentation(ChangedPaths(Root, Base, Head))
  }
}

function RenderReleaseBody(Entry: ReleaseEntry, LedgerPath: string, Revision: string): string {
  const Anchor = Entry.upgradeGuideAnchor ?? ''
  const Body = `# OxiBelt ${Entry.version}

${Entry.body}

### Exact source

- Source revision: [\`${Revision}\`](${RepositoryUrl}/commit/${Revision})
- Changelog entry: [\`${LedgerPath}\` at \`${Revision}\`](${RepositoryUrl}/blob/${Revision}/${LedgerPath})
- Upgrade guide: [\`${UpgradeGuidePath}\` at \`${Revision}\`](${RepositoryUrl}/blob/${Revision}/${UpgradeGuidePath}#${Anchor})
`
  if (Buffer.byteLength(Body, 'utf8') > MaximumReleaseBodyBytes) {
    throw new Error(`release body exceeds ${MaximumReleaseBodyBytes} bytes`)
  }
  return Body
}

export function BuildReleaseCandidate(Options: ReleaseCandidateOptions): ReleaseCandidateResult {
  const Root = ResolveWorkspace(Options.workspacePath)
  const Tag = ParseReleaseRef(Options.ref)
  const RequestedRevision = Options.revision.toLowerCase()
  if (!FullRevision.test(RequestedRevision)) {
    throw new Error('candidate revision must be a full 40-character lowercase hexadecimal commit')
  }
  AssertBuildTagMatchesRevision(Tag, RequestedRevision)
  const TagRevision = ResolveRevision(Root, `refs/tags/${Tag.tag}`)
  if (TagRevision !== RequestedRevision) {
    throw new Error(`tag ${Tag.tag} resolves to ${TagRevision}, not candidate revision ${RequestedRevision}`)
  }

  if (Tag.kind === 'build') {
    return {
      receipt: {
        schemaVersion: 1,
        kind: Tag.kind,
        version: Tag.tag,
        ref: Options.ref,
        revision: RequestedRevision,
        baseVersion: null,
        baseRevision: null,
        supportedUpgradeSources: [],
        ledgerPath: null,
        entrySha256: null,
        bodySha256: null
      },
      body: ''
    }
  }

  const Contract = LoadContract(Root)
  const Ledger = Tag.kind === 'stable' ? Contract.stable : Contract.beta
  const Entry = Ledger.entries.find(Candidate => Candidate.version === Tag.tag)
  if (Entry === undefined || Entry.historical) {
    throw new Error(`${Ledger.path} has no governed entry for release ${Tag.tag}`)
  }
  const BaseVersion = AssertEntryBase(Entry, Tag, Contract.stable, Contract.beta)
  const BaseRevision = ResolveRevision(Root, `refs/tags/${BaseVersion}`)
  try {
    RunGit(Root, ['merge-base', '--is-ancestor', BaseRevision, RequestedRevision])
  } catch {
    throw new Error(`release base ${BaseVersion} (${BaseRevision}) is not an ancestor of ${RequestedRevision}`)
  }
  for (const SupportedSource of Entry.supportedUpgradeSources) {
    if (SupportedSource === BaseVersion) {
      continue
    }
    const SourceRevision = ResolveRevision(Root, `refs/tags/${SupportedSource}`)
    try {
      RunGit(Root, ['merge-base', '--is-ancestor', SourceRevision, RequestedRevision])
    } catch {
      throw new Error(
        `supported upgrade source ${SupportedSource} (${SourceRevision}) is not an ancestor of ${RequestedRevision}`
      )
    }
  }
  AssertCandidateSections(Entry, ChangedPaths(Root, BaseRevision, RequestedRevision))
  const Body = RenderReleaseBody(Entry, Ledger.path, RequestedRevision)
  return {
    receipt: {
      schemaVersion: 1,
      kind: Tag.kind,
      version: Tag.tag,
      ref: Options.ref,
      revision: RequestedRevision,
      baseVersion: BaseVersion,
      baseRevision: BaseRevision,
      supportedUpgradeSources: [...Entry.supportedUpgradeSources],
      ledgerPath: Ledger.path,
      entrySha256: Sha256(Entry.raw),
      bodySha256: Sha256(Body)
    },
    body: Body
  }
}

function ParseGitHubRelease(Value: unknown): GitHubRelease {
  if (typeof Value !== 'object' || Value === null || Array.isArray(Value)) {
    throw new Error('GitHub release input must be an object')
  }
  const Candidate = Value as Record<string, unknown>
  const RequiredString = (Name: string): string => {
    if (typeof Candidate[Name] !== 'string') {
      throw new Error(`GitHub release field ${Name} must be a string`)
    }
    return Candidate[Name]
  }
  const RequiredBoolean = (Name: string): boolean => {
    if (typeof Candidate[Name] !== 'boolean') {
      throw new Error(`GitHub release field ${Name} must be a boolean`)
    }
    return Candidate[Name]
  }
  const Name = Candidate.name
  const Body = Candidate.body
  if (Name !== null && typeof Name !== 'string') {
    throw new Error('GitHub release field name must be a string or null')
  }
  if (Body !== null && typeof Body !== 'string') {
    throw new Error('GitHub release field body must be a string or null')
  }
  return {
    tag_name: RequiredString('tag_name'),
    name: Name as string | null,
    body: Body as string | null,
    draft: RequiredBoolean('draft'),
    prerelease: RequiredBoolean('prerelease')
  }
}

function AssertReceiptIdentity(Receipt: ReleaseContractReceipt): void {
  let Tag: ReleaseTagInfo
  try {
    Tag = ParseReleaseRef(Receipt.ref)
  } catch (ErrorValue) {
    throw new Error(`release-contract receipt has an invalid ref: ${FormatError(ErrorValue)}`)
  }
  if (
    Tag.tag !== Receipt.version ||
    Tag.kind !== Receipt.kind ||
    !FullRevision.test(Receipt.revision) ||
    (Tag.kind === 'beta' && Number(Tag.betaNumber) < 1)
  ) {
    throw new Error('release-contract receipt identity is internally inconsistent')
  }
  if (Receipt.kind === 'build') {
    if (
      Receipt.baseVersion !== null ||
      Receipt.baseRevision !== null ||
      Receipt.supportedUpgradeSources.length !== 0 ||
      Receipt.ledgerPath !== null ||
      Receipt.entrySha256 !== null ||
      Receipt.bodySha256 !== null
    ) {
      throw new Error('build receipt must not contain changelog or GitHub Release metadata')
    }
    return
  }
  const ExpectedLedger = Receipt.kind === 'stable' ? StableChangelogPath : BetaChangelogPath
  if (
    Receipt.baseVersion === null ||
    Receipt.baseRevision === null ||
    Receipt.supportedUpgradeSources.length === 0 ||
    Receipt.ledgerPath !== ExpectedLedger ||
    Receipt.entrySha256 === null ||
    Receipt.bodySha256 === null
  ) {
    throw new Error(`${Receipt.kind} receipt is missing governed release metadata`)
  }
}

export function VerifyGitHubRelease(Options: VerifyReleaseOptions): void {
  const Release = ParseGitHubRelease(Options.release)
  const Receipt = Options.receipt
  AssertReceiptIdentity(Receipt)
  if (Receipt.schemaVersion !== 1 || (Receipt.kind !== 'stable' && Receipt.kind !== 'beta')) {
    throw new Error('GitHub Releases are valid only for stable or beta release-contract receipts')
  }
  const ExpectedDraft = Options.expectedState === 'draft'
  if (Release.tag_name !== Receipt.version || Release.name !== Receipt.version) {
    throw new Error(`GitHub release tag and name must both equal ${Receipt.version}`)
  }
  if (Release.draft !== ExpectedDraft) {
    throw new Error(`GitHub release ${Receipt.version} draft state does not match ${Options.expectedState}`)
  }
  const ExpectedPrerelease = Receipt.kind === 'beta'
  if (Release.prerelease !== ExpectedPrerelease) {
    throw new Error(`GitHub release ${Receipt.version} prerelease flag does not match ${Receipt.kind}`)
  }
  if (Buffer.byteLength(Options.expectedBody, 'utf8') > MaximumReleaseBodyBytes) {
    throw new Error(`expected release body exceeds ${MaximumReleaseBodyBytes} bytes`)
  }
  if (NormalizeReleaseBody(Release.body ?? '') !== NormalizeReleaseBody(Options.expectedBody)) {
    throw new Error(`GitHub release ${Receipt.version} body differs from the canonical changelog entry`)
  }
  if (Receipt.bodySha256 !== Sha256(Options.expectedBody)) {
    throw new Error('release-contract receipt body digest does not match the canonical body')
  }
}

function ParseCliParameters(Argv: string[]): ParsedCli {
  const Command = Argv[2]
  if (!['check', 'candidate', 'verify-release'].includes(Command ?? '')) {
    throw new Error('usage: release_contract.ts <check|candidate|verify-release> [options]')
  }
  const Parameters: CliParameters = {}
  for (let Index = 3; Index < Argv.length; Index += 1) {
    const Option = Argv[Index]
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
      case '--change-base':
        Parameters.changeBase = Value
        break
      case '--change-head':
        Parameters.changeHead = Value
        break
      case '--ref':
        Parameters.ref = Value
        break
      case '--revision':
        Parameters.revision = Value
        break
      case '--receipt-output':
        Parameters.receiptOutput = Value
        break
      case '--body-output':
        Parameters.bodyOutput = Value
        break
      case '--receipt':
        Parameters.receipt = Value
        break
      case '--release':
        Parameters.release = Value
        break
      case '--expected-state':
        Parameters.expectedState = Value
        break
      case '--expected-body':
        Parameters.expectedBody = Value
        break
      default:
        throw new Error(`unknown option: ${Option}`)
    }
  }
  return { command: Command, parameters: Parameters }
}

function Required(Value: string | undefined, Name: string): string {
  if (Value === undefined || Value === '') {
    throw new Error(`missing required option ${Name}`)
  }
  return Value
}

function ParseReceipt(Value: unknown): ReleaseContractReceipt {
  if (typeof Value !== 'object' || Value === null || Array.isArray(Value)) {
    throw new Error('release-contract receipt must be an object')
  }
  const Candidate = Value as Partial<ReleaseContractReceipt>
  if (
    Candidate.schemaVersion !== 1 ||
    !['stable', 'beta', 'build'].includes(Candidate.kind ?? '') ||
    typeof Candidate.version !== 'string' ||
    typeof Candidate.ref !== 'string' ||
    typeof Candidate.revision !== 'string' ||
    !FullRevision.test(Candidate.revision) ||
    Candidate.ref !== `refs/tags/${Candidate.version}` ||
    !Array.isArray(Candidate.supportedUpgradeSources) ||
    !Candidate.supportedUpgradeSources.every(Source => typeof Source === 'string') ||
    (Candidate.baseVersion !== null && typeof Candidate.baseVersion !== 'string') ||
    (Candidate.baseRevision !== null &&
      (typeof Candidate.baseRevision !== 'string' || !FullRevision.test(Candidate.baseRevision))) ||
    (Candidate.ledgerPath !== null && typeof Candidate.ledgerPath !== 'string') ||
    (Candidate.entrySha256 !== null &&
      (typeof Candidate.entrySha256 !== 'string' || !/^[0-9a-f]{64}$/.test(Candidate.entrySha256))) ||
    (Candidate.bodySha256 !== null &&
      (typeof Candidate.bodySha256 !== 'string' || !/^[0-9a-f]{64}$/.test(Candidate.bodySha256)))
  ) {
    throw new Error('release-contract receipt has an invalid schema')
  }
  const Receipt = Candidate as ReleaseContractReceipt
  AssertReceiptIdentity(Receipt)
  return Receipt
}

function RunCli(): void {
  const { command: Command, parameters: Parameters } = ParseCliParameters(Process.argv)
  if (Command === 'check') {
    ValidateRepositoryReleaseContract({
      workspacePath: Parameters.workspacePath ?? '.',
      changeBase: Parameters.changeBase,
      changeHead: Parameters.changeHead
    })
    return
  }
  if (Command === 'candidate') {
    const Result = BuildReleaseCandidate({
      workspacePath: Parameters.workspacePath ?? '.',
      ref: Required(Parameters.ref, '--ref'),
      revision: Required(Parameters.revision, '--revision')
    })
    WriteOutput(
      Required(Parameters.receiptOutput, '--receipt-output'),
      `${JSON.stringify(Result.receipt, null, 2)}\n`
    )
    WriteOutput(Required(Parameters.bodyOutput, '--body-output'), Result.body)
    return
  }

  const ExpectedState = Required(Parameters.expectedState, '--expected-state')
  if (ExpectedState !== 'draft' && ExpectedState !== 'published') {
    throw new Error('--expected-state must be draft or published')
  }
  const Receipt = ParseReceipt(
    ReadBoundedJsonFile(Required(Parameters.receipt, '--receipt'), MaximumReleaseBodyBytes)
  )
  const ExpectedBodyPath = Required(Parameters.expectedBody, '--expected-body')
  const ExpectedBody = ReadBoundedTextFile(
    ExpectedBodyPath,
    MaximumReleaseBodyBytes,
    'expected release body'
  )
  VerifyGitHubRelease({
    receipt: Receipt,
    release: ReadBoundedJsonFile(Required(Parameters.release, '--release'), MaximumReleaseBodyBytes),
    expectedState: ExpectedState,
    expectedBody: ExpectedBody
  })
}

if (Process.argv[1] !== undefined && import.meta.url === pathToFileURL(Process.argv[1]).href) {
  try {
    RunCli()
  } catch (ErrorValue) {
    console.error(FormatError(ErrorValue))
    Process.exit(1)
  }
}
