import * as Fs from 'node:fs'
import * as Path from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import { pathToFileURL } from 'node:url'

const BindingPath = 'devops/config/github-release-tag-ruleset-binding.json'
const PolicyPath = 'devops/config/github-release-tag-ruleset.json'
const MaxJsonBytes = 1024 * 1024
const MaxIndexPages = 10
const MaxIndexRulesets = 1000

export const RulesetVisibilities = ['public', 'authenticated'] as const
export type RulesetVisibility = (typeof RulesetVisibilities)[number]

type JsonRecord = Record<string, unknown>

/* oxlint-disable oxibelt/pascal-case -- GitHub and tracked policy JSON use stable lower-camel-case keys. */
type RulesetBinding = {
  schemaVersion: 1
  repository: string
  rulesetId: number
  rulesetName: string
}
/* oxlint-enable oxibelt/pascal-case */

type CliParameters = {
  workspacePath?: string
  indexPath?: string
  rulesetPath?: string
  visibility?: RulesetVisibility
}

function IsRecord(Value: unknown): Value is JsonRecord {
  return typeof Value === 'object' && Value !== null && !Array.isArray(Value)
}

function ExactKeys(Value: JsonRecord, Expected: string[], Label: string): void {
  const Actual = Object.keys(Value).sort()
  const Wanted = [...Expected].sort()
  if (!isDeepStrictEqual(Actual, Wanted)) {
    throw new Error(`${Label} keys are not canonical`)
  }
}

function ParseBinding(Value: unknown): RulesetBinding {
  if (!IsRecord(Value)) {
    throw new Error('release-tag ruleset binding must be an object')
  }
  ExactKeys(
    Value,
    ['schemaVersion', 'repository', 'rulesetId', 'rulesetName'],
    'release-tag ruleset binding'
  )
  if (Value.schemaVersion !== 1) {
    throw new Error('release-tag ruleset binding schemaVersion must be 1')
  }
  if (Value.repository !== 'OxiBelt/OxiBelt') {
    throw new Error('release-tag ruleset binding repository is not canonical')
  }
  if (!Number.isSafeInteger(Value.rulesetId) || Number(Value.rulesetId) <= 0) {
    throw new Error('release-tag ruleset binding rulesetId must be a positive integer')
  }
  if (Value.rulesetName !== 'release-tags-require-complete-validation') {
    throw new Error('release-tag ruleset binding rulesetName is not canonical')
  }
  return {
    schemaVersion: 1,
    repository: Value.repository,
    rulesetId: Number(Value.rulesetId),
    rulesetName: Value.rulesetName
  }
}

function ParsePolicy(Value: unknown, Binding: RulesetBinding): JsonRecord {
  if (!IsRecord(Value)) {
    throw new Error('release-tag ruleset policy must be an object')
  }
  ExactKeys(
    Value,
    ['name', 'target', 'enforcement', 'bypass_actors', 'conditions', 'rules'],
    'release-tag ruleset policy'
  )
  if (Value.name !== Binding.rulesetName) {
    throw new Error('release-tag ruleset policy name does not match its binding')
  }
  if (Value.target !== 'tag' || Value.enforcement !== 'active') {
    throw new Error('release-tag ruleset policy must be an active tag policy')
  }
  if (!Array.isArray(Value.bypass_actors) || Value.bypass_actors.length !== 0) {
    throw new Error('release-tag ruleset policy must remain bypass-free')
  }
  return Value
}

function FlattenIndex(Value: unknown): JsonRecord[] {
  if (!Array.isArray(Value) || Value.length === 0 || Value.length > MaxIndexPages) {
    throw new Error('GitHub ruleset index must contain a bounded non-empty page list')
  }
  const Rulesets: JsonRecord[] = []
  for (const Page of Value) {
    if (!Array.isArray(Page)) {
      throw new Error('GitHub ruleset index page must be an array')
    }
    for (const Ruleset of Page) {
      if (!IsRecord(Ruleset)) {
        throw new Error('GitHub ruleset index entry must be an object')
      }
      Rulesets.push(Ruleset)
      if (Rulesets.length > MaxIndexRulesets) {
        throw new Error('GitHub ruleset index exceeds the bounded entry limit')
      }
    }
  }
  return Rulesets
}

function ValidateIndex(Value: unknown, Binding: RulesetBinding): void {
  const TagRulesets = FlattenIndex(Value).filter(Ruleset => Ruleset.target === 'tag')
  if (TagRulesets.length !== 1) {
    throw new Error('repository must expose exactly one tag-targeting ruleset')
  }
  const [Ruleset] = TagRulesets
  if (
    Ruleset.id !== Binding.rulesetId ||
    Ruleset.name !== Binding.rulesetName ||
    Ruleset.source_type !== 'Repository' ||
    Ruleset.source !== Binding.repository ||
    Ruleset.enforcement !== 'active'
  ) {
    throw new Error('GitHub tag ruleset index does not match the canonical binding')
  }
}

function MutableRulesetState(Value: JsonRecord, IncludeBypassActors: boolean): JsonRecord {
  const State: JsonRecord = {
    name: Value.name,
    target: Value.target,
    enforcement: Value.enforcement,
    conditions: Value.conditions,
    rules: Value.rules
  }
  if (IncludeBypassActors) {
    State.bypass_actors = Value.bypass_actors
  }
  return State
}

export function ValidateReleaseTagRulesetState(
  BindingValue: unknown,
  PolicyValue: unknown,
  IndexValue: unknown,
  ActualValue: unknown,
  Visibility: RulesetVisibility
): void {
  if (!(RulesetVisibilities as readonly string[]).includes(Visibility)) {
    throw new Error(`unknown ruleset visibility: ${String(Visibility)}`)
  }
  const Binding = ParseBinding(BindingValue)
  const Policy = ParsePolicy(PolicyValue, Binding)
  ValidateIndex(IndexValue, Binding)
  if (!IsRecord(ActualValue)) {
    throw new Error('GitHub release-tag ruleset response must be an object')
  }
  if (
    ActualValue.id !== Binding.rulesetId ||
    ActualValue.source_type !== 'Repository' ||
    ActualValue.source !== Binding.repository
  ) {
    throw new Error('GitHub release-tag ruleset identity does not match the canonical binding')
  }

  const HasBypassActors = Object.hasOwn(ActualValue, 'bypass_actors')
  if (Visibility === 'authenticated' && !HasBypassActors) {
    throw new Error('authenticated ruleset response must expose bypass_actors')
  }
  const IncludeBypassActors = Visibility === 'authenticated' || HasBypassActors
  const Expected = MutableRulesetState(Policy, IncludeBypassActors)
  const Actual = MutableRulesetState(ActualValue, IncludeBypassActors)
  if (!isDeepStrictEqual(Actual, Expected)) {
    throw new Error('GitHub release-tag ruleset does not match tracked desired state')
  }
}

function ReadJson(PathValue: string, Label: string): unknown {
  const Resolved = Path.resolve(PathValue)
  let Descriptor: number
  try {
    Descriptor = Fs.openSync(Resolved, Fs.constants.O_RDONLY | Fs.constants.O_NOFOLLOW)
  } catch {
    throw new Error(`${Label} must be a regular non-symlink file`)
  }
  try {
    const Metadata = Fs.fstatSync(Descriptor)
    if (!Metadata.isFile()) {
      throw new Error(`${Label} must be a regular non-symlink file`)
    }
    if (Metadata.size <= 0 || Metadata.size > MaxJsonBytes) {
      throw new Error(`${Label} must be non-empty and at most ${MaxJsonBytes} bytes`)
    }
    try {
      return JSON.parse(Fs.readFileSync(Descriptor, 'utf8')) as unknown
    } catch {
      throw new Error(`${Label} is not valid JSON`)
    }
  } finally {
    Fs.closeSync(Descriptor)
  }
}

function ParseCli(Argv: string[]): CliParameters {
  if (Argv[2] !== 'check') {
    throw new Error('usage: github_release_tag_ruleset.ts check [options]')
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
      case '--workspace-path': Parameters.workspacePath = Value; break
      case '--index': Parameters.indexPath = Value; break
      case '--ruleset': Parameters.rulesetPath = Value; break
      case '--visibility':
        if (!(RulesetVisibilities as readonly string[]).includes(Value)) {
          throw new Error(`unknown ruleset visibility: ${Value}`)
        }
        Parameters.visibility = Value as RulesetVisibility
        break
      default: throw new Error(`unknown option: ${Option}`)
    }
  }
  return Parameters
}

function RunCli(): void {
  const Parameters = ParseCli(process.argv)
  if (
    Parameters.indexPath === undefined ||
    Parameters.rulesetPath === undefined ||
    Parameters.visibility === undefined
  ) {
    throw new Error('check requires --index, --ruleset, and --visibility')
  }
  const Root = Path.resolve(Parameters.workspacePath ?? '.')
  ValidateReleaseTagRulesetState(
    ReadJson(Path.join(Root, BindingPath), 'release-tag ruleset binding'),
    ReadJson(Path.join(Root, PolicyPath), 'release-tag ruleset policy'),
    ReadJson(Parameters.indexPath, 'GitHub ruleset index'),
    ReadJson(Parameters.rulesetPath, 'GitHub release-tag ruleset response'),
    Parameters.visibility
  )
}

const Entrypoint = process.argv[1]
if (Entrypoint !== undefined && import.meta.url === pathToFileURL(Path.resolve(Entrypoint)).href) {
  try {
    RunCli()
  } catch (ErrorValue) {
    const Message = ErrorValue instanceof Error ? ErrorValue.message : String(ErrorValue)
    console.error(`release-tag ruleset error: ${Message}`)
    process.exitCode = 1
  }
}
