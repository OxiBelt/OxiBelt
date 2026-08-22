import * as Assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import * as Fs from 'node:fs'
import * as Os from 'node:os'
import * as Path from 'node:path'
import * as Process from 'node:process'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  ValidateReleaseTagRulesetState,
  type RulesetVisibility
} from '../sources/github_release_tag_ruleset.js'

const RepositoryRoot = fileURLToPath(new URL('../..', import.meta.url))
const RulesetSource = fileURLToPath(
  new URL('../sources/github_release_tag_ruleset.ts', import.meta.url)
)

const Binding = {
  schemaVersion: 1,
  repository: 'OxiBelt/OxiBelt',
  rulesetId: 19606649,
  rulesetName: 'release-tags-require-complete-validation'
}

const Policy = {
  name: Binding.rulesetName,
  target: 'tag',
  enforcement: 'active',
  bypass_actors: [],
  conditions: {
    ref_name: {
      include: ['refs/tags/[0-9]*.[0-9]*.[0-9]*'],
      exclude: []
    }
  },
  rules: [
    {
      type: 'required_status_checks',
      parameters: {
        do_not_enforce_on_create: false,
        required_status_checks: [{
          context: 'Non-benchmark validation summary',
          integration_id: 15368
        }],
        strict_required_status_checks_policy: false
      }
    },
    { type: 'update' },
    { type: 'deletion' }
  ]
}

function ActualRuleset(IncludeBypassActors = true): Record<string, unknown> {
  const Actual: Record<string, unknown> = {
    id: Binding.rulesetId,
    source_type: 'Repository',
    source: Binding.repository,
    name: Policy.name,
    target: Policy.target,
    enforcement: Policy.enforcement,
    conditions: structuredClone(Policy.conditions),
    rules: structuredClone(Policy.rules)
  }
  if (IncludeBypassActors) {
    Actual.bypass_actors = []
  }
  return Actual
}

function RulesetIndex(): unknown {
  return [[{
    id: Binding.rulesetId,
    source_type: 'Repository',
    source: Binding.repository,
    name: Binding.rulesetName,
    target: 'tag',
    enforcement: 'active'
  }]]
}

function Validate(
  Actual: unknown,
  Visibility: RulesetVisibility = 'authenticated',
  Index: unknown = RulesetIndex()
): void {
  ValidateReleaseTagRulesetState(Binding, Policy, Index, Actual, Visibility)
}

test('accepts exact authenticated and public GitHub ruleset responses', () => {
  Assert.doesNotThrow(() => Validate(ActualRuleset(), 'authenticated'))
  Assert.doesNotThrow(() => Validate(ActualRuleset(), 'public'))
  Assert.doesNotThrow(() => Validate(ActualRuleset(false), 'public'))
})

test('requires authenticated visibility to prove the ruleset remains bypass-free', () => {
  Assert.throws(
    () => Validate(ActualRuleset(false), 'authenticated'),
    /authenticated ruleset response must expose bypass_actors/
  )
  const Actual = ActualRuleset()
  Actual.bypass_actors = [{ actor_id: 1, actor_type: 'RepositoryRole', bypass_mode: 'always' }]
  Assert.throws(
    () => Validate(Actual, 'authenticated'),
    /does not match tracked desired state/
  )
})

test('rejects drift in every release-tag policy boundary', async Context => {
  const Mutations: Array<[string, (Actual: Record<string, unknown>) => void]> = [
    ['binding id', Actual => { Actual.id = Binding.rulesetId + 1 }],
    ['repository source type', Actual => { Actual.source_type = 'Organization' }],
    ['repository source', Actual => { Actual.source = 'OxiBelt/Elsewhere' }],
    ['ruleset name', Actual => { Actual.name = 'replacement-ruleset' }],
    ['target', Actual => { Actual.target = 'branch' }],
    ['enforcement', Actual => { Actual.enforcement = 'evaluate' }],
    ['tag include', Actual => {
      const Conditions = Actual.conditions as {
        ref_name: { include: string[], exclude: string[] }
      }
      Conditions.ref_name.include = ['refs/tags/**']
    }],
    ['tag exclude', Actual => {
      const Conditions = Actual.conditions as {
        ref_name: { include: string[], exclude: string[] }
      }
      Conditions.ref_name.exclude = ['refs/tags/0.8.1-beta.7']
    }],
    ['check context', Actual => {
      const Rules = Actual.rules as typeof Policy.rules
      const Check = Rules[0].parameters?.required_status_checks?.[0]
      if (Check !== undefined) Check.context = 'Verify canonical non-benchmark source validation'
    }],
    ['check application', Actual => {
      const Rules = Actual.rules as typeof Policy.rules
      const Check = Rules[0].parameters?.required_status_checks?.[0]
      if (Check !== undefined) Check.integration_id = 1
    }],
    ['creation enforcement', Actual => {
      const Rules = Actual.rules as typeof Policy.rules
      if (Rules[0].parameters !== undefined) Rules[0].parameters.do_not_enforce_on_create = true
    }],
    ['strict status policy', Actual => {
      const Rules = Actual.rules as typeof Policy.rules
      if (Rules[0].parameters !== undefined) {
        Rules[0].parameters.strict_required_status_checks_policy = true
      }
    }],
    ['update protection', Actual => {
      const Rules = Actual.rules as typeof Policy.rules
      Rules.splice(1, 1)
    }],
    ['deletion protection', Actual => {
      const Rules = Actual.rules as typeof Policy.rules
      Rules.splice(2, 1)
    }],
    ['extra rule', Actual => {
      const Rules = Actual.rules as Array<Record<string, unknown>>
      Rules.push({ type: 'creation' })
    }]
  ]

  for (const [Name, Mutate] of Mutations) {
    await Context.test(Name, () => {
      const Actual = ActualRuleset()
      Mutate(Actual)
      Assert.throws(() => Validate(Actual), /does not match tracked desired state|identity does not match/)
    })
  }
})

test('rejects replacement, missing, duplicate, and extra tag rulesets in the index', () => {
  const ExactIndex = RulesetIndex() as Array<Array<Record<string, unknown>>>
  for (const Index of [
    [[]],
    [[{ ...ExactIndex[0][0], id: Binding.rulesetId + 1 }]],
    [[ExactIndex[0][0], structuredClone(ExactIndex[0][0])]],
    [[ExactIndex[0][0], { ...ExactIndex[0][0], id: Binding.rulesetId + 1 }]]
  ]) {
    Assert.throws(
      () => Validate(ActualRuleset(), 'authenticated', Index),
      /exactly one tag-targeting ruleset|does not match the canonical binding/
    )
  }
})

test('CLI rejects a symbolic-link GitHub response before parsing it', Context => {
  const Root = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-ruleset-test-'))
  try {
    const ActualPath = Path.join(Root, 'actual.json')
    const IndexPath = Path.join(Root, 'index.json')
    const SymlinkPath = Path.join(Root, 'ruleset.json')
    Fs.writeFileSync(ActualPath, JSON.stringify(ActualRuleset()))
    Fs.writeFileSync(IndexPath, JSON.stringify(RulesetIndex()))
    Fs.symlinkSync(ActualPath, SymlinkPath)
    const Result = spawnSync(
      Process.execPath,
      [
        '--import', 'tsx', RulesetSource, 'check',
        '--workspace-path', RepositoryRoot,
        '--index', IndexPath,
        '--ruleset', SymlinkPath,
        '--visibility', 'authenticated'
      ],
      { encoding: 'utf8' }
    )
    const SpawnError = Result.error as (Error & { code?: string }) | undefined
    if (SpawnError?.code === 'EPERM') {
      Context.skip('the sandbox blocks nested Node process spawning')
      return
    }
    Assert.equal(Result.status, 1)
    Assert.match(Result.stderr, /must be a regular non-symlink file/)
  } finally {
    Fs.rmSync(Root, { force: true, recursive: true })
  }
})
