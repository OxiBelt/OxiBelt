import * as Assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import * as Crypto from 'node:crypto'
import * as Fs from 'node:fs'
import * as Os from 'node:os'
import * as Path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  BuildReleaseCandidate,
  ValidateRepositoryReleaseContract,
  VerifyGitHubRelease,
  type ReleaseContractReceipt
} from '../sources/release_contract.js'

const BaselineRevision = '1111111111111111111111111111111111111111'
const ReleaseContractSource = fileURLToPath(new URL('../sources/release_contract.ts', import.meta.url))

const BaselineEntry = `## [0.6.5] - 2026-07-16

> Historical baseline. This release predates the versioned changelog and
> upgrade contract.

- Source revision: [\`${BaselineRevision}\`](https://github.com/OxiBelt/OxiBelt/commit/${BaselineRevision})
`

function GovernedEntry(
  Version = '0.7.0',
  ChangesSince = '0.6.5',
  SupportedSources = `\`${ChangesSince}\``
): string {
  return `## [${Version}] - 2026-07-23

- Changes since: \`${ChangesSince}\`
- Supported upgrade sources: ${SupportedSources}
- Upgrade guide: [Upgrade from 0.6.5](docs/Upgrading.md#upgrade-from-065)

### Configuration

- Add a person-reviewed configuration compatibility statement.

### Schema epochs

- No changes for this release.

### Deprecations and removals

- No changes for this release.

### Admin API

- No changes for this release.

### Feature lifecycle

- No changes for this release.

### Rulepack compatibility

- No changes for this release.

### Executables and images

- No changes for this release.

### Storage and state

- No changes for this release.

### Upgrade validation

\`\`\`sh
oxibeltctl config validate /etc/oxibelt/config/oxibelt.toml --local-only
\`\`\`

### Rollback and irreversible steps

- Retain the prior immutable image digests and restore them with the prior configuration.

### Known issues

- None known at release cut.

### Security

- No changes for this release.
`
}

function WriteFile(Root: string, RelativePath: string, Content: string): void {
  const FilePath = Path.join(Root, RelativePath)
  Fs.mkdirSync(Path.dirname(FilePath), { recursive: true })
  Fs.writeFileSync(FilePath, Content)
}

function CreateContractWorkspace(StableEntries = BaselineEntry, BetaEntries = ''): string {
  const Root = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-release-contract-'))
  WriteFile(
    Root,
    'CHANGELOG.md',
    `# Stable\n\n${StableEntries}`
  )
  WriteFile(
    Root,
    'CHANGELOG-beta.md',
    `# Beta\n\n${BetaEntries}`
  )
  WriteFile(
    Root,
    'docs/Upgrading.md',
    '# Upgrading\n\n## Upgrade from 0.6.5\n\nFollow the release entry.\n'
  )
  return Root
}

function Git(Root: string, Arguments: string[]): string {
  return execFileSync('git', ['-C', Root, ...Arguments], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe']
  }).trim()
}

function Commit(Root: string, Message: string): string {
  Git(Root, ['add', '.'])
  Git(Root, ['-c', 'user.name=OxiBelt Test', '-c', 'user.email=test@oxibelt.invalid', 'commit', '-m', Message])
  return Git(Root, ['rev-parse', 'HEAD'])
}

function CommitBuildTagRevision(Root: string): string {
  for (let Attempt = 0; Attempt < 64; Attempt += 1) {
    WriteFile(Root, '.build-tag-nonce', `${Attempt}\n`)
    const Revision = Commit(Root, `build ${Attempt}`)
    if (!/^0[0-9]{7}$/.test(Revision.slice(0, 8))) {
      return Revision
    }
  }
  throw new Error('could not create a strict-SemVer build-tag revision after 64 attempts')
}

function RemoveWorkspace(Root: string): void {
  Fs.rmSync(Root, { force: true, recursive: true })
}

test('accepts the forward-only historical baseline and governed stable entry', () => {
  const Root = CreateContractWorkspace(`${GovernedEntry()}\n${BaselineEntry}`)
  try {
    ValidateRepositoryReleaseContract({ workspacePath: Root })
  } finally {
    RemoveWorkspace(Root)
  }
})

test('does not rewrite an earlier beta base when a lower stable version is published later', () => {
  const Stable066 = GovernedEntry('0.6.6', '0.6.5').replace(
    '## [0.6.6] - 2026-07-23',
    '## [0.6.6] - 2026-08-14'
  )
  const EarlierBeta = GovernedEntry('0.7.1-beta.1', '0.6.5').replace(
    '## [0.7.1-beta.1] - 2026-07-23',
    '## [0.7.1-beta.1] - 2026-08-11'
  )
  const Root = CreateContractWorkspace(`${Stable066}\n${BaselineEntry}`, EarlierBeta)
  try {
    ValidateRepositoryReleaseContract({ workspacePath: Root })
  } finally {
    RemoveWorkspace(Root)
  }
})

test('requires a stable published on the same date as a later beta', () => {
  const Stable066 = GovernedEntry('0.6.6', '0.6.5').replace(
    '## [0.6.6] - 2026-07-23',
    '## [0.6.6] - 2026-08-14'
  )
  const LaterBeta = GovernedEntry('0.8.0-beta.1', '0.6.5').replace(
    '## [0.8.0-beta.1] - 2026-07-23',
    '## [0.8.0-beta.1] - 2026-08-14'
  )
  const Root = CreateContractWorkspace(`${Stable066}\n${BaselineEntry}`, LaterBeta)
  try {
    Assert.throws(
      () => ValidateRepositoryReleaseContract({ workspacePath: Root }),
      /release 0\.8\.0-beta\.1 must declare Changes since 0\.6\.6/
    )
  } finally {
    RemoveWorkspace(Root)
  }
})

test('requires the latest target beta even when the stable entry is backdated', () => {
  const BetaOne = GovernedEntry('0.8.0-beta.1')
  const BetaTwo = GovernedEntry(
    '0.8.0-beta.2',
    '0.8.0-beta.1',
    '`0.8.0-beta.1`, `0.6.5`'
  ).replace('## [0.8.0-beta.2] - 2026-07-23', '## [0.8.0-beta.2] - 2026-07-24')
  const BackdatedStable = GovernedEntry(
    '0.8.0',
    '0.6.5',
    '`0.6.5`, `0.8.0-beta.1`'
  ).replace('## [0.8.0] - 2026-07-23', '## [0.8.0] - 2026-07-22')
  const Root = CreateContractWorkspace(
    `${BackdatedStable}\n${BaselineEntry}`,
    `${BetaTwo}\n${BetaOne}`
  )
  try {
    Assert.throws(
      () => ValidateRepositoryReleaseContract({ workspacePath: Root }),
      /release 0\.8\.0 must support upgrade source 0\.8\.0-beta\.2/
    )
  } finally {
    RemoveWorkspace(Root)
  }
})

test('rejects cross-channel and placeholder-only release entries', () => {
  const CrossChannelRoot = CreateContractWorkspace(BaselineEntry, GovernedEntry())
  try {
    Assert.throws(
      () => ValidateRepositoryReleaseContract({ workspacePath: CrossChannelRoot }),
      /contains stable version 0\.7\.0; expected beta only/
    )
  } finally {
    RemoveWorkspace(CrossChannelRoot)
  }

  const PlaceholderRoot = CreateContractWorkspace(
    `${GovernedEntry().replace(
      '- Add a person-reviewed configuration compatibility statement.',
      '- No changes for this release.'
    )}\n${BaselineEntry}`
  )
  try {
    Assert.throws(
      () => ValidateRepositoryReleaseContract({ workspacePath: PlaceholderRoot }),
      /placeholder-only/
    )
  } finally {
    RemoveWorkspace(PlaceholderRoot)
  }
})

test('rejects a build ledger and non-descending stable SemVer order', () => {
  const BuildLedgerRoot = CreateContractWorkspace()
  try {
    WriteFile(BuildLedgerRoot, 'CHANGELOG-build.md', '# Build releases are forbidden.\n')
    Assert.throws(
      () => ValidateRepositoryReleaseContract({ workspacePath: BuildLedgerRoot }),
      /CHANGELOG-build\.md is forbidden/
    )
  } finally {
    RemoveWorkspace(BuildLedgerRoot)
  }

  const MisorderedRoot = CreateContractWorkspace(
    `${GovernedEntry('0.7.0')}\n${GovernedEntry('0.8.0')}\n${BaselineEntry}`
  )
  try {
    Assert.throws(
      () => ValidateRepositoryReleaseContract({ workspacePath: MisorderedRoot }),
      /strict descending SemVer order/
    )
  } finally {
    RemoveWorkspace(MisorderedRoot)
  }
})

test('accepts an ordered beta chain and requires both beta and stable sources after beta.1', () => {
  const BetaOne = GovernedEntry('0.7.0-beta.1')
  const BetaTwo = GovernedEntry(
    '0.7.0-beta.2',
    '0.7.0-beta.1',
    '`0.7.0-beta.1`, `0.6.5`'
  )
  const Root = CreateContractWorkspace(BaselineEntry, `${BetaTwo}\n${BetaOne}`)
  try {
    ValidateRepositoryReleaseContract({ workspacePath: Root })
  } finally {
    RemoveWorkspace(Root)
  }

  const MissingStableRoot = CreateContractWorkspace(
    BaselineEntry,
    `${GovernedEntry('0.7.0-beta.2', '0.7.0-beta.1')}\n${BetaOne}`
  )
  try {
    Assert.throws(
      () => ValidateRepositoryReleaseContract({ workspacePath: MissingStableRoot }),
      /must support upgrade source 0\.6\.5/
    )
  } finally {
    RemoveWorkspace(MissingStableRoot)
  }
})

test('rejects compatibility-surface changes without a release-contract document update', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    WriteFile(Root, 'source/src/config/example.rs', 'pub const VALUE: u8 = 1;\n')
    const Base = Commit(Root, 'baseline')
    WriteFile(Root, 'source/src/config/example.rs', 'pub const VALUE: u8 = 2;\n')
    const Head = Commit(Root, 'change config')
    Assert.throws(
      () => ValidateRepositoryReleaseContract({
        workspacePath: Root,
        changeBase: Base,
        changeHead: Head
      }),
      /without updating a changelog ledger or docs\/Upgrading\.md/
    )
  } finally {
    RemoveWorkspace(Root)
  }
})

test('rejects deleted compatibility surfaces without a release-contract document update', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    WriteFile(Root, 'source/src/config/example.rs', 'pub const VALUE: u8 = 1;\n')
    const Base = Commit(Root, 'baseline')
    Fs.rmSync(Path.join(Root, 'source/src/config/example.rs'))
    const DeletedHead = Commit(Root, 'delete config')

    Assert.throws(
      () => ValidateRepositoryReleaseContract({
        workspacePath: Root,
        changeBase: Base,
        changeHead: DeletedHead
      }),
      /without updating a changelog ledger or docs\/Upgrading\.md/
    )

    WriteFile(
      Root,
      'docs/Upgrading.md',
      '# Upgrading\n\n## Upgrade from 0.6.5\n\nDocument the removed configuration surface.\n'
    )
    const DocumentedHead = Commit(Root, 'document config deletion')
    ValidateRepositoryReleaseContract({
      workspacePath: Root,
      changeBase: Base,
      changeHead: DocumentedHead
    })
  } finally {
    RemoveWorkspace(Root)
  }
})

test('rejects renaming a compatibility surface outside governed paths', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    Git(Root, ['config', 'diff.renames', 'true'])
    WriteFile(Root, 'source/src/config/example.rs', 'pub const VALUE: u8 = 1;\n')
    const Base = Commit(Root, 'baseline')
    Fs.mkdirSync(Path.join(Root, 'misc'), { recursive: true })
    Fs.renameSync(
      Path.join(Root, 'source/src/config/example.rs'),
      Path.join(Root, 'misc/example.rs')
    )
    const Head = Commit(Root, 'rename config outside governed paths')

    Assert.throws(
      () => ValidateRepositoryReleaseContract({
        workspacePath: Root,
        changeBase: Base,
        changeHead: Head
      }),
      /without updating a changelog ledger or docs\/Upgrading\.md/
    )
  } finally {
    RemoveWorkspace(Root)
  }
})

test('classifies the Kubernetes graduation registry as a feature lifecycle surface', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    WriteFile(
      Root,
      'devops/config/kubernetes-feature-graduation.json',
      '{"schemaVersion":1,"policyVersion":1}\n'
    )
    const Base = Commit(Root, 'baseline')
    WriteFile(
      Root,
      'devops/config/kubernetes-feature-graduation.json',
      '{"schemaVersion":1,"policyVersion":2}\n'
    )
    const Head = Commit(Root, 'change Kubernetes graduation')
    Assert.throws(
      () => ValidateRepositoryReleaseContract({
        workspacePath: Root,
        changeBase: Base,
        changeHead: Head
      }),
      /compatibility surfaces changed \(Feature lifecycle\)/
    )
  } finally {
    RemoveWorkspace(Root)
  }
})

test('classifies the non-Kubernetes graduation contract as a feature lifecycle surface', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    WriteFile(
      Root,
      'devops/config/feature-graduation.json',
      '{"schemaVersion":1,"policyVersion":1}\n'
    )
    const Base = Commit(Root, 'baseline')
    WriteFile(
      Root,
      'devops/config/feature-graduation.json',
      '{"schemaVersion":1,"policyVersion":2}\n'
    )
    const Head = Commit(Root, 'change feature graduation')
    Assert.throws(
      () => ValidateRepositoryReleaseContract({
        workspacePath: Root,
        changeBase: Base,
        changeHead: Head
      }),
      /compatibility surfaces changed \(Feature lifecycle\)/
    )
  } finally {
    RemoveWorkspace(Root)
  }
})

test('classifies the exact feature-graduation workflow as a feature lifecycle surface', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    WriteFile(
      Root,
      '.github/workflows/feature-graduation.yml',
      'name: Feature graduation\non:\n  workflow_dispatch:\n'
    )
    const Base = Commit(Root, 'baseline')
    WriteFile(
      Root,
      '.github/workflows/feature-graduation.yml',
      'name: Feature graduation qualification\non:\n  workflow_dispatch:\n'
    )
    const Head = Commit(Root, 'change feature graduation workflow')
    Assert.throws(
      () => ValidateRepositoryReleaseContract({
        workspacePath: Root,
        changeBase: Base,
        changeHead: Head
      }),
      /compatibility surfaces changed \(Feature lifecycle\)/
    )
  } finally {
    RemoveWorkspace(Root)
  }
})

test('classifies supply-chain schemas as schema epoch surfaces', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    WriteFile(
      Root,
      'deploy/supply-chain/admission-bundle.schema.json',
      '{"schemaVersion":1}\n'
    )
    const Base = Commit(Root, 'baseline')
    WriteFile(
      Root,
      'deploy/supply-chain/admission-bundle.schema.json',
      '{"schemaVersion":2}\n'
    )
    const ChangedHead = Commit(Root, 'change supply-chain schema')
    Assert.throws(
      () => ValidateRepositoryReleaseContract({
        workspacePath: Root,
        changeBase: Base,
        changeHead: ChangedHead
      }),
      /compatibility surfaces changed \(Schema epochs\)/
    )

    Fs.rmSync(Path.join(Root, 'deploy/supply-chain/admission-bundle.schema.json'))
    const DeletedHead = Commit(Root, 'delete supply-chain schema')
    Assert.throws(
      () => ValidateRepositoryReleaseContract({
        workspacePath: Root,
        changeBase: Base,
        changeHead: DeletedHead
      }),
      /compatibility surfaces changed \(Schema epochs\)/
    )
  } finally {
    RemoveWorkspace(Root)
  }
})

test('builds exact stable release notes and a digest-bound receipt', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    Commit(Root, 'baseline')
    Git(Root, ['tag', '0.6.5'])
    WriteFile(Root, 'CHANGELOG.md', `# Stable\n\n${GovernedEntry()}\n${BaselineEntry}`)
    const Revision = Commit(Root, 'release contract')
    Git(Root, ['tag', '0.7.0'])

    const Result = BuildReleaseCandidate({
      workspacePath: Root,
      ref: 'refs/tags/0.7.0',
      revision: Revision
    })

    Assert.equal(Result.receipt.kind, 'stable')
    Assert.equal(Result.receipt.baseVersion, '0.6.5')
    Assert.equal(Result.receipt.revision, Revision)
    Assert.match(Result.body, new RegExp(`commit/${Revision}`))
    Assert.match(Result.body, new RegExp(`blob/${Revision}/CHANGELOG\\.md`))
    Assert.notEqual(Result.receipt.entrySha256, null)
    Assert.notEqual(Result.receipt.bodySha256, null)
  } finally {
    RemoveWorkspace(Root)
  }
})

test('requires the latest beta and one documentation-only stable carry-forward commit', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    Commit(Root, 'baseline')
    Git(Root, ['tag', '0.6.5'])
    const BetaEntry = GovernedEntry('0.8.0-beta.1')
    WriteFile(Root, 'CHANGELOG-beta.md', `# Beta\n\n${BetaEntry}`)
    WriteFile(Root, 'source.txt', 'beta source\n')
    Commit(Root, 'beta')
    Git(Root, ['tag', '0.8.0-beta.1'])

    const StableEntry = GovernedEntry('0.8.0', '0.6.5', '`0.6.5`, `0.8.0-beta.1`')
      .replace('## [0.8.0] - 2026-07-23', '## [0.8.0] - 2026-07-24')
    WriteFile(Root, 'CHANGELOG.md', `# Stable\n\n${StableEntry}\n${BaselineEntry}`)
    WriteFile(Root, 'docs/Upgrading.md', '# Upgrading\n\n## Upgrade from 0.6.5\n\nStable carry-forward.\n')
    const StableRevision = Commit(Root, 'stable documentation')
    Git(Root, ['tag', '0.8.0'])

    const Result = BuildReleaseCandidate({
      workspacePath: Root,
      ref: 'refs/tags/0.8.0',
      revision: StableRevision
    })
    Assert.equal(Result.receipt.baseVersion, '0.6.5')
    Assert.deepEqual(Result.receipt.supportedUpgradeSources, ['0.6.5', '0.8.0-beta.1'])

    WriteFile(Root, 'source.txt', 'changed after beta\n')
    const InvalidRevision = Commit(Root, 'non-documentation stable change')
    Git(Root, ['tag', '--delete', '0.8.0'])
    Git(Root, ['tag', '0.8.0'])
    Assert.throws(
      () => BuildReleaseCandidate({
        workspacePath: Root,
        ref: 'refs/tags/0.8.0',
        revision: InvalidRevision
      }),
      /must be one documentation-only commit after 0\.8\.0-beta\.1/
    )
  } finally {
    RemoveWorkspace(Root)
  }
})

test('rejects the backdated stable bypass through the candidate CLI', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    WriteFile(Root, 'source/src/config/example.rs', 'pub const VALUE: u8 = 1;\n')
    Commit(Root, 'baseline')
    Git(Root, ['tag', '0.6.5'])

    const BetaEntry = GovernedEntry('0.8.0-beta.1')
    WriteFile(Root, 'CHANGELOG-beta.md', `# Beta\n\n${BetaEntry}`)
    Commit(Root, 'beta')
    Git(Root, ['tag', '0.8.0-beta.1'])

    const BackdatedStable = GovernedEntry('0.8.0').replace(
      '## [0.8.0] - 2026-07-23',
      '## [0.8.0] - 2026-07-22'
    )
    WriteFile(Root, 'CHANGELOG.md', `# Stable\n\n${BackdatedStable}\n${BaselineEntry}`)
    WriteFile(Root, 'docs/Upgrading.md', '# Upgrading\n\n## Upgrade from 0.6.5\n\nStable carry-forward.\n')
    WriteFile(Root, 'source/src/config/example.rs', 'pub const VALUE: u8 = 2;\n')
    const StableRevision = Commit(Root, 'backdated stable with source change')
    Git(Root, ['tag', '0.8.0'])

    const ReceiptOutput = Path.join(Root, 'release-contract.json')
    const BodyOutput = Path.join(Root, 'release-body.md')
    const Result = spawnSync(process.execPath, [
      '--import',
      'tsx',
      ReleaseContractSource,
      'candidate',
      '--workspace-path',
      Root,
      '--ref',
      'refs/tags/0.8.0',
      '--revision',
      StableRevision,
      '--receipt-output',
      ReceiptOutput,
      '--body-output',
      BodyOutput
    ], { encoding: 'utf8' })

    Assert.equal(Result.status, 1)
    Assert.match(Result.stderr, /release 0\.8\.0 must support upgrade source 0\.8\.0-beta\.1/)
    Assert.equal(Fs.existsSync(ReceiptOutput), false)
    Assert.equal(Fs.existsSync(BodyOutput), false)
  } finally {
    RemoveWorkspace(Root)
  }
})

test('rejects a one-commit stable cut containing a non-documentation path', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    WriteFile(Root, 'source/src/config/example.rs', 'pub const VALUE: u8 = 1;\n')
    Commit(Root, 'baseline')
    Git(Root, ['tag', '0.6.5'])

    const BetaEntry = GovernedEntry('0.8.0-beta.1')
    WriteFile(Root, 'CHANGELOG-beta.md', `# Beta\n\n${BetaEntry}`)
    Commit(Root, 'beta')
    Git(Root, ['tag', '0.8.0-beta.1'])

    const BackdatedStable = GovernedEntry('0.8.0', '0.6.5', '`0.6.5`, `0.8.0-beta.1`')
      .replace('## [0.8.0] - 2026-07-23', '## [0.8.0] - 2026-07-22')
    WriteFile(Root, 'CHANGELOG.md', `# Stable\n\n${BackdatedStable}\n${BaselineEntry}`)
    WriteFile(Root, 'docs/Upgrading.md', '# Upgrading\n\n## Upgrade from 0.6.5\n\nStable carry-forward.\n')
    WriteFile(Root, 'source/src/config/example.rs', 'pub const VALUE: u8 = 2;\n')
    const StableRevision = Commit(Root, 'stable with source change')
    Git(Root, ['tag', '0.8.0'])

    Assert.throws(
      () => BuildReleaseCandidate({
        workspacePath: Root,
        ref: 'refs/tags/0.8.0',
        revision: StableRevision
      }),
      /stable release 0\.8\.0 may change only CHANGELOG\.md and docs\/Upgrading\.md after 0\.8\.0-beta\.1/
    )
  } finally {
    RemoveWorkspace(Root)
  }
})

test('rejects a latest target beta that is not an ancestor of the stable cut', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    Commit(Root, 'baseline')
    Git(Root, ['tag', '0.6.5'])

    const BetaEntry = GovernedEntry('0.8.0-beta.1')
    WriteFile(Root, 'CHANGELOG-beta.md', `# Beta\n\n${BetaEntry}`)
    Commit(Root, 'beta')
    Git(Root, ['tag', '0.8.0-beta.1'])

    Git(Root, ['switch', '--detach', '0.6.5'])
    const StableEntry = GovernedEntry('0.8.0', '0.6.5', '`0.6.5`, `0.8.0-beta.1`')
      .replace('## [0.8.0] - 2026-07-23', '## [0.8.0] - 2026-07-24')
    WriteFile(Root, 'CHANGELOG-beta.md', `# Beta\n\n${BetaEntry}`)
    WriteFile(Root, 'CHANGELOG.md', `# Stable\n\n${StableEntry}\n${BaselineEntry}`)
    WriteFile(Root, 'docs/Upgrading.md', '# Upgrading\n\n## Upgrade from 0.6.5\n\nStable carry-forward.\n')
    const StableRevision = Commit(Root, 'stable on divergent history')
    Git(Root, ['tag', '0.8.0'])

    Assert.throws(
      () => BuildReleaseCandidate({
        workspacePath: Root,
        ref: 'refs/tags/0.8.0',
        revision: StableRevision
      }),
      /latest beta 0\.8\.0-beta\.1 \([0-9a-f]{40}\) is not an ancestor of [0-9a-f]{40}/
    )
  } finally {
    RemoveWorkspace(Root)
  }
})

test('requires a substantive candidate section for each changed compatibility surface', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    WriteFile(Root, 'source/src/config/example.rs', 'pub const VALUE: u8 = 1;\n')
    Commit(Root, 'baseline')
    Git(Root, ['tag', '0.6.5'])
    const Entry = GovernedEntry()
      .replace(
        '- Add a person-reviewed configuration compatibility statement.',
        '- No changes for this release.'
      )
      .replace(
        '### Security\n\n- No changes for this release.',
        '### Security\n\n- Preserve the existing release validation boundary.'
      )
    WriteFile(Root, 'CHANGELOG.md', `# Stable\n\n${Entry}\n${BaselineEntry}`)
    WriteFile(Root, 'source/src/config/example.rs', 'pub const VALUE: u8 = 2;\n')
    const Revision = Commit(Root, 'release with config change')
    Git(Root, ['tag', '0.7.0'])

    Assert.throws(
      () => BuildReleaseCandidate({
        workspacePath: Root,
        ref: 'refs/tags/0.7.0',
        revision: Revision
      }),
      /changes the Configuration compatibility surface but marks that section unchanged/
    )
  } finally {
    RemoveWorkspace(Root)
  }
})

test('requires a substantive candidate section for deleted compatibility surfaces', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    WriteFile(Root, 'source/src/config/example.rs', 'pub const VALUE: u8 = 1;\n')
    Commit(Root, 'baseline')
    Git(Root, ['tag', '0.6.5'])
    const PlaceholderEntry = GovernedEntry()
      .replace(
        '- Add a person-reviewed configuration compatibility statement.',
        '- No changes for this release.'
      )
      .replace(
        '### Security\n\n- No changes for this release.',
        '### Security\n\n- Preserve the existing release validation boundary.'
      )
    WriteFile(Root, 'CHANGELOG.md', `# Stable\n\n${PlaceholderEntry}\n${BaselineEntry}`)
    Fs.rmSync(Path.join(Root, 'source/src/config/example.rs'))
    const DeletedRevision = Commit(Root, 'release with config deletion')
    Git(Root, ['tag', '0.7.0'])

    Assert.throws(
      () => BuildReleaseCandidate({
        workspacePath: Root,
        ref: 'refs/tags/0.7.0',
        revision: DeletedRevision
      }),
      /changes the Configuration compatibility surface but marks that section unchanged/
    )

    WriteFile(Root, 'CHANGELOG.md', `# Stable\n\n${GovernedEntry()}\n${BaselineEntry}`)
    const DocumentedRevision = Commit(Root, 'document config deletion')
    Git(Root, ['tag', '--force', '0.7.0', DocumentedRevision])
    const Result = BuildReleaseCandidate({
      workspacePath: Root,
      ref: 'refs/tags/0.7.0',
      revision: DocumentedRevision
    })
    Assert.equal(Result.receipt.revision, DocumentedRevision)
  } finally {
    RemoveWorkspace(Root)
  }
})

test('build tags produce no changelog body or GitHub Release metadata', () => {
  const Root = CreateContractWorkspace()
  try {
    Git(Root, ['init', '-q'])
    const Revision = CommitBuildTagRevision(Root)
    const Tag = `0.7.0-build.${Revision.slice(0, 8)}`
    Git(Root, ['tag', Tag])
    const Result = BuildReleaseCandidate({
      workspacePath: Root,
      ref: `refs/tags/${Tag}`,
      revision: Revision
    })
    Assert.equal(Result.receipt.kind, 'build')
    Assert.equal(Result.receipt.ledgerPath, null)
    Assert.equal(Result.receipt.bodySha256, null)
    Assert.equal(Result.body, '')
  } finally {
    RemoveWorkspace(Root)
  }
})

test('verifies draft and published GitHub release state without normalizing content changes', () => {
  const Body = '# OxiBelt 0.7.0\n\nPerson-reviewed notes.\n'
  const Receipt: ReleaseContractReceipt = {
    schemaVersion: 1,
    kind: 'stable',
    version: '0.7.0',
    ref: 'refs/tags/0.7.0',
    revision: '2222222222222222222222222222222222222222',
    baseVersion: '0.6.5',
    baseRevision: BaselineRevision,
    supportedUpgradeSources: ['0.6.5'],
    ledgerPath: 'CHANGELOG.md',
    entrySha256: '3'.repeat(64),
    bodySha256: Crypto.createHash('sha256').update(Body, 'utf8').digest('hex')
  }

  VerifyGitHubRelease({
    receipt: Receipt,
    release: {
      tag_name: '0.7.0',
      name: '0.7.0',
      body: Body.replace(/\n/g, '\r\n'),
      draft: true,
      prerelease: false
    },
    expectedState: 'draft',
    expectedBody: Body
  })
  Assert.throws(
    () => VerifyGitHubRelease({
      receipt: Receipt,
      release: {
        tag_name: '0.7.0',
        name: '0.7.0',
        body: `${Body}edited`,
        draft: true,
        prerelease: false
      },
      expectedState: 'draft',
      expectedBody: Body
    }),
    /body differs/
  )
  Assert.throws(
    () => VerifyGitHubRelease({
      receipt: Receipt,
      release: {
        tag_name: '0.7.0',
        name: '0.7.0',
        body: Body,
        draft: false,
        prerelease: false
      },
      expectedState: 'draft',
      expectedBody: Body
    }),
    /draft state/
  )

  const BetaReceipt: ReleaseContractReceipt = {
    ...Receipt,
    kind: 'beta',
    version: '0.7.0-beta.1',
    ref: 'refs/tags/0.7.0-beta.1',
    ledgerPath: 'CHANGELOG-beta.md'
  }
  VerifyGitHubRelease({
    receipt: BetaReceipt,
    release: {
      tag_name: '0.7.0-beta.1',
      name: '0.7.0-beta.1',
      body: Body,
      draft: false,
      prerelease: true
    },
    expectedState: 'published',
    expectedBody: Body
  })
})
