import * as Assert from 'node:assert/strict'
import * as Fs from 'node:fs'
import * as Os from 'node:os'
import * as Path from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { RebuildPredicateSha256 } from '../sources/rebuild_recipe.js'

/* oxlint-disable oxibelt/pascal-case -- Fixtures mirror signed JSON and subprocess options. */

const Root = fileURLToPath(new URL('../../', import.meta.url))
const Revision = 'a'.repeat(40)
const Image = 'ghcr.io/oxibelt/oxibelt-tools'
const Digest = `sha256:${'b'.repeat(64)}`
const Ref = 'refs/tags/1.2.3-beta.1'
const Signer = `https://github.com/OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml@${Ref}`
const Invocation = 'https://github.com/OxiBelt/OxiBelt/actions/runs/123/attempts/2'
const HistoricalInvocation = Invocation.replace('/attempts/2', '/attempts/1')

function Attestation(PredicateType: string, Predicate: unknown, RunInvocation = Invocation): unknown {
  return {
    verificationResult: {
      signature: { certificate: {
        subjectAlternativeName: Signer,
        sourceRepositoryURI: 'https://github.com/OxiBelt/OxiBelt',
        sourceRepositoryRef: Ref,
        sourceRepositoryDigest: Revision,
        buildSignerDigest: Revision,
        runnerEnvironment: 'github-hosted',
        runInvocationURI: RunInvocation
      } },
      verifiedTimestamps: [{}],
      statement: {
        subject: [{ name: Image, digest: { sha256: Digest.slice(7) } }],
        predicateType: PredicateType,
        predicate: Predicate
      }
    }
  }
}

function Run(Scenario: string, Selection: string[] = ['--producer-run-invocation-uri', Invocation]): {
  status: number | null
  stderr: string
  dockerCalls: string
} {
  const Temporary = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-rebuild-script-test-'))
  try {
    const Bin = Path.join(Temporary, 'bin')
    const ScriptDirectory = Path.join(Temporary, 'tests/scripts')
    Fs.mkdirSync(Bin)
    Fs.mkdirSync(ScriptDirectory, { recursive: true })
    Fs.copyFileSync(Path.join(Root, 'tests/scripts/verify-release-rebuild.sh'), Path.join(ScriptDirectory, 'verify-release-rebuild.sh'))
    Fs.cpSync(Path.join(Root, 'devops/sources'), Path.join(Temporary, 'devops/sources'), { recursive: true })
    Fs.copyFileSync(Path.join(Root, 'package.json'), Path.join(Temporary, 'package.json'))
    Fs.symlinkSync(Path.join(Root, 'node_modules'), Path.join(Temporary, 'node_modules'))
    const Stub = `#!/usr/bin/env bash
set -euo pipefail
case "\${0##*/}" in
  git) printf '%s\\n' '${Revision}' ;;
  docker)
    printf '%s\\n' "$*" >> "\${TEST_DOCKER_LOG}"
    if [[ "\${1:-}" == pull ]]; then exit 73; fi
    if [[ "\${1:-}" == image && "\${2:-}" == inspect ]]; then exit 1; fi
    ;;
  gh)
    [[ "$1 $2" == 'attestation verify' ]]
    for required in --signer-digest --source-digest --source-ref --cert-oidc-issuer --deny-self-hosted-runners; do
      [[ " $* " == *" \${required} "* ]]
    done
    case "$*" in
      *https://slsa.dev/provenance/v1*) input=provenance ;;
      *https://cyclonedx.org/bom*) input=sbom ;;
      *https://oxibelt.dev/attestations/rebuild/v1*) input=recipe ;;
      *) exit 91 ;;
    esac
    cat "\${TEST_EVIDENCE}/\${input}.json"
    ;;
  pnpm|trivy) exit 92 ;;
  *) exit 93 ;;
esac
`
    for (const Name of ['gh', 'git', 'docker', 'pnpm', 'trivy']) {
      Fs.writeFileSync(Path.join(Bin, Name), Stub, { mode: 0o700 })
    }
    const Sbom = { bomFormat: 'CycloneDX', metadata: { timestamp: '2026-09-07T00:00:00Z' } }
    const Recipe = {
      schemaVersion: 1,
      predicateType: 'https://oxibelt.dev/attestations/rebuild/v1',
      kind: 'platform',
      subject: { name: Image, digest: Digest },
      source: { revision: Revision, ref: Ref },
      build: { role: 'tools', artifactArch: 'amd64' },
      output: {
        sbomSha256: Scenario === 'sbom-mismatch' ? `sha256:${'c'.repeat(64)}` : RebuildPredicateSha256(Sbom),
        artifactContract: { schema: 3, version: '1.2.3-beta.1', created: '2026-09-07T00:00:00Z', source: 'https://github.com/OxiBelt/OxiBelt' }
      }
    }
    const Provenance = {
      buildDefinition: {
        buildType: 'https://actions.github.io/buildtypes/workflow/v1',
        externalParameters: { workflow: { path: '.github/workflows/release.yml', ref: Ref, repository: 'https://github.com/OxiBelt/OxiBelt' } },
        internalParameters: { github: { runner_environment: 'github-hosted' } },
        resolvedDependencies: [{ uri: `git+https://github.com/OxiBelt/OxiBelt@${Ref}`, digest: { gitCommit: Revision } }]
      },
      runDetails: { builder: { id: Signer } }
    }
    for (const [Name, Type, Predicate] of [
      ['recipe', Recipe.predicateType, Recipe],
      ['sbom', 'https://cyclonedx.org/bom', Sbom],
      ['provenance', 'https://slsa.dev/provenance/v1', Provenance]
    ] as const) {
      const Results = [Attestation(Type, Predicate, Scenario === 'historical-provenance' && Name === 'provenance' ? HistoricalInvocation : Invocation)]
      if (Scenario === 'historical-conflict') Results.push(Attestation(Type, { historical: true }, HistoricalInvocation))
      if (Scenario === 'current-conflict' && Name === 'recipe') Results.push(Attestation(Type, { conflicting: true }))
      Fs.writeFileSync(Path.join(Temporary, `${Name}.json`), JSON.stringify(Results))
    }
    const DockerLog = Path.join(Temporary, 'docker.log')
    const Result = spawnSync('bash', [
      Path.join(ScriptDirectory, 'verify-release-rebuild.sh'),
      '--image', Image, '--digest', Digest, '--revision', Revision,
      '--release-ref', Ref, '--verifier-sha', Revision, '--role', 'tools',
      '--artifact-arch', 'amd64', '--output', Path.join(Temporary, 'receipt.json'), ...Selection
    ], {
      cwd: Root,
      env: { ...process.env, PATH: `${Bin}:${process.env.PATH ?? ''}`, TEST_EVIDENCE: Temporary, TEST_DOCKER_LOG: DockerLog },
      encoding: 'utf8', timeout: 30_000
    })
    if (Result.error !== undefined) throw Result.error
    Assert.equal(Fs.existsSync(Path.join(Temporary, 'receipt.json')), false, 'pre-build checks must not emit a receipt')
    return { status: Result.status, stderr: Result.stderr, dockerCalls: Fs.existsSync(DockerLog) ? Fs.readFileSync(DockerLog, 'utf8') : '' }
  } finally {
    Fs.rmSync(Temporary, { recursive: true, force: true })
  }
}

test('rebuild script selects one producer attempt for every attestation class before pulling', () => {
  for (const [Scenario, Selection] of [
    ['historical-conflict', ['--producer-run-invocation-uri', Invocation]],
    ['unique', []]
  ] as const) {
    const Result = Run(Scenario, [...Selection])
    Assert.equal(Result.status, 73, Result.stderr)
    Assert.match(Result.dockerCalls, /pull --platform linux\/amd64/)
  }
})

test('rebuild script rejects conflicting, historical-only, or mismatched evidence before pulling', () => {
  for (const [Scenario, Selection, ErrorPattern] of [
    ['historical-conflict', [], /conflicting predicates/],
    ['current-conflict', ['--producer-run-invocation-uri', Invocation], /conflicting predicates/],
    ['historical-provenance', ['--producer-run-invocation-uri', Invocation], /no verified attestation/],
    ['sbom-mismatch', ['--producer-run-invocation-uri', Invocation], /selected SBOM digest does not match/],
    ['unique', ['--producer-run-invocation-uri', ''], /canonical GitHub run attempt URI/],
    ['unique', ['--producer-run-invocation-uri', Invocation, '--producer-run-invocation-uri', Invocation], /usage:/]
  ] as const) {
    const Result = Run(Scenario, [...Selection])
    Assert.notEqual(Result.status, 0)
    Assert.match(Result.stderr, ErrorPattern)
    Assert.doesNotMatch(Result.dockerCalls, /pull /)
  }
})
