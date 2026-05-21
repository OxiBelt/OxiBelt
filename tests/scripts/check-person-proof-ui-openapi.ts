#!/usr/bin/env node
import { webcrypto } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { TextEncoder } from 'node:util'
import vm from 'node:vm'

type ChallengeKind = 'pow_sha256_v1' | 'third_party_provider'

type ChallengeOptions = {
  mode: string
  kind: ChallengeKind
}

type FetchCall = {
  method: string
  url: string
  body: unknown
}

type ChallengeResult = {
  calls: FetchCall[]
  redirects: string[]
  status: string
}

const ChallengeAssetUrl = new URL('../../source/assets/person-proof-challenge.html', import.meta.url)
const Html = readFileSync(ChallengeAssetUrl, 'utf8')
const ScriptMatch = Html.match(
  /<script type="module" nonce="__CSP_NONCE__">\n([\s\S]*?)\n<\/script>/u,
)

if (!ScriptMatch) {
  throw new Error('failed to locate person proof challenge module script')
}

const ChallengeScript = ScriptMatch[1].replace(/export \{\};\s*$/u, '')

const WaitFor = async (Predicate: () => boolean): Promise<void> => {
  for (let Attempt = 0; Attempt < 100; Attempt += 1) {
    if (Predicate()) {
      return
    }
    await new Promise((Resolve) => setTimeout(Resolve, 10))
  }
  throw new Error('timed out waiting for challenge script')
}

const RunChallenge = async ({ mode, kind }: ChallengeOptions): Promise<ChallengeResult> => {
  const Calls: FetchCall[] = []
  const Redirects: string[] = []
  const Status = { textContent: '' }
  const Storage = new Map<string, string>()

  const Context = {
    Blob: undefined,
    Worker: undefined,
    URL,
    Uint8Array,
    TextEncoder,
    clearTimeout,
    console,
    crypto: webcrypto,
    document: {
      querySelector: (Selector: string) => (Selector === '[data-status]' ? Status : null),
    },
    fetch: async (Url: URL | string, Init: { method?: string; body?: unknown } = {}) => {
      const Method = Init.method || 'GET'
      Calls.push({ method: Method, url: String(Url), body: Init.body })

      if (Method === 'POST') {
        return {
          ok: true,
          json: async () => ({ return_path: '/protected' }),
        }
      }

      return {
        ok: true,
        json: async () => ({
          session: 'session-token',
          person_proof_mode: mode,
          expires_unix_ms: Date.now() + 60_000,
          return_path: '/protected',
          verify_path: '/.oxibelt/person-proof/verify',
          challenge: {
            kind,
            difficulty: 0,
            token: 'session-token',
          },
        }),
      }
    },
    localStorage: {
      setItem: (Key: string, Value: string) => Storage.set(Key, Value),
    },
    navigator: { hardwareConcurrency: 0 },
    setTimeout,
    window: {
      location: {
        origin: 'https://example.test',
        assign: (Path: string) => Redirects.push(Path),
      },
    },
  }

  vm.createContext(Context)
  vm.runInContext(ChallengeScript, Context)
  await WaitFor(() => Status.textContent.startsWith('Challenge failed:') || Redirects.length > 0)

  return { calls: Calls, redirects: Redirects, status: Status.textContent }
}

const Assert = (Condition: boolean, Message: string): void => {
  if (!Condition) {
    throw new Error(Message)
  }
}

const AssertPowModeSucceeds = async (Mode: string): Promise<void> => {
  const Result = await RunChallenge({ mode: Mode, kind: 'pow_sha256_v1' })
  Assert(
    Result.status === 'Proof accepted. Continuing...',
    `${Mode} PoW challenge did not report success: ${Result.status}`,
  )
  Assert(
    Result.calls.some((Call) => Call.method === 'POST'),
    `${Mode} PoW challenge did not submit verification`,
  )
  Assert(
    Result.redirects.length === 1 && Result.redirects[0] === '/protected',
    `${Mode} PoW challenge did not redirect to the protected path`,
  )
}

await AssertPowModeSucceeds('built_in')
await AssertPowModeSucceeds('openapi')

const ProviderResult = await RunChallenge({
  mode: 'third_party_provider',
  kind: 'third_party_provider',
})
Assert(
  ProviderResult.status === 'Challenge failed: unsupported challenge kind third_party_provider',
  `provider challenge failed with an unexpected status: ${ProviderResult.status}`,
)
Assert(
  !ProviderResult.calls.some((Call) => Call.method === 'POST'),
  'provider challenge unexpectedly submitted verification through the PoW UI',
)

console.log('person proof UI accepts built_in/openapi PoW and rejects provider challenges')
