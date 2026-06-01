#!/usr/bin/env node
import { readFileSync } from 'node:fs'
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
const BuiltScriptUrl = new URL('../../ui/person-proof/dist/challenge.js', import.meta.url)
const Html = readFileSync(ChallengeAssetUrl, 'utf8')
const BuiltChallengeScript = readFileSync(BuiltScriptUrl, 'utf8')
const ScriptMatch = Html.match(
  /<script type="module" nonce="__CSP_NONCE__">\n([\s\S]*?)\n<\/script>/u,
)

if (!ScriptMatch) {
  throw new Error('failed to locate person proof challenge module script')
}

const EscapeClosingScript = (ScriptText: string): string => ScriptText.replaceAll('</script', '<\\/script')
const EmbeddedChallengeScript = ScriptMatch[1]

if (EmbeddedChallengeScript !== EscapeClosingScript(BuiltChallengeScript)) {
  throw new Error('person proof challenge HTML does not match the built challenge module')
}

const ChallengeScript = BuiltChallengeScript.replace(/export \{\};\s*$/u, '')

type SandboxContext = vm.Context & {
  __OXIBELT_ESCAPE_RESULT__?: string
  __OXIBELT_IMPORT_RESULT__?: string
  __OXIBELT_PROCESS_TYPE__?: string
}

const CreateSandboxContext = (): SandboxContext => {
  const Context = Object.create(null) as SandboxContext
  vm.createContext(Context)
  return Context
}

const WaitFor = async (Predicate: () => boolean): Promise<void> => {
  for (let Attempt = 0; Attempt < 100; Attempt += 1) {
    if (Predicate()) {
      return
    }
    await new Promise((Resolve) => setTimeout(Resolve, 10))
  }
  throw new Error('timed out waiting for challenge script')
}

const RunInSandbox = (Context: SandboxContext, Script: string): unknown =>
  vm.runInContext(Script, Context, { displayErrors: true, timeout: 1_000 })

const BuildChallengeHarness = ({ mode, kind }: ChallengeOptions): string => `
'use strict';
{
  const Calls = [];
  const Redirects = [];
  const Status = { textContent: '' };
  const Storage = new Map();
  const Mode = ${JSON.stringify(mode)};
  const Kind = ${JSON.stringify(kind)};
  const SetGlobal = (Name, Value) => {
    Object.defineProperty(globalThis, Name, {
      configurable: true,
      value: Value,
      writable: true,
    });
  };

  class HarnessUrlSearchParams {
    constructor(Owner) {
      this.Owner = Owner;
    }
    set(Key, Value) {
      const Separator = this.Owner.href.includes('?') ? '&' : '?';
      this.Owner.href += Separator + encodeURIComponent(String(Key)) + '=' + encodeURIComponent(String(Value));
    }
  }

  class HarnessUrl {
    constructor(Path, Origin = '') {
      const Text = String(Path);
      if (/^[a-z][a-z0-9+.-]*:/i.test(Text)) {
        this.href = Text;
      } else {
        const Base = String(Origin || '').replace(/\\/$/u, '');
        const Suffix = Text.startsWith('/') ? Text : '/' + Text;
        this.href = Base + Suffix;
      }
      this.searchParams = new HarnessUrlSearchParams(this);
    }
    toString() {
      return this.href;
    }
  }

  class HarnessTextEncoder {
    encode(Value) {
      const Text = String(Value);
      const Bytes = new Uint8Array(Text.length);
      for (let Index = 0; Index < Text.length; Index += 1) {
        Bytes[Index] = Text.charCodeAt(Index) & 0xff;
      }
      return Bytes;
    }
  }

  SetGlobal('Blob', undefined);
  SetGlobal('Worker', undefined);
  SetGlobal('URL', HarnessUrl);
  SetGlobal('TextEncoder', HarnessTextEncoder);
  SetGlobal('crypto', {
    subtle: {
      digest: async () => new ArrayBuffer(32),
    },
  });
  SetGlobal('document', {
    querySelector: (Selector) => (Selector === '[data-status]' ? Status : null),
  });
  SetGlobal('fetch', async (Url, Init = {}) => {
    const Method = Init.method || 'GET';
    Calls.push({ method: Method, url: String(Url), body: Init.body });

    if (Method === 'POST') {
      return {
        ok: true,
        json: async () => ({ return_path: '/protected' }),
      };
    }

    return {
      ok: true,
      json: async () => ({
        session: 'session-token',
        person_proof_mode: Mode,
        expires_unix_ms: Date.now() + 60_000,
        return_path: '/protected',
        verify_path: '/.oxibelt/person-proof/verify',
        challenge: {
          kind: Kind,
          difficulty: 0,
          token: 'session-token',
        },
      }),
    };
  });
  SetGlobal('localStorage', {
    setItem: (Key, Value) => Storage.set(String(Key), String(Value)),
  });
  SetGlobal('navigator', { hardwareConcurrency: 0 });
  SetGlobal('window', {
    location: {
      origin: 'https://example.test',
      assign: (Path) => Redirects.push(String(Path)),
    },
  });
  SetGlobal('__OXIBELT_RESULT__', { calls: Calls, redirects: Redirects, status: Status });
}
`

const ChallengeFinished = (Context: SandboxContext): boolean =>
  RunInSandbox(
    Context,
    `
Boolean(
  globalThis.__OXIBELT_RESULT__ &&
  (
    globalThis.__OXIBELT_RESULT__.status.textContent.startsWith('Challenge failed:') ||
    globalThis.__OXIBELT_RESULT__.redirects.length > 0
  )
)
`,
  ) === true

const ReadChallengeResult = (Context: SandboxContext): ChallengeResult => {
  const SerializedResult = RunInSandbox(
    Context,
    `
JSON.stringify({
  calls: globalThis.__OXIBELT_RESULT__.calls.map((Call) => ({
    method: String(Call.method),
    url: String(Call.url),
    body: Call.body,
  })),
  redirects: globalThis.__OXIBELT_RESULT__.redirects.map((Path) => String(Path)),
  status: String(globalThis.__OXIBELT_RESULT__.status.textContent),
})
`,
  )

  if (typeof SerializedResult !== 'string') {
    throw new Error('failed to read challenge result from sandbox')
  }

  return JSON.parse(SerializedResult) as ChallengeResult
}

const RunChallenge = async ({ mode, kind }: ChallengeOptions): Promise<ChallengeResult> => {
  const Context = CreateSandboxContext()
  RunInSandbox(Context, BuildChallengeHarness({ mode, kind }))
  RunInSandbox(Context, ChallengeScript)
  await WaitFor(() => ChallengeFinished(Context))
  return ReadChallengeResult(Context)
}

const Assert = (Condition: boolean, Message: string): void => {
  if (!Condition) {
    throw new Error(Message)
  }
}

const AssertSandboxBlocksNodeAccess = async (): Promise<void> => {
  const Context = CreateSandboxContext()
  RunInSandbox(
    Context,
    `
'use strict';
globalThis.__OXIBELT_PROCESS_TYPE__ = typeof process;
try {
  globalThis.__OXIBELT_ESCAPE_RESULT__ = typeof globalThis.constructor?.constructor?.('return process')?.();
} catch (ErrorValue) {
  globalThis.__OXIBELT_ESCAPE_RESULT__ = ErrorValue?.name || 'blocked';
}
globalThis.__OXIBELT_IMPORT_RESULT__ = 'pending';
import('node:fs').then(
  () => {
    globalThis.__OXIBELT_IMPORT_RESULT__ = 'loaded';
  },
  (ErrorValue) => {
    globalThis.__OXIBELT_IMPORT_RESULT__ = ErrorValue?.code || ErrorValue?.name || 'rejected';
  },
);
`,
  )
  await WaitFor(() => Context.__OXIBELT_IMPORT_RESULT__ !== 'pending')
  Assert(
    Context.__OXIBELT_PROCESS_TYPE__ === 'undefined',
    `sandbox exposed process as ${Context.__OXIBELT_PROCESS_TYPE__}`,
  )
  Assert(
    Context.__OXIBELT_ESCAPE_RESULT__ !== 'object' && Context.__OXIBELT_ESCAPE_RESULT__ !== 'function',
    'sandbox allowed constructor access to process',
  )
  Assert(
    Context.__OXIBELT_IMPORT_RESULT__ !== 'loaded',
    'sandbox allowed dynamic import of node:fs',
  )
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

await AssertSandboxBlocksNodeAccess()
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
