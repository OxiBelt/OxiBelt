const Session = '__SESSION_JS__'
const SessionPath = '__SESSION_PATH_JS__'
const VerifyPath = '__VERIFY_PATH_JS__'
const ReturnPath = '__RETURN_PATH_JS__'
const EmbeddedDifficulty = Number('__DIFFICULTY__')
const Encoder = new TextEncoder()

type SessionDocument = {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  session: string
  // eslint-disable-next-line @typescript-eslint/naming-convention
  method: string
  // eslint-disable-next-line @typescript-eslint/naming-convention
  expires_unix_ms: number
  // eslint-disable-next-line @typescript-eslint/naming-convention
  return_path: string
  // eslint-disable-next-line @typescript-eslint/naming-convention
  verify_path: string
  // eslint-disable-next-line @typescript-eslint/naming-convention
  challenge: {
    // eslint-disable-next-line @typescript-eslint/naming-convention
    kind: string
    // eslint-disable-next-line @typescript-eslint/naming-convention
    difficulty?: number
    // eslint-disable-next-line @typescript-eslint/naming-convention
    token?: string
  }
}

const StatusElement = document.querySelector<HTMLElement>('[data-status]')

const SetStatus = (Message: string): void => {
  if (StatusElement) {
    StatusElement.textContent = Message
  }
}

const CountLeadingZeroBits = (Bytes: Uint8Array): number => {
  let Total = 0

  for (const Byte of Bytes) {
    if (Byte === 0) {
      Total += 8
      continue
    }

    for (let Bit = 7; Bit >= 0; Bit -= 1) {
      if ((Byte & (1 << Bit)) === 0) {
        Total += 1
      } else {
        return Total
      }
    }
  }

  return Total
}

const YieldToBrowser = async (): Promise<void> => {
  await new Promise((Resolve) => setTimeout(Resolve, 0))
}

const GetJson = async <T>(Path: string): Promise<T> => {
  const Url = new URL(Path, window.location.origin)
  Url.searchParams.set('session', Session)
  const Response = await fetch(Url, {
    cache: 'no-store',
    credentials: 'same-origin',
    headers: { accept: 'application/json' },
  })

  if (!Response.ok) {
    throw new Error(`session endpoint returned ${Response.status}`)
  }

  return (await Response.json()) as T
}

const WorkerSource = String.raw`
const Encoder = new TextEncoder()
const CountLeadingZeroBits = (Bytes) => {
  let Total = 0
  for (const Byte of Bytes) {
    if (Byte === 0) {
      Total += 8
      continue
    }
    for (let Bit = 7; Bit >= 0; Bit -= 1) {
      if ((Byte & (1 << Bit)) === 0) {
        Total += 1
      } else {
        return Total
      }
    }
  }
  return Total
}
self.onmessage = async (Event) => {
  const { token, difficulty, start, step } = Event.data
  if (!globalThis.crypto?.subtle) {
    self.postMessage({ type: 'error', error: 'Web Crypto is unavailable' })
    return
  }
  for (let Nonce = start; ; Nonce += step) {
    const Hash = await crypto.subtle.digest('SHA-256', Encoder.encode(token + '.' + Nonce))
    if (CountLeadingZeroBits(new Uint8Array(Hash)) >= difficulty) {
      self.postMessage({ type: 'found', nonce: Nonce })
      return
    }
  }
}
`

const SolveWithWorkers = async (Token: string, Difficulty: number): Promise<number | undefined> => {
  if (typeof Worker === 'undefined' || typeof Blob === 'undefined' || !globalThis.crypto?.subtle) {
    return undefined
  }

  const WorkerCount = Math.min(Math.max(1, Math.floor((navigator.hardwareConcurrency || 2) / 2)), 4)
  const BlobUrl = URL.createObjectURL(new Blob([WorkerSource], { type: 'text/javascript' }))
  const Workers: Worker[] = []

  return await new Promise<number | undefined>((Resolve) => {
    let Finished = false
    let Failures = 0

    const Finish = (Nonce: number | undefined): void => {
      if (Finished) {
        return
      }
      Finished = true
      for (const WorkerInstance of Workers) {
        WorkerInstance.terminate()
      }
      URL.revokeObjectURL(BlobUrl)
      Resolve(Nonce)
    }

    for (let Index = 0; Index < WorkerCount; Index += 1) {
      const WorkerInstance = new Worker(BlobUrl)
      Workers.push(WorkerInstance)
      WorkerInstance.onmessage = (Event: MessageEvent<{ type: string; nonce?: number }>) => {
        if (Event.data.type === 'found' && typeof Event.data.nonce === 'number') {
          Finish(Event.data.nonce)
        } else {
          Failures += 1
          if (Failures === WorkerCount) {
            Finish(undefined)
          }
        }
      }
      WorkerInstance.onerror = () => {
        Failures += 1
        if (Failures === WorkerCount) {
          Finish(undefined)
        }
      }
      WorkerInstance.postMessage({
        token: Token,
        difficulty: Difficulty,
        start: Index,
        step: WorkerCount,
      })
    }
  })
}

const SolveOnMainThread = async (Token: string, Difficulty: number): Promise<number> => {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto is unavailable')
  }

  for (let Nonce = 0; ; Nonce += 1) {
    const Hash = await crypto.subtle.digest('SHA-256', Encoder.encode(`${Token}.${Nonce}`))

    if (CountLeadingZeroBits(new Uint8Array(Hash)) >= Difficulty) {
      return Nonce
    }

    if (Nonce % 512 === 0) {
      await YieldToBrowser()
    }
  }
}

const SubmitProof = async (SessionToken: string, Nonce: number): Promise<string> => {
  const Response = await fetch(VerifyPath, {
    method: 'POST',
    cache: 'no-store',
    credentials: 'same-origin',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      session: SessionToken,
      response: {
        token: String(Nonce),
        fields: {},
      },
    }),
  })

  if (!Response.ok) {
    throw new Error(`verify endpoint returned ${Response.status}`)
  }

  const Body = (await Response.json()) as { return_path?: string }
  return Body.return_path || ReturnPath || '/'
}

const SafeOriginRelativePath = (Path: string): string => {
  if (Path.startsWith('/') && !Path.startsWith('//')) {
    return Path
  }
  return '/'
}

const SolveChallenge = async (): Promise<void> => {
  SetStatus('Preparing challenge...')
  const Document = await GetJson<SessionDocument>(SessionPath)
  if (Document.challenge.kind !== 'pow_sha256_v1') {
    throw new Error(`unsupported challenge kind ${Document.challenge.kind}`)
  }

  const Token = Document.challenge.token || Document.session || Session
  const Difficulty = Document.challenge.difficulty ?? EmbeddedDifficulty
  SetStatus('Solving proof-of-work...')
  const WorkerNonce = await SolveWithWorkers(Token, Difficulty)
  const Nonce = WorkerNonce ?? (await SolveOnMainThread(Token, Difficulty))

  SetStatus('Verifying proof...')
  const NextPath = await SubmitProof(Document.session || Session, Nonce)
  SetStatus('Proof accepted. Continuing...')
  window.location.assign(SafeOriginRelativePath(NextPath))
}

void SolveChallenge().catch((ErrorValue: unknown) => {
  const Message = ErrorValue instanceof Error ? ErrorValue.message : 'unknown error'
  SetStatus(`Challenge failed: ${Message}`)
})
