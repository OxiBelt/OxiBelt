const Token = '__TOKEN_JS__'
const CookieName = '__COOKIE_JS__'
const Difficulty = Number('__DIFFICULTY__')
const MaxAge = Number('__TTL_SECONDS__')
const Encoder = new TextEncoder()

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

const SolveChallenge = async (): Promise<void> => {
  for (let Nonce = 0; ; Nonce += 1) {
    const Hash = await crypto.subtle.digest('SHA-256', Encoder.encode(`${Token}.${Nonce}`))

    if (CountLeadingZeroBits(new Uint8Array(Hash)) >= Difficulty) {
      document.cookie = `${CookieName}=${Token}.${Nonce}; Max-Age=${MaxAge}; Path=/; SameSite=Lax; Secure`
      window.location.reload()
      return
    }

    if (Nonce % 512 === 0) {
      await YieldToBrowser()
    }
  }
}

void SolveChallenge()
