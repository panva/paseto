// Selects the CryptoKey structural fallback by compiling without DOM or Node ambient types.
import * as PASETO from 'paseto'
import { LocalKeyFromCryptoKey, LocalKeyToCryptoKey, type LocalKey } from 'paseto/v3/local'
import {
  PublicKeyFromCryptoKey,
  PublicKeyToCryptoKey,
  SecretKeyFromCryptoKey,
  SecretKeyToCryptoKey,
  type PublicKey,
  type SecretKey,
} from 'paseto/v4/public'

declare global {
  abstract class CryptoKey {
    readonly type: string
    readonly extractable: boolean
    readonly algorithm: { name: string }
    readonly usages: string[]
  }

  interface SubtleCrypto {
    generateKey(algorithm: string, extractable: boolean, keyUsages: string[]): Promise<CryptoKey>
  }

  interface Crypto {
    readonly subtle: SubtleCrypto
  }

  const crypto: Crypto
}

type Equals<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never

const _algorithm: Equals<PASETO.CryptoKey['algorithm'], { readonly name: string }> = true
const _extractable: Equals<PASETO.CryptoKey['extractable'], boolean> = true
const _type: Equals<PASETO.CryptoKey['type'], string> = true
const _usages: Equals<PASETO.CryptoKey['usages'], string[]> = true

// @ts-expect-error the fallback must not degrade to any
const _notAny: PASETO.CryptoKey = 'definitely not a key'

declare const key: CryptoKey
declare const pasetoKey: PASETO.CryptoKey
declare const localKey: LocalKey
declare const publicKey: PublicKey
declare const secretKey: SecretKey

const _pasetoKey: PASETO.CryptoKey = key
const _hostKey: CryptoKey = pasetoKey
const _hostLocalKey: CryptoKey = LocalKeyToCryptoKey(localKey)
const _hostPublicKey: CryptoKey = PublicKeyToCryptoKey(publicKey)
const _hostSecretKey: CryptoKey = SecretKeyToCryptoKey(secretKey)
const _localKey: LocalKey = LocalKeyFromCryptoKey(key)

async function fallbackKeys() {
  const _publicKey: PublicKey = await PublicKeyFromCryptoKey(key)
  const _secretKey: SecretKey = await SecretKeyFromCryptoKey(key)
}
