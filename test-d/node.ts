// Checks the package against Node.js WebCrypto types without the DOM library.
import type { webcrypto } from 'node:crypto'

import * as PASETO from 'paseto'
import { LocalKeyToCryptoKey, type LocalKey } from 'paseto/v3/local'
import {
  PublicKeyFromCryptoKey,
  PublicKeyToCryptoKey,
  SecretKeyToCryptoKey,
  type PublicKey,
  type SecretKey,
} from 'paseto/v4/public'

type Equals<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never

const _isNodeCryptoKey: Equals<PASETO.CryptoKey, webcrypto.CryptoKey> = true

declare const localKey: LocalKey
declare const publicKey: PublicKey
declare const secretKey: SecretKey

const _localCryptoKey: webcrypto.CryptoKey = LocalKeyToCryptoKey(localKey)
const _publicCryptoKey: webcrypto.CryptoKey = PublicKeyToCryptoKey(publicKey)
const _secretCryptoKey: webcrypto.CryptoKey = SecretKeyToCryptoKey(secretKey)

async function nodeCryptoKeyInput(key: webcrypto.CryptoKey) {
  const _publicKey: PublicKey = await PublicKeyFromCryptoKey(key)
}
