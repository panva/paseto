import assert from 'node:assert/strict'
import { test } from 'node:test'

import { InvalidKeyError, KDF_ARGON2ID, UnsupportedAlgorithmError } from '../index.ts'
import { digest, importEd25519PublicKey, importRsaPublicKey } from '../_internal/crypto.ts'
import { mockSubtle } from './helpers/subtle.ts'

type ImportKey = SubtleCrypto['importKey']
type Digest = SubtleCrypto['digest']

async function mockImportKey(
  algorithm: string,
  cause: Error,
  operation: () => Promise<unknown>,
): Promise<void> {
  const original: ImportKey = crypto.subtle.importKey
  const restore = mockSubtle({
    importKey: async function (this: SubtleCrypto, ...args: unknown[]): Promise<CryptoKey> {
      const identifier = args[2]
      const name = typeof identifier === 'string' ? identifier : (identifier as Algorithm).name
      if (name === algorithm) throw cause
      return (await Reflect.apply(original, this, args)) as CryptoKey
    },
  })
  try {
    await operation()
  } finally {
    restore()
  }
}

async function mockDigest(cause: Error, operation: () => Promise<unknown>): Promise<void> {
  const original: Digest = crypto.subtle.digest
  const restore = mockSubtle({
    digest: async function (this: SubtleCrypto, ...args: unknown[]): Promise<ArrayBuffer> {
      if (args[0] === 'SHA-384') throw cause
      return (await Reflect.apply(original, this, args)) as ArrayBuffer
    },
  })
  try {
    await operation()
  } finally {
    restore()
  }
}

function isUnavailable(cause: Error): (error: unknown) => boolean {
  return (error) => {
    assert(error instanceof UnsupportedAlgorithmError)
    assert.equal(error.code, 'ERR_PASETO_UNSUPPORTED_ALGORITHM')
    assert.match(error.message, /is not available from the Web Cryptography runtime API/u)
    assert.equal(error.cause, cause)
    return true
  }
}

test('missing Web Cryptography algorithms have a consistent library error', async (t) => {
  await t.test('direct operations', async () => {
    const cause = new DOMException('Algorithm is unavailable', 'NotSupportedError')
    await mockDigest(cause, async () => {
      await assert.rejects(digest('SHA-384', new Uint8Array()), isUnavailable(cause))
    })
  })

  await t.test('RSA key operations', async () => {
    const cause = new DOMException('Algorithm is unavailable', 'NotSupportedError')
    await mockImportKey('RSA-PSS', cause, async () => {
      await assert.rejects(importRsaPublicKey(Uint8Array.of(0)), isUnavailable(cause))
    })
  })

  await t.test('Ed25519 key operations', async () => {
    const cause = new DOMException('Algorithm is unavailable', 'NotSupportedError')
    await mockImportKey('Ed25519', cause, async () => {
      await assert.rejects(importEd25519PublicKey(4, new Uint8Array(32)), isUnavailable(cause))
    })
  })

  await t.test('Argon2id', async () => {
    const cause = new DOMException('Algorithm is unavailable', 'NotSupportedError')
    await mockImportKey('Argon2id', cause, async () => {
      await assert.rejects(
        KDF_ARGON2ID().Derive(new Uint8Array(), new Uint8Array(16), {
          memory: 8 * 1024,
          passes: 1,
          parallelism: 1,
          length: 32,
        }),
        isUnavailable(cause),
      )
    })
  })
})

test('invalid key data is not reported as an unavailable algorithm', async () => {
  const cause = new DOMException('The key data is invalid', 'DataError')
  await mockImportKey('Ed25519', cause, async () => {
    await assert.rejects(importEd25519PublicKey(4, new Uint8Array(32)), (error) => {
      assert(error instanceof InvalidKeyError)
      assert.equal(error.cause, cause)
      return true
    })
  })
})
