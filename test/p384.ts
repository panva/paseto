import assert from 'node:assert/strict'
import { test } from 'node:test'
import * as api from '../_internal/crypto.ts'
import { SecretKeyToCryptoKey } from '../v3/public.ts'
// @ts-expect-error Shared browser test logic.
import { checkP384Keys, fromHex } from './p384-keys.js'
import fixture from './p384-fixtures.json' with { type: 'json' }
import { mockSubtle } from './helpers/subtle.ts'

test('P-384 native recovery and decompression match reference points', async () => {
  await checkP384Keys(api, SecretKeyToCryptoKey)
})

test('P-384 recovery when scalar-only PKCS8 coordinates cannot be exported', async () => {
  const c = crypto.subtle
  const importKey = c.importKey
  const exportKey = c.exportKey
  const imported = new WeakSet<CryptoKey>()
  let recoveries = 0
  const restore = mockSubtle({
    getPublicKey: undefined,
    importKey: async (...args: unknown[]) => {
      const key = (await Reflect.apply(importKey, c, args)) as CryptoKey
      if (args[0] === 'pkcs8') imported.add(key)
      return key
    },
    exportKey: async (...args: unknown[]) => {
      if (args[0] === 'jwk' && imported.has(args[1] as CryptoKey)) {
        recoveries++
        throw new DOMException('Public coordinates unavailable', 'OperationError')
      }
      return Reflect.apply(exportKey, c, args)
    },
  })
  try {
    await checkP384Keys(api, SecretKeyToCryptoKey)
    assert.ok(recoveries > 0)
  } finally {
    restore()
  }
})

test('P-384 recovery propagates unexpected import failures without retrying', async () => {
  const cause = new Error('Unexpected import failure')
  let calls = 0
  const restore = mockSubtle({
    importKey: async () => {
      calls++
      throw cause
    },
  })
  try {
    await assert.rejects(
      api.importP384SecretKey(fromHex(fixture.keys[0]!.privateKey), false),
      (error) => error === cause,
    )
    assert.equal(calls, 1)
  } finally {
    restore()
  }
})

test('P-384 native public-key extraction retains the original private key', async (t) => {
  // @ts-expect-error getPublicKey is not yet declared in every Web Crypto lib.
  if (typeof crypto.subtle.getPublicKey !== 'function') return t.skip('getPublicKey unavailable')
  const c = crypto.subtle
  const importKey = c.importKey
  const imported: CryptoKey[] = []
  const restore = mockSubtle({
    importKey: async (...args: unknown[]) => {
      const key = (await Reflect.apply(importKey, c, args)) as CryptoKey
      imported.push(key)
      return key
    },
  })
  try {
    for (const extractable of [false, true]) {
      imported.length = 0
      const scalar = Buffer.from(fixture.keys[0]!.privateKey, 'hex')
      const importing = api.importP384SecretKey(scalar, extractable)
      scalar.fill(0)
      const key = SecretKeyToCryptoKey(await importing)
      assert.equal(imported.length, 1)
      assert.equal(key, imported[0])
      assert.equal(key.extractable, extractable)
    }
  } finally {
    restore()
  }
})
