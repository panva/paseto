import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import {
  InvalidKeyError,
  LocalProtocol,
  PublicProtocol,
  UnsupportedAlgorithmError,
  type CryptoKey,
  type Key,
} from '../index.ts'
import * as V1Local from '../v1/local.ts'
import * as V1Public from '../v1/public.ts'
import * as V2Public from '../v2/public.ts'
import * as V3Local from '../v3/local.ts'
import * as V3Public from '../v3/public.ts'
import * as V4Public from '../v4/public.ts'

const tokenProduceOptions = { addIssuedAt: false, nonExpiring: true } as const
const tokenConsumeOptions = { allowNonExpiring: true } as const

interface LocalAdapter {
  readonly name: string
  readonly FromCryptoKey: (key: CryptoKey) => Key
  readonly ToCryptoKey: (key: Key) => CryptoKey
  readonly Encrypt: (key: Key, claims: object) => Promise<string>
  readonly Decrypt: (key: Key, token: string) => Promise<{ claims: Record<string, unknown> }>
  readonly ExportKey: (key: Key) => Promise<string>
}

interface PublicAdapter {
  readonly name: string
  readonly generate: (extractable: boolean) => Promise<CryptoKeyPair>
  readonly acceptsNonExtractablePublicKey: boolean
  readonly PublicKeyFromCryptoKey: (key: CryptoKey) => Key | Promise<Key>
  readonly PublicKeyToCryptoKey: (key: Key) => CryptoKey
  readonly FromCryptoKey: (key: CryptoKey) => Promise<Key>
  readonly ToCryptoKey: (key: Key) => CryptoKey
  readonly Sign: (key: Key, claims: object) => Promise<string>
  readonly Verify: (key: Key, token: string) => Promise<{ claims: Record<string, unknown> }>
  readonly GetPublicKey: (key: Key) => Promise<Key>
  readonly ExportSecretKey: (key: Key) => Promise<string>
}

function localAdapters(): LocalAdapter[] {
  const v1 = new LocalProtocol(
    V1Local.EncryptFactory,
    V1Local.DecryptFactory,
    V1Local.ExportKeyFactory,
  )
  const v3 = new LocalProtocol(
    V3Local.EncryptFactory,
    V3Local.DecryptFactory,
    V3Local.ExportKeyFactory,
  )

  return [
    {
      name: 'v1.local',
      FromCryptoKey: V1Local.LocalKeyFromCryptoKey,
      ToCryptoKey: (key) => V1Local.LocalKeyToCryptoKey(key as V1Local.LocalKey),
      Encrypt: (key, claims) => v1.Encrypt(key as V1Local.LocalKey, claims, tokenProduceOptions),
      Decrypt: (key, token) => v1.Decrypt(key as V1Local.LocalKey, token, tokenConsumeOptions),
      ExportKey: (key) => v1.ExportKey(key as V1Local.LocalKey),
    },
    {
      name: 'v3.local',
      FromCryptoKey: V3Local.LocalKeyFromCryptoKey,
      ToCryptoKey: (key) => V3Local.LocalKeyToCryptoKey(key as V3Local.LocalKey),
      Encrypt: (key, claims) => v3.Encrypt(key as V3Local.LocalKey, claims, tokenProduceOptions),
      Decrypt: (key, token) => v3.Decrypt(key as V3Local.LocalKey, token, tokenConsumeOptions),
      ExportKey: (key) => v3.ExportKey(key as V3Local.LocalKey),
    },
  ]
}

function publicAdapters(): PublicAdapter[] {
  const v1 = new PublicProtocol(
    V1Public.SignFactory,
    V1Public.VerifyFactory,
    V1Public.GetPublicKeyFactory,
    V1Public.ExportSecretKeyFactory,
  )
  const v2 = new PublicProtocol(
    V2Public.SignFactory,
    V2Public.VerifyFactory,
    V2Public.GetPublicKeyFactory,
    V2Public.ExportSecretKeyFactory,
  )
  const v3 = new PublicProtocol(
    V3Public.SignFactory,
    V3Public.VerifyFactory,
    V3Public.GetPublicKeyFactory,
    V3Public.ExportSecretKeyFactory,
  )
  const v4 = new PublicProtocol(
    V4Public.SignFactory,
    V4Public.VerifyFactory,
    V4Public.GetPublicKeyFactory,
    V4Public.ExportSecretKeyFactory,
  )

  return [
    {
      name: 'v1.public',
      acceptsNonExtractablePublicKey: true,
      generate: async (extractable) =>
        (await crypto.subtle.generateKey(
          {
            name: 'RSA-PSS',
            modulusLength: 2048,
            publicExponent: Uint8Array.of(0x01, 0x00, 0x01),
            hash: 'SHA-384',
          },
          extractable,
          ['sign', 'verify'],
        )) as CryptoKeyPair,
      FromCryptoKey: V1Public.SecretKeyFromCryptoKey,
      ToCryptoKey: (key) => V1Public.SecretKeyToCryptoKey(key as V1Public.SecretKey),
      PublicKeyFromCryptoKey: V1Public.PublicKeyFromCryptoKey,
      PublicKeyToCryptoKey: (key) => V1Public.PublicKeyToCryptoKey(key as V1Public.PublicKey),
      Sign: (key, claims) => v1.Sign(key as V1Public.SecretKey, claims, tokenProduceOptions),
      Verify: (key, token) => v1.Verify(key as V1Public.PublicKey, token, tokenConsumeOptions),
      GetPublicKey: (key) => v1.GetPublicKey(key as V1Public.SecretKey),
      ExportSecretKey: (key) => v1.ExportSecretKey(key as V1Public.SecretKey),
    },
    {
      name: 'v2.public',
      acceptsNonExtractablePublicKey: true,
      generate: async (extractable) =>
        (await crypto.subtle.generateKey('Ed25519', extractable, [
          'sign',
          'verify',
        ])) as CryptoKeyPair,
      FromCryptoKey: V2Public.SecretKeyFromCryptoKey,
      ToCryptoKey: (key) => V2Public.SecretKeyToCryptoKey(key as V2Public.SecretKey),
      PublicKeyFromCryptoKey: V2Public.PublicKeyFromCryptoKey,
      PublicKeyToCryptoKey: (key) => V2Public.PublicKeyToCryptoKey(key as V2Public.PublicKey),
      Sign: (key, claims) => v2.Sign(key as V2Public.SecretKey, claims, tokenProduceOptions),
      Verify: (key, token) => v2.Verify(key as V2Public.PublicKey, token, tokenConsumeOptions),
      GetPublicKey: (key) => v2.GetPublicKey(key as V2Public.SecretKey),
      ExportSecretKey: (key) => v2.ExportSecretKey(key as V2Public.SecretKey),
    },
    {
      name: 'v3.public',
      acceptsNonExtractablePublicKey: false,
      generate: async (extractable) =>
        (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, extractable, [
          'sign',
          'verify',
        ])) as CryptoKeyPair,
      FromCryptoKey: V3Public.SecretKeyFromCryptoKey,
      ToCryptoKey: (key) => V3Public.SecretKeyToCryptoKey(key as V3Public.SecretKey),
      PublicKeyFromCryptoKey: V3Public.PublicKeyFromCryptoKey,
      PublicKeyToCryptoKey: (key) => V3Public.PublicKeyToCryptoKey(key as V3Public.PublicKey),
      Sign: (key, claims) => v3.Sign(key as V3Public.SecretKey, claims, tokenProduceOptions),
      Verify: (key, token) => v3.Verify(key as V3Public.PublicKey, token, tokenConsumeOptions),
      GetPublicKey: (key) => v3.GetPublicKey(key as V3Public.SecretKey),
      ExportSecretKey: (key) => v3.ExportSecretKey(key as V3Public.SecretKey),
    },
    {
      name: 'v4.public',
      acceptsNonExtractablePublicKey: true,
      generate: async (extractable) =>
        (await crypto.subtle.generateKey('Ed25519', extractable, [
          'sign',
          'verify',
        ])) as CryptoKeyPair,
      FromCryptoKey: V4Public.SecretKeyFromCryptoKey,
      ToCryptoKey: (key) => V4Public.SecretKeyToCryptoKey(key as V4Public.SecretKey),
      PublicKeyFromCryptoKey: V4Public.PublicKeyFromCryptoKey,
      PublicKeyToCryptoKey: (key) => V4Public.PublicKeyToCryptoKey(key as V4Public.PublicKey),
      Sign: (key, claims) => v4.Sign(key as V4Public.SecretKey, claims, tokenProduceOptions),
      Verify: (key, token) => v4.Verify(key as V4Public.PublicKey, token, tokenConsumeOptions),
      GetPublicKey: (key) => v4.GetPublicKey(key as V4Public.SecretKey),
      ExportSecretKey: (key) => v4.ExportSecretKey(key as V4Public.SecretKey),
    },
  ]
}

describe('local CryptoKey adapters', () => {
  for (const adapter of localAdapters()) {
    test(`${adapter.name} retains and uses a non-extractable HKDF key`, async () => {
      const native = await crypto.subtle.importKey(
        'raw',
        crypto.getRandomValues(new Uint8Array(32)),
        'HKDF',
        false,
        ['deriveBits'],
      )
      const key = adapter.FromCryptoKey(native)

      assert.equal(key.extractable, false)
      assert.strictEqual(adapter.ToCryptoKey(key), native)

      const token = await adapter.Encrypt(key, { sub: 'crypto-key-adapter' })
      const result = await adapter.Decrypt(key, token)
      assert.equal(result.claims.sub, 'crypto-key-adapter')
      await assert.rejects(adapter.ExportKey(key), InvalidKeyError)
    })
  }

  test('rejects values that are not usable HKDF CryptoKeys', async () => {
    assert.throws(
      () => V1Local.LocalKeyFromCryptoKey(null as never),
      new InvalidKeyError('Expected a CryptoKey'),
    )

    const hmac = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(32),
      { name: 'HMAC', hash: 'SHA-384' },
      false,
      ['sign'],
    )
    assert.throws(
      () => V1Local.LocalKeyFromCryptoKey(hmac),
      new InvalidKeyError('Expected an HKDF secret CryptoKey'),
    )

    const wrongUsage = await crypto.subtle.importKey('raw', new Uint8Array(32), 'HKDF', false, [
      'deriveKey',
    ])
    assert.throws(
      () => V3Local.LocalKeyFromCryptoKey(wrongUsage),
      new InvalidKeyError('CryptoKey usages must include deriveBits'),
    )
  })

  test('ToCryptoKey rejects keys from another built-in version', async () => {
    const native = await crypto.subtle.importKey('raw', new Uint8Array(32), 'HKDF', false, [
      'deriveBits',
    ])
    const v1 = V1Local.LocalKeyFromCryptoKey(native)
    assert.throws(() => V3Local.LocalKeyToCryptoKey(v1 as never), InvalidKeyError)
  })
})

async function reimportPublicKey(key: CryptoKey, usages: 'verify'[]): Promise<CryptoKey> {
  const spki = await crypto.subtle.exportKey('spki', key)
  return await crypto.subtle.importKey('spki', spki, key.algorithm, false, usages)
}

describe('public CryptoKey adapters', () => {
  for (const adapter of publicAdapters()) {
    const description = adapter.acceptsNonExtractablePublicKey
      ? 'a non-extractable'
      : 'an extractable'
    test(`${adapter.name} retains and uses ${description} public key`, async () => {
      const pair = await adapter.generate(true)
      const native = adapter.acceptsNonExtractablePublicKey
        ? await reimportPublicKey(pair.publicKey, ['verify'])
        : pair.publicKey
      const key = await adapter.PublicKeyFromCryptoKey(native)

      assert.equal(key.extractable, native.extractable)
      assert.strictEqual(adapter.PublicKeyToCryptoKey(key), native)

      const secretKey = await adapter.FromCryptoKey(pair.privateKey)
      const token = await adapter.Sign(secretKey, { sub: 'crypto-key-adapter' })
      const result = await adapter.Verify(key, token)
      assert.equal(result.claims.sub, 'crypto-key-adapter')
    })
  }

  test('v3.public rejects a non-extractable public key', async () => {
    const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const native = await reimportPublicKey(pair.publicKey, ['verify'])

    await assert.rejects(async () => await V3Public.PublicKeyFromCryptoKey(native), InvalidKeyError)
  })

  test('rejects values that are not public verification CryptoKeys', async () => {
    await assert.rejects(
      async () => await V2Public.PublicKeyFromCryptoKey(null as never),
      new InvalidKeyError('Expected a CryptoKey'),
    )

    const ed25519 = (await crypto.subtle.generateKey('Ed25519', true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    await assert.rejects(
      async () => await V2Public.PublicKeyFromCryptoKey(ed25519.privateKey),
      new InvalidKeyError('Expected a public CryptoKey'),
    )
    await assert.rejects(
      async () => await V3Public.PublicKeyFromCryptoKey(ed25519.publicKey),
      new InvalidKeyError('Expected an ECDSA P-384 CryptoKey'),
    )

    const p384 = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    await assert.rejects(
      async () => await V4Public.PublicKeyFromCryptoKey(p384.publicKey),
      new InvalidKeyError('Expected an Ed25519 CryptoKey'),
    )

    const noUsages = await reimportPublicKey(ed25519.publicKey, [])
    await assert.rejects(
      async () => await V2Public.PublicKeyFromCryptoKey(noUsages),
      new InvalidKeyError('CryptoKey usages must include verify'),
    )
  })

  test('v1 rejects RSA-PSS public keys with incompatible parameters', async () => {
    const pair = (await crypto.subtle.generateKey(
      {
        name: 'RSA-PSS',
        modulusLength: 1024,
        publicExponent: Uint8Array.of(0x01, 0x00, 0x01),
        hash: 'SHA-384',
      },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair

    await assert.rejects(
      async () => await V1Public.PublicKeyFromCryptoKey(pair.publicKey),
      new InvalidKeyError('v1.public requires a 2048-bit RSA key with exponent 65537'),
    )
  })

  test('ToCryptoKey rejects keys from another built-in version', async () => {
    const pair = (await crypto.subtle.generateKey('Ed25519', true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const v2 = await V2Public.PublicKeyFromCryptoKey(pair.publicKey)
    assert.throws(() => V4Public.PublicKeyToCryptoKey(v2 as never), InvalidKeyError)
  })
})

describe('secret CryptoKey adapters', () => {
  for (const adapter of publicAdapters()) {
    test(`${adapter.name} retains and uses an extractable private key`, async () => {
      const pair = await adapter.generate(true)
      const key = await adapter.FromCryptoKey(pair.privateKey)

      assert.equal(key.extractable, true)
      assert.strictEqual(adapter.ToCryptoKey(key), pair.privateKey)

      const publicKey = await adapter.GetPublicKey(key)
      const token = await adapter.Sign(key, { sub: 'crypto-key-adapter' })
      const result = await adapter.Verify(publicKey, token)
      assert.equal(result.claims.sub, 'crypto-key-adapter')
    })

    test(`${adapter.name} handles a non-extractable private key`, async () => {
      const pair = await adapter.generate(false)
      if (typeof Reflect.get(crypto.subtle, 'getPublicKey') !== 'function') {
        await assert.rejects(
          adapter.FromCryptoKey(pair.privateKey),
          new UnsupportedAlgorithmError(
            'SubtleCrypto.getPublicKey is required for a non-extractable private CryptoKey',
          ),
        )
        return
      }

      const key = await adapter.FromCryptoKey(pair.privateKey)

      assert.equal(key.extractable, false)
      assert.strictEqual(adapter.ToCryptoKey(key), pair.privateKey)

      const publicKey = await adapter.GetPublicKey(key)
      const token = await adapter.Sign(key, { sub: 'crypto-key-adapter' })
      const result = await adapter.Verify(publicKey, token)
      assert.equal(result.claims.sub, 'crypto-key-adapter')
      await assert.rejects(adapter.ExportSecretKey(key), InvalidKeyError)
    })
  }

  test('rejects values that are not private signing CryptoKeys', async () => {
    await assert.rejects(
      V2Public.SecretKeyFromCryptoKey(null as never),
      new InvalidKeyError('Expected a CryptoKey'),
    )

    const ed25519 = (await crypto.subtle.generateKey('Ed25519', false, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    await assert.rejects(
      V2Public.SecretKeyFromCryptoKey(ed25519.publicKey),
      new InvalidKeyError('Expected a private CryptoKey'),
    )
    await assert.rejects(
      V3Public.SecretKeyFromCryptoKey(ed25519.privateKey),
      new InvalidKeyError('Expected an ECDSA P-384 CryptoKey'),
    )

    const p384 = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, false, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    await assert.rejects(
      V4Public.SecretKeyFromCryptoKey(p384.privateKey),
      new InvalidKeyError('Expected an Ed25519 CryptoKey'),
    )

    const ecdh = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, false, [
      'deriveBits',
    ])) as CryptoKeyPair
    await assert.rejects(
      V3Public.SecretKeyFromCryptoKey(ecdh.privateKey),
      new InvalidKeyError('CryptoKey usages must include sign'),
    )
  })

  test('v1 rejects RSA-PSS keys with incompatible parameters', async () => {
    const pair = (await crypto.subtle.generateKey(
      {
        name: 'RSA-PSS',
        modulusLength: 1024,
        publicExponent: Uint8Array.of(0x01, 0x00, 0x01),
        hash: 'SHA-384',
      },
      false,
      ['sign', 'verify'],
    )) as CryptoKeyPair

    await assert.rejects(
      V1Public.SecretKeyFromCryptoKey(pair.privateKey),
      new InvalidKeyError('v1.public requires a 2048-bit RSA key with exponent 65537'),
    )
  })

  test('ToCryptoKey rejects keys from another built-in version', async () => {
    const pair = (await crypto.subtle.generateKey('Ed25519', true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const v2 = await V2Public.SecretKeyFromCryptoKey(pair.privateKey)
    assert.throws(() => V4Public.SecretKeyToCryptoKey(v2 as never), InvalidKeyError)
  })
})
