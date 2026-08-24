import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { describe, test } from 'node:test'

import { blake2b } from '@noble/hashes/blake2.js'

import {
  InvalidPASERKError,
  KDF_ARGON2ID,
  LocalProtocol,
  PublicProtocol,
  type LocalProtocolInstance,
  type PublicProtocolInstance,
} from '../index.ts'
import {
  KDF_ARGON2ID_NOBLE,
  V2_LOCAL,
  V2_PUBLIC,
  V4_LOCAL,
  V4_PUBLIC,
  createLocalCapabilities,
  createPublicCapabilities,
  type ModernVersion,
  type NobleLocalCapabilities,
  type NoblePublicCapabilities,
  type NobleSuiteOptions,
} from '../examples/noble-suite/index.ts'
import { factoryTuple, type FactoryTuple } from './helpers/factories.ts'

type NobleLocalFactoryTuple<V extends ModernVersion> = FactoryTuple<NobleLocalCapabilities<V>>
type NoblePublicFactoryTuple<V extends ModernVersion> = FactoryTuple<NoblePublicCapabilities<V>>

type CombinedProtocolOperations = Readonly<
  Omit<LocalProtocolInstance<NobleLocalFactoryTuple<ModernVersion>>, 'purpose' | 'version'> &
    Omit<PublicProtocolInstance<NoblePublicFactoryTuple<ModernVersion>>, 'purpose' | 'version'>
>

interface VectorFile<T> {
  name: string
  tests: T[]
}

interface TokenVector {
  name: string
  'expect-fail': boolean
  token: string
  payload?: string | null
  footer: string
  'implicit-assertion': string
  key?: string | null
  nonce?: string | null
  'public-key'?: string | null
  'secret-key'?: string | null
}

interface IdVector {
  name: string
  'expect-fail': boolean
  key: string
  paserk: string | null
}

interface PieVector {
  name: string
  'expect-fail': boolean
  paserk: string
  unwrapped: string | null
  'wrapping-key': string
}

interface PasswordVector {
  name: string
  'expect-fail': boolean
  paserk: string
  unwrapped: string | null
  password: string
}

interface SealVector {
  name: string
  'expect-fail': boolean
  paserk: string
  unsealed: string | null
  'sealing-public-key': string
  'sealing-secret-key': string
}

const encoder: TextEncoder = new TextEncoder()

function modernPaserkIdentifier(
  version: ModernVersion,
  type: 'lid' | 'pid' | 'sid',
  paserk: string,
): string {
  const header = `k${version}.${type}.`
  return `${header}${toBase64url(blake2b(encoder.encode(`${header}${paserk}`), { dkLen: 33 }))}`
}

function fromHex(input: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/u.test(input)) throw new TypeError('Invalid hexadecimal vector field')
  const output = new Uint8Array(input.length / 2)
  for (let index = 0; index < output.byteLength; index++) {
    output[index] = Number.parseInt(input.slice(index * 2, index * 2 + 2), 16)
  }
  return output
}

function toBase64url(input: Uint8Array): string {
  // @ts-ignore New typed-array Base64 API with an atob/btoa-only fallback.
  const encoded = input.toBase64?.({ alphabet: 'base64url', omitPadding: true })
  if (encoded) return encoded
  let binary = ''
  for (const value of input) binary += String.fromCharCode(value)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

function decodeBase64url(input: string): Uint8Array {
  // @ts-ignore New typed-array Base64 API with an atob/btoa-only fallback.
  const decoded = Uint8Array.fromBase64?.(input, { alphabet: 'base64url' })
  if (decoded) return decoded
  const base64 = input.replaceAll('-', '+').replaceAll('_', '/')
  return Uint8Array.from(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')), (character) =>
    character.charCodeAt(0),
  )
}

function plainPaserk(version: ModernVersion, type: 'local' | 'public' | 'secret', key: Uint8Array) {
  return `k${version}.${type}.${toBase64url(key)}`
}

function paserkBody(input: string): Uint8Array {
  return decodeBase64url(input.slice(input.lastIndexOf('.') + 1))
}

async function loadVectors<T>(path: string): Promise<VectorFile<T>> {
  return JSON.parse(await readFile(new URL(path, import.meta.url), 'utf8')) as VectorFile<T>
}

function nativeArgon2idSupported(): boolean {
  const constructor = globalThis.SubtleCrypto as typeof SubtleCrypto & {
    supports?: (operation: string, algorithm: unknown) => boolean
  }
  return (
    typeof constructor?.supports === 'function' && constructor.supports('importKey', 'Argon2id')
  )
}

const nativeArgon2id = nativeArgon2idSupported()

function suiteOptions(randomBytes?: (length: number) => Uint8Array): NobleSuiteOptions {
  const options: NobleSuiteOptions = {}
  if (randomBytes !== undefined) options.randomBytes = randomBytes
  if (!nativeArgon2id) options.argon2id = KDF_ARGON2ID_NOBLE
  return options
}

function localProtocol(version: ModernVersion, randomBytes?: (length: number) => Uint8Array) {
  const factories = factoryTuple(createLocalCapabilities(version, suiteOptions(randomBytes)))
  return new LocalProtocol<NobleLocalFactoryTuple<ModernVersion>>(...(factories as never))
}

function publicProtocol(version: ModernVersion, randomBytes?: (length: number) => Uint8Array) {
  const factories = factoryTuple(createPublicCapabilities(version, suiteOptions(randomBytes)))
  return new PublicProtocol<NoblePublicFactoryTuple<ModernVersion>>(...(factories as never))
}

for (const [version, localFactory, publicFactory] of [
  [2, V2_LOCAL, V2_PUBLIC],
  [4, V4_LOCAL, V4_PUBLIC],
] as const) {
  describe(`private Noble v${version} factory seam`, () => {
    test('supports generated local and public keys through the public wrappers', async () => {
      // Each matrix entry has one runtime version, which the constructor validates, while its
      // static version type is a union after destructuring the matrix entry.
      const factories = factoryTuple(localFactory)
      const local = new LocalProtocol<NobleLocalFactoryTuple<ModernVersion>>(
        ...(factories as never),
      )
      const localKey = await local.GenerateKey()
      const token = await local.Encrypt(localKey, { sub: 'alice' }, { nonExpiring: true })
      assert.equal(
        (await local.Decrypt(localKey, token, { allowNonExpiring: true })).claims.sub,
        'alice',
      )

      const publicFactories = factoryTuple(publicFactory)
      const asymmetric = new PublicProtocol<NoblePublicFactoryTuple<ModernVersion>>(
        ...(publicFactories as never),
      )
      const pair = await asymmetric.GenerateKeyPair()
      const signed = await asymmetric.Sign(pair.secretKey, { sub: 'alice' }, { nonExpiring: true })
      assert.equal(
        (await asymmetric.Verify(pair.publicKey, signed, { allowNonExpiring: true })).claims.sub,
        'alice',
      )
    })
  })
}

for (const version of [2, 4] as const) {
  const vectors = await loadVectors<TokenVector>(`./vectors/v${version}.json`)

  describe(`${vectors.name} private Noble local factory`, () => {
    for (const vector of vectors.tests.filter((item) => item.token.includes('.local.'))) {
      test(vector.name, async () => {
        const keyMaterial = vector.key == null ? new Uint8Array(32) : fromHex(vector.key)
        const nonce =
          vector.nonce == null ? new Uint8Array(version === 2 ? 24 : 32) : fromHex(vector.nonce)
        const protocol = localProtocol(version, (length) => {
          assert.equal(length, nonce.byteLength)
          return nonce
        })
        const key = await protocol.ImportKey(plainPaserk(version, 'local', keyMaterial) as never, {
          extractable: true,
        })
        const implicitAssertion = encoder.encode(vector['implicit-assertion'])
        const consumeOptions = {
          now: new Date(version === 2 ? '2018-01-01T00:00:00Z' : '2021-01-01T00:00:00Z'),
          ...(version === 4 ? { implicitAssertion } : {}),
        }
        // The loop variable leaves the protocol statically bound to v2 | v4; the runtime branch
        // supplies implicit assertions only for v4.
        const operation = () => protocol.Decrypt(key, vector.token, consumeOptions as never)

        if (vector['expect-fail']) {
          await assert.rejects(operation)
          return
        }

        assert.ok(vector.payload != null)
        const result = await operation()
        assert.deepEqual(result.claims, JSON.parse(vector.payload))
        assert.deepEqual(result.footer, encoder.encode(vector.footer))
        assert.equal(
          await protocol.Encrypt(key, JSON.parse(vector.payload), {
            addIssuedAt: false,
            footer: encoder.encode(vector.footer),
            ...(version === 4 ? { implicitAssertion } : {}),
          } as never),
          vector.token,
        )
      })
    }
  })

  describe(`${vectors.name} private Noble public factory`, () => {
    const fallbackPublicKey = vectors.tests.find(
      (item) => !item['expect-fail'] && item['public-key'] != null,
    )?.['public-key']
    assert.ok(fallbackPublicKey)

    for (const vector of vectors.tests.filter((item) => item.token.includes('.public.'))) {
      test(vector.name, async () => {
        const protocol = publicProtocol(version)
        const implicitAssertion = encoder.encode(vector['implicit-assertion'])
        const publicMaterial = fromHex(vector['public-key'] ?? fallbackPublicKey)
        const publicKey = await protocol.ImportPublicKey(
          plainPaserk(version, 'public', publicMaterial) as never,
        )
        const consumeOptions = {
          now: new Date(version === 2 ? '2018-01-01T00:00:00Z' : '2021-01-01T00:00:00Z'),
          ...(version === 4 ? { implicitAssertion } : {}),
        }
        // The loop variable leaves the protocol statically bound to v2 | v4; the runtime branch
        // supplies implicit assertions only for v4.
        const operation = () => protocol.Verify(publicKey, vector.token, consumeOptions as never)

        if (vector['expect-fail']) {
          await assert.rejects(operation)
          return
        }

        assert.ok(vector.payload != null)
        assert.ok(vector['secret-key'] != null)
        const result = await operation()
        assert.deepEqual(result.claims, JSON.parse(vector.payload))
        assert.deepEqual(result.footer, encoder.encode(vector.footer))
        const secretKey = await protocol.ImportSecretKey(
          plainPaserk(version, 'secret', fromHex(vector['secret-key'])) as never,
          { extractable: true },
        )
        assert.equal(
          await protocol.Sign(secretKey, JSON.parse(vector.payload), {
            addIssuedAt: false,
            footer: encoder.encode(vector.footer),
            ...(version === 4 ? { implicitAssertion } : {}),
          } as never),
          vector.token,
        )
      })
    }
  })
}

for (const version of [2, 4] as const) {
  for (const type of ['lid', 'pid', 'sid'] as const) {
    const vectors = await loadVectors<IdVector>(`./vectors/PASERK/k${version}.${type}.json`)

    describe(`${vectors.name} private Noble factory`, () => {
      // ID accepts an existing serialization. Upstream failure vectors instead exercise the
      // raw-key serialization step, which is covered by the serialization tests.
      for (const vector of vectors.tests.filter((item) => !item['expect-fail'])) {
        test(vector.name, async () => {
          const material = fromHex(vector.key)
          if (type === 'lid') {
            const protocol = localProtocol(version)
            const paserk = plainPaserk(version, 'local', material)
            assert.equal(await protocol.KeyID(paserk as never), vector.paserk)
            return
          }
          const protocol = publicProtocol(version)
          if (type === 'pid') {
            const paserk = plainPaserk(version, 'public', material)
            assert.equal(await protocol.PublicKeyID(paserk as never), vector.paserk)
            return
          }
          const paserk = plainPaserk(version, 'secret', material)
          assert.equal(await protocol.SecretKeyID(paserk as never), vector.paserk)
        })
      }
    })
  }

  test(`PASERK k${version} identifiers hash compatible serialized PASERKs verbatim`, async () => {
    const local = localProtocol(version)
    for (const filename of ['local-wrap.pie', 'local-pw', 'seal']) {
      const vectors = await loadVectors<{ 'expect-fail': boolean; paserk: string }>(
        `./vectors/PASERK/k${version}.${filename}.json`,
      )
      const vector = vectors.tests.find((item) => !item['expect-fail'])
      assert.ok(vector)
      assert.equal(
        await local.KeyID(vector.paserk as never),
        modernPaserkIdentifier(version, 'lid', vector.paserk),
      )
    }

    const publicForId = publicProtocol(version)
    for (const filename of ['secret-wrap.pie', 'secret-pw']) {
      const vectors = await loadVectors<{ 'expect-fail': boolean; paserk: string }>(
        `./vectors/PASERK/k${version}.${filename}.json`,
      )
      const vector = vectors.tests.find((item) => !item['expect-fail'])
      assert.ok(vector)
      assert.equal(
        await publicForId.SecretKeyID(vector.paserk as never),
        modernPaserkIdentifier(version, 'sid', vector.paserk),
      )
    }

    const customWrapped =
      `k${version}.local-wrap.aws-kms.arn:aws:kms:eu-central-1:123:key/abc.def` as const
    assert.equal(
      await local.KeyID(customWrapped),
      modernPaserkIdentifier(version, 'lid', customWrapped),
    )
    const customWrappedSecret =
      `k${version}.secret-wrap.aws-kms.arn:aws:kms:eu-central-1:123:key/abc.def` as const
    assert.equal(
      await publicForId.SecretKeyID(customWrappedSecret),
      modernPaserkIdentifier(version, 'sid', customWrappedSecret),
    )
    await assert.rejects(local.KeyID(`k${version}.secret.AA` as never), InvalidPASERKError)
    await assert.rejects(
      publicForId.PublicKeyID(`k${version}.local.AA` as never),
      InvalidPASERKError,
    )
    await assert.rejects(
      publicForId.SecretKeyID(`k${version}.local.AA` as never),
      InvalidPASERKError,
    )
  })
}

for (const version of [2, 4] as const) {
  for (const [filename, type] of [
    ['local-wrap.pie', 'local-wrap'],
    ['secret-wrap.pie', 'secret-wrap'],
  ] as const) {
    const vectors = await loadVectors<PieVector>(`./vectors/PASERK/k${version}.${filename}.json`)

    describe(`${vectors.name} private Noble factory`, () => {
      for (const vector of vectors.tests) {
        test(vector.name, async () => {
          const nonce = paserkBody(vector.paserk).slice(32, 64)
          const protocol =
            type === 'local-wrap'
              ? localProtocol(version, () => nonce)
              : publicProtocol(version, () => nonce)
          const operations = protocol as unknown as CombinedProtocolOperations
          const wrappingKey = await operations.ImportWrappingKey(fromHex(vector['wrapping-key']))
          const operation = async () => {
            if (type === 'local-wrap') {
              return await operations.UnwrapKey(vector.paserk as never, wrappingKey as never, {
                extractable: true,
              })
            }
            return await operations.UnwrapSecretKey(vector.paserk as never, wrappingKey as never, {
              extractable: true,
            })
          }

          if (vector['expect-fail']) {
            await assert.rejects(operation, InvalidPASERKError)
            return
          }

          assert.ok(vector.unwrapped !== null)
          const key = await operation()
          if (type === 'local-wrap') {
            assert.equal(
              await operations.ExportKey(key as never),
              plainPaserk(version, 'local', fromHex(vector.unwrapped)),
            )
            assert.equal(
              await operations.WrapKey(key as never, wrappingKey as never),
              vector.paserk,
            )
          } else {
            assert.equal(
              await operations.ExportSecretKey(key as never),
              plainPaserk(version, 'secret', fromHex(vector.unwrapped)),
            )
            assert.equal(
              await operations.WrapSecretKey(key as never, wrappingKey as never),
              vector.paserk,
            )
          }
        })
      }
    })
  }
}

for (const version of [2, 4] as const) {
  for (const [filename, type] of [
    ['local-pw', 'local-wrap'],
    ['secret-pw', 'secret-wrap'],
  ] as const) {
    const vectors = await loadVectors<PasswordVector>(
      `./vectors/PASERK/k${version}.${filename}.json`,
    )

    describe(`${vectors.name} private Noble factory`, () => {
      for (const vector of vectors.tests) {
        test(vector.name, { timeout: 120_000 }, async () => {
          const protocol = type === 'local-wrap' ? localProtocol(version) : publicProtocol(version)
          const operations = protocol as unknown as CombinedProtocolOperations
          const password = encoder.encode(vector.password)
          const operation = async () => {
            if (type === 'local-wrap') {
              return await operations.UnwrapKeyWithPassword(vector.paserk as never, password, {
                extractable: true,
              })
            }
            return await operations.UnwrapSecretKeyWithPassword(vector.paserk as never, password, {
              extractable: true,
            })
          }

          if (vector['expect-fail']) {
            await assert.rejects(operation, InvalidPASERKError)
            return
          }

          assert.ok(vector.unwrapped !== null)
          const key = await operation()
          if (type === 'local-wrap') {
            assert.equal(
              await operations.ExportKey(key as never),
              plainPaserk(version, 'local', fromHex(vector.unwrapped)),
            )
          } else {
            assert.equal(
              await operations.ExportSecretKey(key as never),
              plainPaserk(version, 'secret', fromHex(vector.unwrapped)),
            )
          }
        })
      }

      test('wraps and opens through the configurable extension seam', async () => {
        const random = (length: number) => new Uint8Array(length).fill(version)
        const protocol =
          type === 'local-wrap' ? localProtocol(version, random) : publicProtocol(version, random)
        const operations = protocol as unknown as CombinedProtocolOperations
        const reference = vectors.tests.find(
          (vector) => !vector['expect-fail'] && vector.unwrapped !== null,
        )
        assert.ok(reference?.unwrapped)
        const plaintext = fromHex(reference.unwrapped)
        const password = encoder.encode(`k${version}.${filename} extension seam`)
        const key =
          type === 'local-wrap'
            ? await operations.ImportKey(plainPaserk(version, 'local', plaintext) as never, {
                extractable: true,
              })
            : await operations.ImportSecretKey(plainPaserk(version, 'secret', plaintext) as never, {
                extractable: true,
              })
        const paserk =
          type === 'local-wrap'
            ? await operations.WrapKeyWithPassword(key as never, password, {
                memory: 8 * 1024,
                passes: 1,
                parallelism: 1,
              })
            : await operations.WrapSecretKeyWithPassword(key as never, password, {
                memory: 8 * 1024,
                passes: 1,
                parallelism: 1,
              })
        const opened =
          type === 'local-wrap'
            ? await operations.UnwrapKeyWithPassword(paserk as never, password, {
                extractable: true,
              })
            : await operations.UnwrapSecretKeyWithPassword(paserk as never, password, {
                extractable: true,
              })
        assert.equal(
          type === 'local-wrap'
            ? await operations.ExportKey(opened as never)
            : await operations.ExportSecretKey(opened as never),
          plainPaserk(version, type === 'local-wrap' ? 'local' : 'secret', plaintext),
        )
      })
    })
  }
}

for (const version of [2, 4] as const) {
  const vectors = await loadVectors<SealVector>(`./vectors/PASERK/k${version}.seal.json`)

  describe(`${vectors.name} private Noble factory`, () => {
    for (const vector of vectors.tests) {
      test(vector.name, async () => {
        const protocol = localProtocol(version)
        const recipient = await protocol.ImportSealingSecretKey(
          fromHex(vector['sealing-secret-key']),
        )
        const operation = () =>
          protocol.UnsealKey(vector.paserk as never, recipient, { extractable: true })
        if (vector['expect-fail']) {
          await assert.rejects(operation, InvalidPASERKError)
          return
        }
        assert.ok(vector.unsealed !== null)
        assert.equal(
          await protocol.ExportKey(await operation()),
          plainPaserk(version, 'local', fromHex(vector.unsealed)),
        )
      })
    }

    test('seals and opens through the extension seam', async () => {
      const reference = vectors.tests.find((vector) => !vector['expect-fail'])
      assert.ok(reference)
      const protocol = localProtocol(version)
      const key = await protocol.ImportKey(
        plainPaserk(version, 'local', new Uint8Array(32).fill(version)) as never,
        { extractable: true },
      )
      const publicKey = await protocol.ImportSealingPublicKey(
        fromHex(reference['sealing-public-key']),
      )
      const secretKey = await protocol.ImportSealingSecretKey(
        fromHex(reference['sealing-secret-key']),
      )
      const sealed = await protocol.SealKey(key, publicKey)
      assert.equal(
        await protocol.ExportKey(
          await protocol.UnsealKey(sealed, secretKey, { extractable: true }),
        ),
        await protocol.ExportKey(key),
      )
    })
  })
}

test(
  'the default Noble factory delegates password wrapping to native WebCrypto Argon2id',
  { skip: !nativeArgon2id },
  async () => {
    const protocol = new LocalProtocol(...factoryTuple(V4_LOCAL))
    const key = await protocol.GenerateKey({ extractable: true })
    const password = encoder.encode('native argon2id')
    const paserk = await protocol.WrapKeyWithPassword(key, password, {
      memory: 8 * 1024,
      passes: 1,
      parallelism: 1,
    })
    assert.equal(
      await protocol.ExportKey(
        await protocol.UnwrapKeyWithPassword(paserk, password, { extractable: true }),
      ),
      await protocol.ExportKey(key),
    )
    assert.equal(KDF_ARGON2ID().name, 'Argon2id')
  },
)
