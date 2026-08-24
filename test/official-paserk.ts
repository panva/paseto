import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { describe, test } from 'node:test'

import * as PASETO from '../index.ts'
import * as V1Local from '../v1/local.ts'
import * as V1Public from '../v1/public.ts'
import * as V2Local from '../v2/local.ts'
import * as V2Public from '../v2/public.ts'
import * as V3Local from '../v3/local.ts'
import * as V3Public from '../v3/public.ts'
import * as V4Local from '../v4/local.ts'
import * as V4Public from '../v4/public.ts'
import { factoryTuple } from './helpers/factories.ts'

interface VectorFile<T> {
  name: string
  tests: T[]
}

interface PaserkVector {
  name: string
  'expect-fail': boolean
  key?: string
  paserk?: string | null
  unwrapped?: string
  'wrapping-key'?: string
  password?: string
}

interface VectorLocalProtocol {
  ImportKey(paserk: PASETO.LocalPASERK, options?: PASETO.KeyOptions): Promise<PASETO.Key>
  ExportKey(key: PASETO.Key): Promise<PASETO.LocalPASERK>
  KeyID(
    paserk:
      | PASETO.LocalPASERK
      | PASETO.WrappedLocalPASERK<PASETO.Version, string>
      | PASETO.PasswordWrappedLocalPASERK
      | PASETO.SealedLocalPASERK,
  ): Promise<PASETO.LocalIdPASERK>
  ImportWrappingKey(material: Uint8Array): Promise<PASETO.Key>
  UnwrapKey(
    paserk: PASETO.WrappedLocalPASERK<PASETO.Version, 'pie'>,
    wrappingKey: PASETO.Key,
    options?: PASETO.KeyOptions,
  ): Promise<PASETO.Key>
  UnwrapKeyWithPassword(
    paserk: PASETO.PasswordWrappedLocalPASERK,
    password: Uint8Array,
    options?: PASETO.PasswordUnwrapOptions<PASETO.Version>,
  ): Promise<PASETO.Key>
}

interface VectorPublicProtocol {
  ImportPublicKey(paserk: PASETO.PublicPASERK): Promise<PASETO.Key>
  ExportPublicKey(key: PASETO.Key): Promise<PASETO.PublicPASERK>
  ImportSecretKey(paserk: PASETO.SecretPASERK, options?: PASETO.KeyOptions): Promise<PASETO.Key>
  ExportSecretKey(key: PASETO.Key): Promise<PASETO.SecretPASERK>
  PublicKeyID(paserk: PASETO.PublicPASERK): Promise<PASETO.PublicIdPASERK>
  SecretKeyID(
    paserk:
      | PASETO.SecretPASERK
      | PASETO.WrappedSecretPASERK<PASETO.Version, string>
      | PASETO.PasswordWrappedSecretPASERK,
  ): Promise<PASETO.SecretIdPASERK>
  ImportWrappingKey(material: Uint8Array): Promise<PASETO.Key>
  UnwrapSecretKey(
    paserk: PASETO.WrappedSecretPASERK<PASETO.Version, 'pie'>,
    wrappingKey: PASETO.Key,
    options?: PASETO.KeyOptions,
  ): Promise<PASETO.Key>
  UnwrapSecretKeyWithPassword(
    paserk: PASETO.PasswordWrappedSecretPASERK,
    password: Uint8Array,
    options?: PASETO.PasswordUnwrapOptions<PASETO.Version>,
  ): Promise<PASETO.Key>
}

const encoder = new TextEncoder()

function fromHex(input: string): Uint8Array {
  if (input.length % 2 !== 0 || !/^[0-9a-f]*$/iu.test(input)) {
    throw new TypeError('Invalid hexadecimal test-vector field')
  }
  const output = new Uint8Array(input.length / 2)
  for (let i = 0; i < output.byteLength; i++) {
    output[i] = Number.parseInt(input.slice(i * 2, i * 2 + 2), 16)
  }
  return output
}

function decodePem(input: string): Uint8Array {
  const base64 = input
    .replace(/^-----BEGIN [^-]+-----$/gmu, '')
    .replace(/^-----END [^-]+-----$/gmu, '')
    .replace(/\s/gu, '')
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0))
}

function keyMaterial(input: string): Uint8Array {
  return input.startsWith('-----BEGIN ') ? decodePem(input) : fromHex(input)
}

function base64url(input: Uint8Array): string {
  let binary = ''
  for (const byte of input) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

async function legacyPaserkId(
  version: 1 | 3,
  type: 'lid' | 'pid' | 'sid',
  paserk: string,
): Promise<string> {
  const header = `k${version}.${type}.`
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-384', encoder.encode(`${header}${paserk}`)),
  )
  return `${header}${base64url(digest.subarray(0, 33))}`
}

function plaintextPaserk(
  version: PASETO.Version,
  type: 'local' | 'public' | 'secret',
  material: string,
): string {
  return `k${version}.${type}.${base64url(keyMaterial(material))}`
}

async function loadVectors(
  version: PASETO.Version,
  type: string,
): Promise<VectorFile<PaserkVector>> {
  const json = await readFile(
    new URL(`./vectors/PASERK/k${version}.${type}.json`, import.meta.url),
    'utf8',
  )
  return JSON.parse(json) as VectorFile<PaserkVector>
}

const suites = [
  {
    version: 1,
    local: new PASETO.LocalProtocol(...factoryTuple(V1Local)),
    public: new PASETO.PublicProtocol(...factoryTuple(V1Public)),
  },
  {
    version: 2,
    local: new PASETO.LocalProtocol(...factoryTuple(V2Local)),
    public: new PASETO.PublicProtocol(...factoryTuple(V2Public)),
  },
  {
    version: 3,
    local: new PASETO.LocalProtocol(...factoryTuple(V3Local)),
    public: new PASETO.PublicProtocol(...factoryTuple(V3Public)),
  },
  {
    version: 4,
    local: new PASETO.LocalProtocol(...factoryTuple(V4Local)),
    public: new PASETO.PublicProtocol(...factoryTuple(V4Public)),
  },
] as const

for (const suite of suites) {
  const local = suite.local as unknown as VectorLocalProtocol
  const publicProtocol = suite.public as unknown as VectorPublicProtocol

  const localVectors = await loadVectors(suite.version, 'local')
  describe(localVectors.name, () => {
    for (const vector of localVectors.tests) {
      test(vector.name, async () => {
        assert.ok(vector.paserk)
        const operation = async () => {
          const key = await local.ImportKey(vector.paserk as PASETO.LocalPASERK, {
            extractable: true,
          })
          return await local.ExportKey(key)
        }
        if (vector['expect-fail']) {
          await assert.rejects(operation)
        } else {
          assert.equal(await operation(), vector.paserk)
        }
      })
    }
  })

  const publicVectors = await loadVectors(suite.version, 'public')
  describe(publicVectors.name, () => {
    for (const vector of publicVectors.tests) {
      test(vector.name, async () => {
        const serialized =
          vector.paserk ??
          (() => {
            assert.ok(vector.key)
            return plaintextPaserk(suite.version, 'public', vector.key)
          })()
        const operation = async () => {
          const key = await publicProtocol.ImportPublicKey(serialized as PASETO.PublicPASERK)
          return await publicProtocol.ExportPublicKey(key)
        }
        if (vector['expect-fail']) {
          await assert.rejects(operation)
        } else {
          assert.equal(await operation(), vector.paserk)
        }
      })
    }
  })

  const secretVectors = await loadVectors(suite.version, 'secret')
  describe(secretVectors.name, () => {
    for (const vector of secretVectors.tests) {
      test(vector.name, async () => {
        const serialized =
          vector.paserk ??
          (() => {
            assert.ok(vector.key)
            return plaintextPaserk(suite.version, 'secret', vector.key)
          })()
        const operation = async () => {
          const key = await publicProtocol.ImportSecretKey(serialized as PASETO.SecretPASERK, {
            extractable: true,
          })
          return await publicProtocol.ExportSecretKey(key)
        }
        if (vector['expect-fail']) {
          await assert.rejects(operation)
        } else {
          assert.equal(await operation(), vector.paserk)
        }
      })
    }
  })

  const localIdVectors = await loadVectors(suite.version, 'lid')
  describe(localIdVectors.name, () => {
    // ID operates on an existing serialization. Upstream ID failure vectors exercise the
    // preceding key-serialization step, which the local/public/secret suites above cover.
    const operation = async (vector: PaserkVector) => {
      assert.ok(vector.key)
      const serialized = plaintextPaserk(suite.version, 'local', vector.key)
      return await local.KeyID(serialized as PASETO.LocalPASERK)
    }
    if (suite.version === 2 || suite.version === 4) {
      test('omits the unavailable key identifier capability', () => {
        assert.equal('KeyID' in local, false)
      })
    } else {
      for (const vector of localIdVectors.tests.filter((item) => !item['expect-fail'])) {
        test(vector.name, async () => {
          assert.equal(await operation(vector), vector.paserk)
        })
      }
    }
  })

  const publicIdVectors = await loadVectors(suite.version, 'pid')
  describe(publicIdVectors.name, () => {
    const operation = async (vector: PaserkVector) => {
      assert.ok(vector.key)
      const serialized = plaintextPaserk(suite.version, 'public', vector.key)
      return await publicProtocol.PublicKeyID(serialized as PASETO.PublicPASERK)
    }
    if (suite.version === 2 || suite.version === 4) {
      test('omits the unavailable public-key identifier capability', () => {
        assert.equal('PublicKeyID' in publicProtocol, false)
      })
    } else {
      for (const vector of publicIdVectors.tests.filter((item) => !item['expect-fail'])) {
        test(vector.name, async () => {
          assert.equal(await operation(vector), vector.paserk)
        })
      }
    }
  })

  const secretIdVectors = await loadVectors(suite.version, 'sid')
  describe(secretIdVectors.name, () => {
    const operation = async (vector: PaserkVector) => {
      assert.ok(vector.key)
      const serialized = plaintextPaserk(suite.version, 'secret', vector.key)
      return await publicProtocol.SecretKeyID(serialized as PASETO.SecretPASERK)
    }
    if (suite.version === 2 || suite.version === 4) {
      test('omits the unavailable secret-key identifier capability', () => {
        assert.equal('SecretKeyID' in publicProtocol, false)
      })
    } else {
      for (const vector of secretIdVectors.tests.filter((item) => !item['expect-fail'])) {
        test(vector.name, async () => {
          assert.equal(await operation(vector), vector.paserk)
        })
      }
    }
  })

  if (suite.version === 1 || suite.version === 3) {
    test(`PASERK k${suite.version} identifiers hash compatible serialized PASERKs verbatim`, async () => {
      for (const filename of ['local-wrap.pie', 'local-pw', 'seal']) {
        const vectors = await loadVectors(suite.version, filename)
        const vector = vectors.tests.find((item) => !item['expect-fail'])
        assert.ok(vector?.paserk)
        assert.equal(
          await local.KeyID(vector.paserk as never),
          await legacyPaserkId(suite.version, 'lid', vector.paserk),
        )
      }

      for (const filename of ['secret-wrap.pie', 'secret-pw']) {
        const vectors = await loadVectors(suite.version, filename)
        const vector = vectors.tests.find((item) => !item['expect-fail'])
        assert.ok(vector?.paserk)
        assert.equal(
          await publicProtocol.SecretKeyID(vector.paserk as never),
          await legacyPaserkId(suite.version, 'sid', vector.paserk),
        )
      }

      const customWrapped =
        `k${suite.version}.local-wrap.aws-kms.arn:aws:kms:eu-central-1:123:key/abc.def` as const
      assert.equal(
        await local.KeyID(customWrapped),
        await legacyPaserkId(suite.version, 'lid', customWrapped),
      )
      const customWrappedSecret =
        `k${suite.version}.secret-wrap.aws-kms.arn:aws:kms:eu-central-1:123:key/abc.def` as const
      assert.equal(
        await publicProtocol.SecretKeyID(customWrappedSecret),
        await legacyPaserkId(suite.version, 'sid', customWrappedSecret),
      )
      await assert.rejects(
        local.KeyID(`k${suite.version}.secret.AA` as never),
        PASETO.InvalidPASERKError,
      )
      await assert.rejects(
        publicProtocol.PublicKeyID(`k${suite.version}.local.AA` as never),
        PASETO.InvalidPASERKError,
      )
      await assert.rejects(
        publicProtocol.SecretKeyID(`k${suite.version}.local.AA` as never),
        PASETO.InvalidPASERKError,
      )
    })
  }

  const localWrapVectors = await loadVectors(suite.version, 'local-wrap.pie')
  describe(localWrapVectors.name, () => {
    const operation = async (vector: PaserkVector) => {
      assert.ok(vector.paserk)
      assert.ok(vector['wrapping-key'])
      const wrappingKey = await local.ImportWrappingKey(fromHex(vector['wrapping-key']))
      const key = await local.UnwrapKey(
        vector.paserk as PASETO.WrappedLocalPASERK<PASETO.Version, 'pie'>,
        wrappingKey,
        { extractable: true },
      )
      return await local.ExportKey(key)
    }
    if (suite.version === 2 || suite.version === 4) {
      test('omits the unavailable local-key unwrap capability', () => {
        assert.equal('UnwrapKey' in local, false)
      })
    } else {
      for (const vector of localWrapVectors.tests) {
        test(vector.name, async () => {
          if (vector['expect-fail']) {
            await assert.rejects(operation(vector), PASETO.InvalidPASERKError)
          } else {
            assert.ok(vector.unwrapped)
            assert.equal(
              await operation(vector),
              plaintextPaserk(suite.version, 'local', vector.unwrapped),
            )
          }
        })
      }
    }
  })

  const secretWrapVectors = await loadVectors(suite.version, 'secret-wrap.pie')
  describe(secretWrapVectors.name, () => {
    const operation = async (vector: PaserkVector) => {
      assert.ok(vector.paserk)
      assert.ok(vector['wrapping-key'])
      const wrappingKey = await publicProtocol.ImportWrappingKey(fromHex(vector['wrapping-key']))
      const key = await publicProtocol.UnwrapSecretKey(
        vector.paserk as PASETO.WrappedSecretPASERK<PASETO.Version, 'pie'>,
        wrappingKey,
        { extractable: true },
      )
      return await publicProtocol.ExportSecretKey(key)
    }
    if (suite.version === 2 || suite.version === 4) {
      test('omits the unavailable secret-key unwrap capability', () => {
        assert.equal('UnwrapSecretKey' in publicProtocol, false)
      })
    } else {
      for (const vector of secretWrapVectors.tests) {
        test(vector.name, async () => {
          if (vector['expect-fail']) {
            await assert.rejects(operation(vector), PASETO.InvalidPASERKError)
          } else {
            assert.ok(vector.unwrapped)
            assert.equal(
              await operation(vector),
              plaintextPaserk(suite.version, 'secret', vector.unwrapped),
            )
          }
        })
      }
    }
  })

  const localPasswordVectors = await loadVectors(suite.version, 'local-pw')
  describe(localPasswordVectors.name, () => {
    const operation = async (vector: PaserkVector) => {
      assert.ok(vector.paserk)
      assert.ok(vector.password)
      const key = await local.UnwrapKeyWithPassword(
        vector.paserk as PASETO.PasswordWrappedLocalPASERK,
        encoder.encode(vector.password),
        { extractable: true },
      )
      return await local.ExportKey(key)
    }
    if (suite.version === 2 || suite.version === 4) {
      test('omits the unavailable local password unwrap capability', () => {
        assert.equal('UnwrapKeyWithPassword' in local, false)
      })
    } else {
      for (const vector of localPasswordVectors.tests) {
        test(vector.name, async () => {
          if (vector['expect-fail']) {
            await assert.rejects(operation(vector), PASETO.InvalidPASERKError)
          } else {
            assert.ok(vector.unwrapped)
            assert.equal(
              await operation(vector),
              plaintextPaserk(suite.version, 'local', vector.unwrapped),
            )
          }
        })
      }
    }
  })

  const secretPasswordVectors = await loadVectors(suite.version, 'secret-pw')
  describe(secretPasswordVectors.name, () => {
    const operation = async (vector: PaserkVector) => {
      assert.ok(vector.paserk)
      assert.ok(vector.password)
      const key = await publicProtocol.UnwrapSecretKeyWithPassword(
        vector.paserk as PASETO.PasswordWrappedSecretPASERK,
        encoder.encode(vector.password),
        { extractable: true },
      )
      return await publicProtocol.ExportSecretKey(key)
    }
    if (suite.version === 2 || suite.version === 4) {
      test('omits the unavailable secret password unwrap capability', () => {
        assert.equal('UnwrapSecretKeyWithPassword' in publicProtocol, false)
      })
    } else {
      for (const vector of secretPasswordVectors.tests) {
        test(vector.name, async () => {
          if (vector['expect-fail']) {
            await assert.rejects(operation(vector), PASETO.InvalidPASERKError)
          } else {
            assert.ok(vector.unwrapped)
            assert.equal(
              await operation(vector),
              plaintextPaserk(suite.version, 'secret', vector.unwrapped),
            )
          }
        })
      }
    }
  })
}
