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

interface TokenVector {
  name: string
  'expect-fail': boolean
  key?: string
  'public-key'?: string
  token: string
  payload: string
  footer: string
  'implicit-assertion': string
}

interface VectorLocalProtocol {
  ImportKey(paserk: PASETO.LocalPASERK): Promise<PASETO.Key>
  Decrypt(
    key: PASETO.Key,
    token: string,
    options?:
      | PASETO.ConsumeOptions<1>
      | PASETO.ConsumeOptions<2>
      | PASETO.ConsumeOptions<3>
      | PASETO.ConsumeOptions<4>,
  ): Promise<PASETO.TokenResult>
}

interface VectorPublicProtocol {
  ImportPublicKey(paserk: PASETO.PublicPASERK): Promise<PASETO.Key>
  Verify(
    key: PASETO.Key,
    token: string,
    options?:
      | PASETO.ConsumeOptions<1>
      | PASETO.ConsumeOptions<2>
      | PASETO.ConsumeOptions<3>
      | PASETO.ConsumeOptions<4>,
  ): Promise<PASETO.TokenResult>
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

function base64url(input: Uint8Array): string {
  let binary = ''
  for (const byte of input) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

function localPaserk(version: PASETO.Version, key: string): PASETO.LocalPASERK {
  return `k${version}.local.${base64url(fromHex(key))}`
}

function publicPaserk(version: PASETO.Version, key: string): PASETO.PublicPASERK {
  const material = key.startsWith('-----BEGIN ') ? decodePem(key) : fromHex(key)
  return `k${version}.public.${base64url(material)}`
}

async function loadVectors(version: PASETO.Version): Promise<VectorFile<TokenVector>> {
  const json = await readFile(new URL(`./vectors/v${version}.json`, import.meta.url), 'utf8')
  return JSON.parse(json) as VectorFile<TokenVector>
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
  const vectors = await loadVectors(suite.version)
  const local = suite.local as unknown as VectorLocalProtocol
  const publicProtocol = suite.public as unknown as VectorPublicProtocol

  describe(vectors.name, () => {
    for (const vector of vectors.tests) {
      if (vector.key !== undefined && (suite.version === 2 || suite.version === 4)) {
        continue
      }
      test(vector.name, async () => {
        const options: PASETO.ConsumeOptions<3 | 4> = {
          footer: encoder.encode(vector.footer),
          now: new Date(suite.version < 3 ? '2018-01-01T00:00:00Z' : '2021-01-01T00:00:00Z'),
        }
        if (suite.version >= 3) {
          options.implicitAssertion = encoder.encode(vector['implicit-assertion'])
        }

        let operation: Promise<PASETO.TokenResult>
        if (vector.key !== undefined) {
          const key = await local.ImportKey(localPaserk(suite.version, vector.key))
          operation = local.Decrypt(key, vector.token, options)
        } else {
          assert.ok(vector['public-key'], 'public vectors must contain a public key')
          const key = await publicProtocol.ImportPublicKey(
            publicPaserk(suite.version, vector['public-key']),
          )
          operation = publicProtocol.Verify(key, vector.token, options)
        }

        if (vector['expect-fail']) {
          await assert.rejects(operation, PASETO.InvalidTokenError)
          return
        }

        const result = await operation
        assert.deepEqual(result.claims, JSON.parse(vector.payload))
        assert.deepEqual(result.footer, encoder.encode(vector.footer))
      })
    }
  })
}
