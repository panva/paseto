import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { describe, test } from 'node:test'

import * as PASETO from '../index.ts'
import * as V3Local from '../v3/local.ts'
import { factoryTuple } from './helpers/factories.ts'

interface SealVector {
  name: string
  'expect-fail': boolean
  paserk: string
  unsealed: string | null
  'sealing-public-key': string
  'sealing-secret-key': string
}

interface VectorFile {
  name: string
  tests: SealVector[]
}

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

function readDerElement(
  input: Uint8Array,
  offset: number,
  expectedTag: number,
): { contents: Uint8Array; next: number } {
  if (input[offset] !== expectedTag) throw new TypeError('Unexpected DER tag')
  const firstLength = input[offset + 1]
  if (firstLength === undefined) throw new TypeError('Truncated DER length')
  let length = firstLength
  let headerLength = 2
  if ((firstLength & 0x80) !== 0) {
    const octets = firstLength & 0x7f
    if (octets === 0 || octets > 4 || offset + 2 + octets > input.byteLength) {
      throw new TypeError('Invalid DER length')
    }
    length = 0
    headerLength += octets
    for (let i = 0; i < octets; i++) {
      length = length * 256 + input[offset + 2 + i]!
    }
  }
  const start = offset + headerLength
  const end = start + length
  if (end > input.byteLength) throw new TypeError('Truncated DER value')
  return { contents: input.subarray(start, end), next: end }
}

function p384ScalarFromSec1(pem: string): Uint8Array {
  const sequence = readDerElement(decodePem(pem), 0, 0x30).contents
  const version = readDerElement(sequence, 0, 0x02)
  const scalar = readDerElement(sequence, version.next, 0x04).contents
  assert.equal(scalar.byteLength, 48)
  return new Uint8Array(scalar)
}

async function compressedP384FromSpki(pem: string): Promise<Uint8Array> {
  const publicKey = await crypto.subtle.importKey(
    'spki',
    new Uint8Array(decodePem(pem)),
    { name: 'ECDH', namedCurve: 'P-384' },
    true,
    [],
  )
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey))
  assert.equal(raw.byteLength, 97)
  assert.equal(raw[0], 0x04)
  const compressed = new Uint8Array(49)
  compressed[0] = 0x02 | (raw[96]! & 1)
  compressed.set(raw.subarray(1, 49), 1)
  return compressed
}

async function loadVectors(version: PASETO.Version): Promise<VectorFile> {
  const json = await readFile(
    new URL(`./vectors/PASERK/k${version}.seal.json`, import.meta.url),
    'utf8',
  )
  return JSON.parse(json) as VectorFile
}

const k3Vectors = await loadVectors(3)
const k3Reference = k3Vectors.tests.find((vector) => !vector['expect-fail'])!
const k3PublicMaterial = await compressedP384FromSpki(k3Reference['sealing-public-key'])
const k3SecretMaterial = p384ScalarFromSec1(k3Reference['sealing-secret-key'])
const v3Local = new PASETO.LocalProtocol(...factoryTuple(V3Local))
const k3PublicKey = await v3Local.ImportSealingPublicKey(k3PublicMaterial)
const k3SecretKey = await v3Local.ImportSealingSecretKey(k3SecretMaterial, { extractable: true })

describe(k3Vectors.name, () => {
  test('imports the official P-384 recipient key pair', async () => {
    assert.deepEqual(await v3Local.ExportSealingPublicKey(k3PublicKey), k3PublicMaterial)
    assert.deepEqual(await v3Local.ExportSealingSecretKey(k3SecretKey), k3SecretMaterial)
  })

  for (const vector of k3Vectors.tests) {
    test(vector.name, async () => {
      const operation = async () => {
        const key = await v3Local.UnsealKey(
          vector.paserk as PASETO.SealedLocalPASERK<3>,
          k3SecretKey,
          { extractable: true },
        )
        return await v3Local.ExportKey(key)
      }
      if (vector['expect-fail']) {
        await assert.rejects(operation, PASETO.InvalidPASERKError)
      } else {
        assert.ok(vector.unsealed)
        assert.equal(await operation(), `k3.local.${base64url(fromHex(vector.unsealed))}`)
      }
    })
  }

  test('seals and opens a local key with the official recipient', async () => {
    const key = await v3Local.ImportKey(`k3.local.${base64url(fromHex(k3Reference.unsealed!))}`, {
      extractable: true,
    })
    const sealed = await v3Local.SealKey(key, k3PublicKey)
    const opened = await v3Local.UnsealKey(sealed, k3SecretKey, { extractable: true })
    assert.equal(await v3Local.ExportKey(opened), await v3Local.ExportKey(key))
  })

  test('rejects an invalid ephemeral public key as an invalid PASERK', async () => {
    const malformed: PASETO.SealedLocalPASERK<3> = `k3.seal.${base64url(new Uint8Array(48 + 49 + 32))}`
    await assert.rejects(
      v3Local.UnsealKey(malformed, k3SecretKey, { extractable: true }),
      (error) => {
        assert(error instanceof PASETO.InvalidPASERKError)
        assert.equal(error.message, 'Invalid sealed PASERK ephemeral public key')
        assert(error.cause instanceof PASETO.InvalidKeyError)
        return true
      },
    )
  })
})
