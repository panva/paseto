import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { describe, test } from 'node:test'

import { ed25519, x25519 } from '@noble/curves/ed25519.js'

import {
  argon2id,
  blake2b,
  ed25519PublicToX25519,
  xchacha20,
  xchacha20poly1305Decrypt,
  xchacha20poly1305Encrypt,
} from '../examples/noble-suite/index.ts'

interface VectorFile<T> {
  tests: T[]
}

interface TokenVector {
  name: string
  nonce: string
  key: string
  token: string
  payload: string
  footer: string
  'implicit-assertion': string
}

interface PasswordVector {
  name: string
  unwrapped: string
  password: string
  options: { memlimit: number; opslimit: number }
  paserk: string
}

interface SealVector {
  name: string
  'sealing-secret-key': string
  'sealing-public-key': string
  unsealed: string
  paserk: string
}

const encoder = new TextEncoder()

function fromHex(input: string): Uint8Array {
  assert.match(input, /^(?:[0-9a-f]{2})*$/u)
  const output = new Uint8Array(input.length / 2)
  for (let i = 0; i < output.byteLength; i++) {
    output[i] = Number.parseInt(input.slice(i * 2, i * 2 + 2), 16)
  }
  return output
}

function decodeBase64url(input: string): Uint8Array {
  const base64 = input.replaceAll('-', '+').replaceAll('_', '/')
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0))
}

function concat(...inputs: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(inputs.reduce((length, input) => length + input.byteLength, 0))
  let offset = 0
  for (const input of inputs) {
    output.set(input, offset)
    offset += input.byteLength
  }
  return output
}

function le64(value: number): Uint8Array {
  const output = new Uint8Array(8)
  new DataView(output.buffer).setBigUint64(0, BigInt(value), true)
  return output
}

function pae(pieces: readonly Uint8Array[]): Uint8Array {
  return concat(le64(pieces.length), ...pieces.flatMap((piece) => [le64(piece.byteLength), piece]))
}

function readUint32be(input: Uint8Array, offset: number): number {
  return new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(offset)
}

function readUint64be(input: Uint8Array, offset: number): number {
  return Number(new DataView(input.buffer, input.byteOffset, input.byteLength).getBigUint64(offset))
}

async function vector<T extends { name: string }>(path: string, name: string): Promise<T> {
  const json = await readFile(new URL(path, import.meta.url), 'utf8')
  const file = JSON.parse(json) as VectorFile<T>
  const result = file.tests.find((candidate) => candidate.name === name)
  assert.ok(result, `missing official vector ${name}`)
  return result
}

describe('Noble reference primitives', () => {
  test('reproduces official PASETO v2.local vector 2-E-4', async () => {
    const item = await vector<TokenVector>('./vectors/v2.json', '2-E-4')
    const header = encoder.encode('v2.local.')
    const message = encoder.encode(item.payload)
    const footer = encoder.encode(item.footer)
    const key = fromHex(item.key)
    const nonce = blake2b(message, 24, fromHex(item.nonce))
    const sealed = xchacha20poly1305Encrypt(key, nonce, message, pae([header, nonce, footer]))
    const expected = decodeBase64url(item.token.split('.')[2]!)

    assert.deepEqual(concat(nonce, sealed), expected)
    assert.deepEqual(
      xchacha20poly1305Decrypt(key, nonce, sealed, pae([header, nonce, footer])),
      message,
    )
  })

  test('reproduces official PASETO v4.local vector 4-E-3', async () => {
    const item = await vector<TokenVector>('./vectors/v4.json', '4-E-3')
    const header = encoder.encode('v4.local.')
    const message = encoder.encode(item.payload)
    const footer = encoder.encode(item.footer)
    const implicitAssertion = encoder.encode(item['implicit-assertion'])
    const key = fromHex(item.key)
    const nonce = fromHex(item.nonce)
    const temporary = blake2b(concat(encoder.encode('paseto-encryption-key'), nonce), 56, key)
    const ciphertext = xchacha20(temporary.subarray(0, 32), temporary.subarray(32), message)
    const authenticationKey = blake2b(
      concat(encoder.encode('paseto-auth-key-for-aead'), nonce),
      32,
      key,
    )
    const tag = blake2b(
      pae([header, nonce, ciphertext, footer, implicitAssertion]),
      32,
      authenticationKey,
    )
    const expected = decodeBase64url(item.token.split('.')[2]!)

    assert.deepEqual(concat(nonce, ciphertext, tag), expected)
    assert.deepEqual(
      xchacha20(temporary.subarray(0, 32), temporary.subarray(32), ciphertext),
      message,
    )
  })

  test('opens official PASERK k4.local-pw vector 1', async () => {
    const item = await vector<PasswordVector>('./vectors/PASERK/k4.local-pw.json', 'k4.local-pw-1')
    const header = encoder.encode('k4.local-pw.')
    const input = decodeBase64url(item.paserk.slice('k4.local-pw.'.length))
    const salt = input.subarray(0, 16)
    const memory = readUint64be(input, 16)
    const passes = readUint32be(input, 24)
    const parallelism = readUint32be(input, 28)
    const nonce = input.subarray(32, 56)
    const ciphertext = input.subarray(56, -32)
    const tag = input.subarray(-32)

    assert.equal(memory, item.options.memlimit)
    assert.equal(passes, item.options.opslimit)
    assert.equal(parallelism, 1)

    const preKey = await argon2id(encoder.encode(item.password), salt, {
      memory,
      passes,
      parallelism,
      length: 32,
    })
    const authenticationKey = blake2b(concat(Uint8Array.of(0xfe), preKey), 32)
    const expectedTag = blake2b(concat(header, input.subarray(0, -32)), 32, authenticationKey)
    const encryptionKey = blake2b(concat(Uint8Array.of(0xff), preKey), 32)

    assert.deepEqual(expectedTag, tag)
    assert.deepEqual(xchacha20(encryptionKey, nonce, ciphertext), fromHex(item.unwrapped))
  })

  test('opens official PASERK k4.seal vector 1', async () => {
    const item = await vector<SealVector>('./vectors/PASERK/k4.seal.json', 'k4.seal-1')
    const header = encoder.encode('k4.seal.')
    const input = decodeBase64url(item.paserk.slice('k4.seal.'.length))
    const tag = input.subarray(0, 32)
    const ephemeralPublic = input.subarray(32, 64)
    const ciphertext = input.subarray(64)
    const publicKey = fromHex(item['sealing-public-key'])
    const secretKey = fromHex(item['sealing-secret-key'])
    const agreementPublic = ed25519PublicToX25519(publicKey)
    const agreementSecret = ed25519.utils.toMontgomerySecret(secretKey.subarray(0, 32))

    assert.deepEqual(x25519.getPublicKey(agreementSecret), agreementPublic)

    const shared = x25519.getSharedSecret(agreementSecret, ephemeralPublic)
    const authenticationKey = blake2b(
      concat(Uint8Array.of(0x02), header, shared, ephemeralPublic, agreementPublic),
      32,
    )
    assert.deepEqual(
      blake2b(concat(header, ephemeralPublic, ciphertext), 32, authenticationKey),
      tag,
    )

    const encryptionKey = blake2b(
      concat(Uint8Array.of(0x01), header, shared, ephemeralPublic, agreementPublic),
      32,
    )
    const nonce = blake2b(concat(ephemeralPublic, agreementPublic), 24)
    assert.deepEqual(xchacha20(encryptionKey, nonce, ciphertext), fromHex(item.unsealed))
  })
})
