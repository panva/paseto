import assert from 'node:assert/strict'
import { test } from 'node:test'

import * as PASETO from '../index.ts'
import * as V1Public from '../v1/public.ts'
import * as V4Local from '../v4/local.ts'
import { factoryTuple } from './helpers/factories.ts'

const v1Public = new PASETO.PublicProtocol(...factoryTuple(V1Public))
const v4Local = new PASETO.LocalProtocol(...factoryTuple(V4Local))

function base64url(input: Uint8Array): string {
  let binary = ''
  for (const byte of input) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

function withTrailingByte(paserk: string): string {
  const separator = paserk.lastIndexOf('.') + 1
  const encoded = paserk.slice(separator).replaceAll('-', '+').replaceAll('_', '/')
  const padded = encoded.padEnd(Math.ceil(encoded.length / 4) * 4, '=')
  const material = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0))
  const modified = new Uint8Array(material.byteLength + 1)
  modified.set(material)
  return paserk.slice(0, separator) + base64url(modified)
}

test('k1 PASERK rejects trailing bytes after canonical DER keys', async () => {
  const { publicKey, secretKey } = await v1Public.GenerateKeyPair({ extractable: true })
  const publicPaserk = await v1Public.ExportPublicKey(publicKey)
  const secretPaserk = await v1Public.ExportSecretKey(secretKey)

  await assert.rejects(
    v1Public.ImportPublicKey(withTrailingByte(publicPaserk) as PASETO.PublicPASERK<1>),
    PASETO.InvalidKeyError,
  )
  await assert.rejects(
    v1Public.ImportSecretKey(withTrailingByte(secretPaserk) as PASETO.SecretPASERK<1>),
    PASETO.InvalidKeyError,
  )
})

test('PASERK parsing applies type-specific validation without an input ceiling', async () => {
  const oversized = `k4.local.${'A'.repeat(8_192)}` as PASETO.LocalPASERK<4>

  await assert.rejects(
    v4Local.ImportKey(oversized),
    (error: unknown) =>
      error instanceof PASETO.InvalidKeyError && error.message === 'Invalid k4.local key material',
  )
})
