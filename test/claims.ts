import assert from 'node:assert/strict'
import { test } from 'node:test'

import * as PASETO from '../index.ts'
import * as V4Public from '../v4/public.ts'
import { factoryTuple } from './helpers/factories.ts'

const encoder = new TextEncoder()
const empty = new Uint8Array()
const v4Public = new PASETO.PublicProtocol(...factoryTuple(V4Public))

function concat(...pieces: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(pieces.reduce((length, piece) => length + piece.byteLength, 0))
  let offset = 0
  for (const piece of pieces) {
    output.set(piece, offset)
    offset += piece.byteLength
  }
  return output
}

function base64url(input: Uint8Array): string {
  let binary = ''
  for (const byte of input) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

async function rawV4Signer(): Promise<{
  publicKey: V4Public.PublicKey
  sign(json: string): Promise<string>
}> {
  const generated = (await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair
  const publicMaterial = new Uint8Array(await crypto.subtle.exportKey('raw', generated.publicKey))
  const publicKey = await v4Public.ImportPublicKey(`k4.public.${base64url(publicMaterial)}`)
  return {
    publicKey,
    async sign(json: string): Promise<string> {
      const header = encoder.encode('v4.public.')
      const message = encoder.encode(json)
      const signature = new Uint8Array(
        await crypto.subtle.sign(
          'Ed25519',
          generated.privateKey,
          new Uint8Array(PASETO.PAE([header, message, empty, empty])),
        ),
      )
      return `v4.public.${base64url(concat(message, signature))}`
    },
  }
}

test('RFC 3339 claims reject normalized calendar dates and out-of-range times', async () => {
  const { secretKey } = await v4Public.GenerateKeyPair()
  const invalid = [
    '2023-02-29T00:00:00Z',
    '2024-04-31T00:00:00Z',
    '2024-01-01T24:00:00Z',
    '2024-01-01T00:60:00Z',
    '2024-01-01T00:00:60Z',
    '2024-01-01T00:00:00+24:00',
  ]

  for (const exp of invalid) {
    await assert.rejects(
      v4Public.Sign(secretKey, { exp }, { addIssuedAt: false }),
      PASETO.ClaimValidationError,
    )
  }

  const token = await v4Public.Sign(
    secretKey,
    { exp: '2024-02-29T23:59:59.123456789+14:00' },
    { addIssuedAt: false },
  )
  assert.match(token, /^v4\.public\./u)
})

test('consumer applies strict RFC 3339 calendar validation after authentication', async () => {
  const { publicKey, sign } = await rawV4Signer()
  const token = await sign('{"exp":"2023-02-29T00:00:00Z"}')

  await assert.rejects(
    v4Public.Verify(publicKey, token, { now: new Date('2023-01-01T00:00:00Z') }),
    PASETO.ClaimValidationError,
  )
})

test('expiration remains valid at the exact RFC 3339 instant', async () => {
  const { publicKey, secretKey } = await v4Public.GenerateKeyPair()
  const now = new Date('2030-01-01T00:00:00Z')
  const token = await v4Public.Sign(
    secretKey,
    { exp: now.toISOString().replace('.000Z', 'Z') },
    { addIssuedAt: false },
  )

  await assert.doesNotReject(v4Public.Verify(publicKey, token, { now }))
})

test('explicit expiration options take precedence over claims', async () => {
  const { publicKey, secretKey } = await v4Public.GenerateKeyPair()
  const now = new Date('2030-01-01T00:00:00Z')
  const suppliedExpiration = '2040-01-01T00:00:00Z'
  const claims = { exp: suppliedExpiration }

  const nonExpiring = await v4Public.Sign(secretKey, claims, {
    addIssuedAt: false,
    nonExpiring: true,
    now,
  })
  assert.equal(
    (await v4Public.Verify(publicKey, nonExpiring, { allowNonExpiring: true, now })).claims.exp,
    undefined,
  )
  assert.equal(claims.exp, suppliedExpiration)

  const expiring = await v4Public.Sign(secretKey, claims, {
    addIssuedAt: false,
    expiresIn: 60,
    now,
  })
  assert.equal(
    (await v4Public.Verify(publicKey, expiring, { now })).claims.exp,
    '2030-01-01T00:01:00Z',
  )

  const preserved = await v4Public.Sign(secretKey, claims, { addIssuedAt: false, now })
  assert.equal(
    (await v4Public.Verify(publicKey, preserved, { now })).claims.exp,
    suppliedExpiration,
  )

  await assert.rejects(
    v4Public.Sign(secretKey, claims, { expiresIn: 60, nonExpiring: true, now }),
    TypeError,
  )
})
