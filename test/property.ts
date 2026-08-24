import assert from 'node:assert/strict'
import { test } from 'node:test'

import fc from 'fast-check'

import * as PASETO from '../index.ts'
import { V4_LOCAL, V4_PUBLIC } from '../examples/noble-suite/index.ts'
import { factoryTuple } from './helpers/factories.ts'

const local = new PASETO.LocalProtocol(...factoryTuple(V4_LOCAL))
const asymmetric = new PASETO.PublicProtocol(...factoryTuple(V4_PUBLIC))
const bytes = fc.uint8Array({ maxLength: 512 })
const nonEmptyBytes = fc.uint8Array({ minLength: 1, maxLength: 512 })
const registeredClaims = new Set(['aud', 'exp', 'iat', 'iss', 'jti', 'nbf', 'sub'])
const claims = fc
  .dictionary(
    fc.string({ unit: 'grapheme', maxLength: 32 }).filter((name) => !registeredClaims.has(name)),
    fc.jsonValue({ maxDepth: 4, stringUnit: 'grapheme' }),
    { maxKeys: 12, noNullPrototype: true },
  )
  .map((value) => value as unknown as PASETO.Claims)
const timestamp = fc.integer({ min: 946_684_800, max: 4_102_444_800 })
const tolerance = fc.integer({ min: 0, max: 120 })
const boundaryDelta = fc.integer({ min: -3, max: 3 })
const options = { numRuns: 50 }

function base64url(input: Uint8Array): string {
  let binary = ''
  for (const value of input) binary += String.fromCharCode(value)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

function decodeBase64url(input: string): Uint8Array {
  const base64 = input.replaceAll('-', '+').replaceAll('_', '/')
  return Uint8Array.from(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')), (value) =>
    value.charCodeAt(0),
  )
}

function tamperSegment(input: string, segment: number, position: number): string {
  const parts = input.split('.')
  const decoded = decodeBase64url(parts[segment]!)
  decoded[position % decoded.byteLength]! ^= 1 << (position % 8)
  parts[segment] = base64url(decoded)
  return parts.join('.')
}

function different(input: Uint8Array): Uint8Array {
  const output = new Uint8Array(input.byteLength + 1)
  output.set(input)
  output[input.byteLength] = 1
  return output
}

function rfc3339(timestamp: number): string {
  return new Date(timestamp * 1000).toISOString().replace('.000Z', 'Z')
}

test('local and public tokens preserve arbitrary claims, footer, and implicit assertion', async () => {
  const localKey = await local.GenerateKey()
  const { publicKey, secretKey } = await asymmetric.GenerateKeyPair()

  await fc.assert(
    fc.asyncProperty(claims, bytes, bytes, async (payload, footer, implicitAssertion) => {
      const produce = { addIssuedAt: false, footer, implicitAssertion, nonExpiring: true }
      const consume = { allowNonExpiring: true, footer, implicitAssertion }
      const expected = JSON.parse(JSON.stringify(payload)) as PASETO.Claims

      const encrypted = await local.Encrypt(localKey, payload, produce)
      const decrypted = await local.Decrypt(localKey, encrypted, consume)
      assert.deepEqual(decrypted.claims, expected)
      assert.deepEqual(decrypted.footer, footer)
      assert.deepEqual(PASETO.InspectFooter(encrypted), footer)

      const signed = await asymmetric.Sign(secretKey, payload, produce)
      const verified = await asymmetric.Verify(publicKey, signed, consume)
      assert.deepEqual(verified.claims, expected)
      assert.deepEqual(verified.footer, footer)
      assert.deepEqual(PASETO.InspectFooter(signed), footer)
    }),
    options,
  )
})

test('tokens reject modified payloads, footers, and implicit assertions', async () => {
  const localKey = await local.GenerateKey()
  const { publicKey, secretKey } = await asymmetric.GenerateKeyPair()

  await fc.assert(
    fc.asyncProperty(
      fc.string({ unit: 'grapheme', maxLength: 256 }),
      nonEmptyBytes,
      bytes,
      fc.nat(),
      async (value, footer, implicitAssertion, position) => {
        const claims = { value }
        const produce = { addIssuedAt: false, footer, implicitAssertion, nonExpiring: true }
        const consume = { allowNonExpiring: true, implicitAssertion }

        const encrypted = await local.Encrypt(localKey, claims, produce)
        await assert.rejects(
          local.Decrypt(localKey, tamperSegment(encrypted, 2, position), consume),
          PASETO.InvalidTokenError,
        )
        await assert.rejects(
          local.Decrypt(localKey, tamperSegment(encrypted, 3, position), consume),
          PASETO.InvalidTokenError,
        )
        await assert.rejects(
          local.Decrypt(localKey, encrypted, {
            allowNonExpiring: true,
            implicitAssertion: different(implicitAssertion),
          }),
          PASETO.InvalidTokenError,
        )

        const signed = await asymmetric.Sign(secretKey, claims, produce)
        await assert.rejects(
          asymmetric.Verify(publicKey, tamperSegment(signed, 2, position), consume),
          PASETO.InvalidTokenError,
        )
        await assert.rejects(
          asymmetric.Verify(publicKey, tamperSegment(signed, 3, position), consume),
          PASETO.InvalidTokenError,
        )
        await assert.rejects(
          asymmetric.Verify(publicKey, signed, {
            allowNonExpiring: true,
            implicitAssertion: different(implicitAssertion),
          }),
          PASETO.InvalidTokenError,
        )
      },
    ),
    options,
  )
})

test('PASERK serialization, identifiers, and wrapping preserve arbitrary local keys', async () => {
  const keyMaterial = fc.uint8Array({ minLength: 32, maxLength: 32 })
  const wrappingMaterial = fc.uint8Array({ minLength: 32, maxLength: 32 })

  await fc.assert(
    fc.asyncProperty(
      keyMaterial,
      wrappingMaterial,
      fc.nat(),
      async (material, secret, position) => {
        const serialized = `k4.local.${base64url(material)}` as PASETO.LocalPASERK<4>
        const key = await local.ImportKey(serialized, { extractable: true })
        assert.equal(await local.ExportKey(key), serialized)

        const identifier = await local.KeyID(serialized)
        const reparsed = await local.ImportKey(serialized, { extractable: true })
        assert.equal(await local.KeyID(await local.ExportKey(reparsed)), identifier)

        const wrappingKey = await local.ImportWrappingKey(secret)
        const wrapped = await local.WrapKey(key, wrappingKey)
        const wrappedIdentifier = await local.KeyID(wrapped)
        assert.equal(await local.KeyID(wrapped), wrappedIdentifier)
        assert.notEqual(wrappedIdentifier, identifier)
        const unwrapped = await local.UnwrapKey(wrapped, wrappingKey, { extractable: true })
        assert.equal(await local.ExportKey(unwrapped), serialized)
        await assert.rejects(
          local.UnwrapKey(
            tamperSegment(wrapped, 3, position) as PASETO.WrappedLocalPASERK<4, 'pie'>,
            wrappingKey,
          ),
          PASETO.InvalidPASERKError,
        )
      },
    ),
    options,
  )
})

test('temporal claims honor expiration and not-before tolerance boundaries', async () => {
  const { publicKey, secretKey } = await asymmetric.GenerateKeyPair()

  await fc.assert(
    fc.asyncProperty(timestamp, tolerance, boundaryDelta, async (now, clockTolerance, delta) => {
      const currentDate = new Date(now * 1000)
      const expiration = await asymmetric.Sign(
        secretKey,
        { exp: rfc3339(now - clockTolerance + delta) },
        { addIssuedAt: false },
      )
      const verifyExpiration = asymmetric.Verify(publicKey, expiration, {
        clockTolerance,
        now: currentDate,
      })
      if (delta >= 0) {
        await assert.doesNotReject(verifyExpiration)
      } else {
        await assert.rejects(
          verifyExpiration,
          (error: unknown) => error instanceof PASETO.ClaimValidationError && error.claim === 'exp',
        )
      }

      const notBefore = await asymmetric.Sign(
        secretKey,
        { nbf: rfc3339(now + clockTolerance + delta) },
        { addIssuedAt: false, nonExpiring: true },
      )
      const verifyNotBefore = asymmetric.Verify(publicKey, notBefore, {
        allowNonExpiring: true,
        clockTolerance,
        now: currentDate,
      })
      if (delta <= 0) {
        await assert.doesNotReject(verifyNotBefore)
      } else {
        await assert.rejects(
          verifyNotBefore,
          (error: unknown) => error instanceof PASETO.ClaimValidationError && error.claim === 'nbf',
        )
      }
    }),
    options,
  )
})
