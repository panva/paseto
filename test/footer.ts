import assert from 'node:assert/strict'
import { test } from 'node:test'

import { InspectFooter, InvalidTokenError, type Version } from '../index.ts'

function base64url(input: Uint8Array): string {
  let binary = ''
  for (const byte of input) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

test('InspectFooter extracts an unauthenticated footer for every token header', () => {
  const footer = Uint8Array.of(0, 1, 2, 253, 254, 255)
  const encoded = base64url(footer)

  for (const version of [1, 2, 3, 4] satisfies readonly Version[]) {
    for (const purpose of ['local', 'public'] as const) {
      assert.deepEqual(InspectFooter(`v${version}.${purpose}.AA.${encoded}`), footer)
      assert.deepEqual(InspectFooter(`v${version}.${purpose}.AA`), new Uint8Array())
    }
  }
})

test('InspectFooter validates token framing without inspecting the payload', () => {
  for (const token of [
    'v5.local.AA',
    'v4.other.AA',
    'v4.local.',
    'v4.local.AA.',
    'v4.local.AA.extra.segment',
  ]) {
    assert.throws(() => InspectFooter(token), InvalidTokenError)
  }

  const footer = Uint8Array.of(1, 2, 3)
  assert.deepEqual(InspectFooter(`v4.local.payload-is-not-decoded.${base64url(footer)}`), footer)
  assert.deepEqual(InspectFooter('v4.local.A='), new Uint8Array())
  assert.throws(() => InspectFooter(undefined as never), TypeError)
})
