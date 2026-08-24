import assert from 'node:assert/strict'
import { test } from 'node:test'

import { KDF_ARGON2ID } from '../index.ts'

const subtleCryptoConstructor = SubtleCrypto as unknown as {
  supports?: (operation: string, algorithm: string, ...parameters: unknown[]) => boolean
}
const supportsArgon2id =
  typeof subtleCryptoConstructor.supports === 'function' &&
  subtleCryptoConstructor.supports('importKey', 'Argon2id')

function fromHex(input: string): Uint8Array {
  return Uint8Array.from({ length: input.length / 2 }, (_, index) =>
    Number.parseInt(input.slice(index * 2, index * 2 + 2), 16),
  )
}

test(
  'Web Cryptography Argon2id factory derives PASERK byte-based memory parameters',
  { skip: !supportsArgon2id },
  async () => {
    const kdf = KDF_ARGON2ID()
    assert.equal(kdf.type, 'KDF')
    assert.equal(kdf.name, 'Argon2id')

    const result = await kdf.Derive(
      new TextEncoder().encode('password'),
      new Uint8Array(16).fill(1),
      { memory: 8 * 1024, passes: 1, parallelism: 1, length: 32 },
    )

    assert.deepEqual(
      result,
      fromHex('55dbcec536a7ea872cbe528dfbbdb777efd2d13a7c8ea45133d0f58684ca1fe7'),
    )
  },
)
