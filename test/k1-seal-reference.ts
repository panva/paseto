import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { describe, test } from 'node:test'

import { sealK1Paserk, unsealK1Paserk } from '../examples/noble-suite/k1-seal.node.ts'

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
  if (!/^(?:[0-9a-f]{2})*$/u.test(input)) throw new TypeError('Invalid hexadecimal vector field')
  const output = new Uint8Array(input.length / 2)
  for (let index = 0; index < output.byteLength; index++) {
    output[index] = Number.parseInt(input.slice(index * 2, index * 2 + 2), 16)
  }
  return output
}

const vectors = JSON.parse(
  await readFile(new URL('./vectors/PASERK/k1.seal.json', import.meta.url), 'utf8'),
) as VectorFile

describe(`${vectors.name} private Node.js raw-RSA reference`, () => {
  for (const vector of vectors.tests) {
    test(vector.name, () => {
      const operation = () => unsealK1Paserk(vector.paserk, vector['sealing-secret-key'])
      if (vector['expect-fail']) {
        assert.throws(operation)
        return
      }

      assert.ok(vector.unsealed !== null)
      const opened = operation()
      assert.deepEqual(opened.plaintext, fromHex(vector.unsealed))
      assert.equal(
        sealK1Paserk(opened.plaintext, vector['sealing-public-key'], opened.random),
        vector.paserk,
      )
    })
  }
})
