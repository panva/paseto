import * as fs from 'fs'

import test from 'ava'

const paseto = await import('#dist')

const vectors = JSON.parse(fs.readFileSync('./vectors/v2.json'))
const buf = TextEncoder.prototype.encode.bind(new TextEncoder())

const sign = paseto.seal(paseto.V2Public)
const verify = paseto.unseal(paseto.V2Public)
const encrypt = paseto.seal(paseto.V2Local)
const decrypt = paseto.unseal(paseto.V2Local)

const kNonce = Object.getOwnPropertySymbols(paseto.V2Local).find(
  (sym) => sym.description === 'kNonce',
)

test.beforeEach((t) => {
  t.context.origNonce = paseto.V2Local[kNonce]
})

test.afterEach.always((t) => {
  paseto.V2Local[kNonce] = t.context.origNonce
})

for (const vector of vectors.tests.filter(({ name }) => name.startsWith('2-E-'))) {
  async function testLocal(t, vector) {
    const footer = buf(vector.footer)
    const payload = buf(JSON.stringify(vector.payload))
    paseto.V2Local[kNonce] = () => new Uint8Array(Buffer.from(vector.nonce, 'hex'))

    const actual = await decrypt(vector.paserk.local, vector.token)
    t.deepEqual([...actual.payload], [...payload])
    t.deepEqual([...actual.footer], [...footer])
    t.is(await encrypt(vector.paserk.local, payload, footer), vector.token)
  }

  test.serial(`${vectors.name} - ${vector.name} (PASERK)`, testLocal, vector)
}

for (const vector of vectors.tests.filter(({ name }) => name.startsWith('2-S-'))) {
  async function testPublic(t, vector) {
    const footer = buf(vector.footer)
    const payload = buf(JSON.stringify(vector.payload))

    {
      const actual = await verify(vector.paserk.public, vector.token)
      t.deepEqual([...actual.payload], [...payload])
      t.deepEqual([...actual.footer], [...footer])
    }

    {
      const token = await sign(vector.paserk.secret, payload, footer)
      const actual = await verify(vector.paserk.public, token)
      t.deepEqual([...actual.payload], [...payload])
      t.deepEqual([...actual.footer], [...footer])
    }
  }

  test(`${vectors.name} - ${vector.name} (PASERK)`, testPublic, vector)
}
