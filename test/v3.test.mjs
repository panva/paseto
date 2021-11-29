import * as fs from 'fs'

import test from 'ava'

const paseto = await import('#dist')

const vectors = JSON.parse(fs.readFileSync('./vectors/v3.json'))
const buf = TextEncoder.prototype.encode.bind(new TextEncoder())

const sign = paseto.seal(paseto.V3Public)
const verify = paseto.unseal(paseto.V3Public)
const encrypt = paseto.seal(paseto.V3Local)
const decrypt = paseto.unseal(paseto.V3Local)

const kNonce = Object.getOwnPropertySymbols(paseto.V3Local).find(
  (sym) => sym.description === 'kNonce',
)

test.beforeEach((t) => {
  t.context.origNonce = paseto.V3Local[kNonce]
})

test.afterEach.always((t) => {
  paseto.V3Local[kNonce] = t.context.origNonce
})

for (const vector of vectors.tests.filter(({ name }) => name.startsWith('3-E-'))) {
  async function testLocal(t, vector) {
    const footer = buf(vector.footer)
    const assertion = buf(vector['implicit-assertion'])
    const payload = buf(JSON.stringify(vector.payload))
    paseto.V3Local[kNonce] = () => new Uint8Array(Buffer.from(vector.nonce, 'hex'))

    const actual = await decrypt(vector.paserk.local, vector.token, assertion)
    t.deepEqual([...actual.payload], [...payload])
    t.deepEqual([...actual.footer], [...footer])
    t.is(await encrypt(vector.paserk.local, payload, footer, assertion), vector.token)
  }

  test.serial(`${vectors.name} - ${vector.name} (PASERK)`, testLocal, vector)
}

for (const vector of vectors.tests.filter(({ name }) => name.startsWith('3-S-'))) {
  async function testPublic(t, vector) {
    const footer = buf(vector.footer)
    const assertion = buf(vector['implicit-assertion'])
    const payload = buf(JSON.stringify(vector.payload))

    {
      const actual = await verify(vector.paserk.public, vector.token, assertion)
      t.deepEqual([...actual.payload], [...payload])
      t.deepEqual([...actual.footer], [...footer])
    }

    {
      const token = await sign(vector.paserk.secret, payload, footer, assertion)
      const actual = await verify(vector.paserk.public, token, assertion)
      t.deepEqual([...actual.payload], [...payload])
      t.deepEqual([...actual.footer], [...footer])
    }
  }

  test(`${vectors.name} - ${vector.name} (PASERK)`, testPublic, vector)
}
