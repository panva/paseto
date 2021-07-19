const crypto = require('crypto')

const test = require('ava')
const sinon = require('sinon').createSandbox()

const { decode, V1 } = require('../../lib')
const vectors = require('./v1.json')

test.afterEach(() => sinon.restore())

for (const vector of vectors.tests.filter(({ name }) => name.startsWith('1-E-'))) {
  test.serial(`${vectors.name} - ${vector.name}`, async (t) => {
    const sk = crypto.createSecretKey(Buffer.from(vector.key, 'hex'))
    sinon.stub(crypto, 'randomBytes').returns(Buffer.from(vector.nonce, 'hex'))
    const token = vector.token
    const footer = vector.footer || undefined
    const expected = vector.payload

    t.deepEqual(decode(token), {
      payload: undefined,
      purpose: 'local',
      version: 'v1',
      footer: footer ? Buffer.from(footer) : undefined,
    })
    t.deepEqual(await V1.decrypt(token, sk, { ignoreExp: true }), expected)
    t.deepEqual(await V1.encrypt(expected, sk, { footer, iat: false }), token)
  })
}

for (const vector of vectors.tests.filter(({ name }) => name.startsWith('1-S-'))) {
  test(`${vectors.name} - ${vector.name}`, async (t) => {
    const pk = crypto.createPublicKey(vector['public-key'])
    const sk = crypto.createPrivateKey(vector['secret-key'])
    let token = vector.token
    const footer = vector.footer || undefined
    const expected = vector.payload

    t.deepEqual(decode(token), {
      payload: expected,
      purpose: 'public',
      version: 'v1',
      footer: footer ? Buffer.from(footer) : undefined,
    })
    t.deepEqual(await V1.verify(token, pk, { ignoreExp: true }), expected)
    t.deepEqual(await V1.verify(token, sk, { ignoreExp: true }), expected)

    token = await V1.sign(expected, sk, { footer, iat: false })

    t.deepEqual(decode(token), {
      payload: expected,
      purpose: 'public',
      version: 'v1',
      footer: footer ? Buffer.from(footer) : undefined,
    })
    t.deepEqual(await V1.verify(token, pk, { ignoreExp: true }), expected)
    t.deepEqual(await V1.verify(token, sk, { ignoreExp: true }), expected)
  })
}
