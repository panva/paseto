const { createSecretKey, createPublicKey, createPrivateKey } = require('crypto')

const test = require('ava')

const { decode, V1 } = require('../../lib')
const vectors = require('./v1.json')

for (const vector of vectors.tests.filter(({ token }) => token.startsWith('v1.local.'))) {
  test(`${vectors.name} - ${vector.name}`, async (t) => {
    const sk = createSecretKey(Buffer.from(vector.key, 'hex'))
    const nonce = Buffer.from(vector.nonce, 'hex')
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
    t.deepEqual(await V1.encrypt(expected, sk, { footer, nonce, iat: false }), token)
  })
}

for (const vector of vectors.tests.filter(({ token }) => token.startsWith('v1.public.'))) {
  test(`${vectors.name} - ${vector.name}`, async (t) => {
    const pk = createPublicKey(vector['public-key'])
    const sk = createPrivateKey(vector['secret-key'])
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
