const { createPublicKey, createPrivateKey } = require('crypto')

const test = require('ava')

const { decode, V2 } = require('../../lib')
const vectors = require('./v2.json')

function importPrivateKey(buffer) {
  return createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), buffer.subarray(0, 32)]),
    format: 'der',
    type: 'pkcs8',
  })
}

function importPublicKey(buffer) {
  return createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), buffer]),
    format: 'der',
    type: 'spki',
  })
}

for (const vector of vectors.tests.filter(({ token }) => token.startsWith('v2.public.'))) {
  test(`${vectors.name} - ${vector.name} (raw)`, async (t) => {
    const pk = importPublicKey(Buffer.from(vector['public-key'], 'hex'))
    const sk = importPrivateKey(Buffer.from(vector['secret-key'], 'hex'))
    const token = vector.token
    const footer = vector.footer || undefined
    const expected = vector.payload

    t.deepEqual(decode(token), {
      payload: expected,
      purpose: 'public',
      version: 'v2',
      footer: footer ? Buffer.from(footer) : undefined,
    })
    t.deepEqual(await V2.verify(token, pk, { ignoreExp: true }), expected)
    t.deepEqual(await V2.verify(token, sk, { ignoreExp: true }), expected)
    t.deepEqual(await V2.sign(expected, sk, { footer, iat: false }), token)
  })

  test(`${vectors.name} - ${vector.name} (pem)`, async (t) => {
    const pk = createPublicKey(vector['public-key-pem'])
    const sk = createPrivateKey(vector['secret-key-pem'])
    const token = vector.token
    const footer = vector.footer || undefined
    const expected = vector.payload

    t.deepEqual(decode(token), {
      payload: expected,
      purpose: 'public',
      version: 'v2',
      footer: footer ? Buffer.from(footer) : undefined,
    })
    t.deepEqual(await V2.verify(token, pk, { ignoreExp: true }), expected)
    t.deepEqual(await V2.verify(token, sk, { ignoreExp: true }), expected)
    t.deepEqual(await V2.sign(expected, sk, { footer, iat: false }), token)
  })
}
