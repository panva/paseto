const { createPublicKey, createPrivateKey } = require('crypto')

const test = require('ava')

const { decode, V4 } = require('../../lib')
const vectors = require('./v4.json')

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

for (const vector of vectors.tests.filter(({ token }) => token.startsWith('v4.public.'))) {
  test(`${vectors.name} - ${vector.name} (raw)`, async (t) => {
    const pk = importPublicKey(Buffer.from(vector['public-key'], 'hex'))
    const sk = importPrivateKey(Buffer.from(vector['secret-key'], 'hex'))
    const token = vector.token
    const footer = vector.footer || undefined
    const expected = vector.payload
    const assertion = vector['implicit-assertion']

    t.deepEqual(decode(token), {
      payload: expected,
      purpose: 'public',
      version: 'v4',
      footer: footer ? Buffer.from(footer) : undefined,
    })
    t.deepEqual(await V4.verify(token, pk, { ignoreExp: true, assertion }), expected)
    t.deepEqual(await V4.verify(token, sk, { ignoreExp: true, assertion }), expected)
    t.deepEqual(await V4.sign(expected, sk, { footer, iat: false, assertion }), token)
  })

  test(`${vectors.name} - ${vector.name} (pem)`, async (t) => {
    const pk = createPublicKey(vector['public-key-pem'])
    const sk = createPrivateKey(vector['secret-key-pem'])
    const token = vector.token
    const footer = vector.footer || undefined
    const expected = vector.payload
    const assertion = vector['implicit-assertion']

    t.deepEqual(decode(token), {
      payload: expected,
      purpose: 'public',
      version: 'v4',
      footer: footer ? Buffer.from(footer) : undefined,
    })
    t.deepEqual(await V4.verify(token, pk, { ignoreExp: true, assertion }), expected)
    t.deepEqual(await V4.verify(token, sk, { ignoreExp: true, assertion }), expected)
    t.deepEqual(await V4.sign(expected, sk, { footer, iat: false, assertion }), token)
  })
}
