const crypto = require('crypto')

const test = require('ava')
const sinon = require('sinon').createSandbox()

const { decode, V1 } = require('../../lib')
const vectors = require('./v1.json')

test.afterEach(() => sinon.restore())

for (const vector of vectors.tests.filter(({ name }) => name.startsWith('1-E-'))) {
  async function testLocal(t, vector, sk) {
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
  }

  test.serial(
    `${vectors.name} - ${vector.name} (KeyObject)`,
    testLocal,
    vector,
    crypto.createSecretKey(Buffer.from(vector.key, 'hex')),
  )

  test.serial(
    `${vectors.name} - ${vector.name} (Buffer)`,
    testLocal,
    vector,
    Buffer.from(vector.key, 'hex'),
  )

  test.serial(
    `${vectors.name} - ${vector.name} (PASERK)`,
    testLocal,
    vector,
    `k1.local.${Buffer.from(vector.key, 'hex').toString('base64url')}`,
  )
}

for (const vector of vectors.tests.filter(({ name }) => name.startsWith('1-S-'))) {
  async function testPublic(t, vector, pk, sk) {
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

    token = await V1.sign(expected, sk, { footer, iat: false })

    t.deepEqual(decode(token), {
      payload: expected,
      purpose: 'public',
      version: 'v1',
      footer: footer ? Buffer.from(footer) : undefined,
    })
    t.deepEqual(await V1.verify(token, pk, { ignoreExp: true }), expected)
  }
  test(
    `${vectors.name} - ${vector.name} (KeyObject)`,
    testPublic,
    vector,
    crypto.createPublicKey(vector['public-key']),
    crypto.createPrivateKey(vector['secret-key']),
  )

  test(
    `${vectors.name} - ${vector.name} (PASERK)`,
    testPublic,
    vector,
    `k1.public.${crypto
      .createPublicKey(vector['public-key'])
      .export({ format: 'der', type: 'pkcs1' })
      .toString('base64url')}`,
    `k1.secret.${crypto
      .createPrivateKey(vector['secret-key'])
      .export({ format: 'der', type: 'pkcs1' })
      .toString('base64url')}`,
  )
}
