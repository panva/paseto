const crypto = require('crypto')

const test = require('ava')

const { decode, V2 } = require('../../lib')
const vectors = require('./v2.json')

for (const vector of vectors.tests.filter(({ name }) => name.startsWith('2-S-'))) {
  async function testPublic(t, vector, pk, sk) {
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
  }

  test(
    `${vectors.name} - ${vector.name} (bytesToKeyObject)`,
    testPublic,
    vector,
    V2.bytesToKeyObject(Buffer.from(vector['public-key'], 'hex')),
    V2.bytesToKeyObject(Buffer.from(vector['secret-key'], 'hex')),
  )

  test(
    `${vectors.name} - ${vector.name} (raw)`,
    testPublic,
    vector,
    Buffer.from(vector['public-key'], 'hex'),
    Buffer.from(vector['secret-key'], 'hex'),
  )

  test(
    `${vectors.name} - ${vector.name} (pem)`,
    testPublic,
    vector,
    crypto.createPublicKey(vector['public-key-pem']),
    crypto.createPrivateKey(vector['secret-key-pem']),
  )

  test(`${vectors.name} - ${vector.name} (key operations)`, (t) => {
    const keyObjects = {
      pk: crypto.createPublicKey(vector['public-key-pem']),
      sk: crypto.createPrivateKey(vector['secret-key-pem']),
    }
    const raw = {
      pk: Buffer.from(vector['public-key'], 'hex'),
      sk: Buffer.from(vector['secret-key'], 'hex'),
    }

    t.deepEqual(V2.keyObjectToBytes(keyObjects.pk), raw.pk)
    t.deepEqual(V2.keyObjectToBytes(keyObjects.sk), raw.sk)

    t.deepEqual(
      V2.bytesToKeyObject(raw.pk).export({ format: 'jwk' }),
      keyObjects.pk.export({ format: 'jwk' }),
    )
    t.deepEqual(
      V2.bytesToKeyObject(raw.sk).export({ format: 'jwk' }),
      keyObjects.sk.export({ format: 'jwk' }),
    )
  })
}
