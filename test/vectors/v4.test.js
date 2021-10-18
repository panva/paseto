const crypto = require('crypto')

const test = require('ava')

const { decode, V4 } = require('../../lib')
const vectors = require('./v4.json')

for (const vector of vectors.tests.filter(({ name }) => name.startsWith('4-S-'))) {
  async function testPublic(t, vector, pk, sk) {
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
    t.deepEqual(await V4.sign(expected, sk, { footer, iat: false, assertion }), token)
  }

  test(
    `${vectors.name} - ${vector.name} (bytesToKeyObject)`,
    testPublic,
    vector,
    V4.bytesToKeyObject(Buffer.from(vector['public-key'], 'hex')),
    V4.bytesToKeyObject(Buffer.from(vector['secret-key'], 'hex')),
  )

  test(
    `${vectors.name} - ${vector.name} (PASERK)`,
    testPublic,
    vector,
    `k4.public.${Buffer.from(vector['public-key'], 'hex').toString('base64url')}`,
    `k4.secret.${Buffer.from(vector['secret-key'], 'hex').toString('base64url')}`,
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

    t.deepEqual(V4.keyObjectToBytes(keyObjects.pk), raw.pk)
    t.deepEqual(V4.keyObjectToBytes(keyObjects.sk), raw.sk)

    t.deepEqual(
      V4.bytesToKeyObject(raw.pk).export({ format: 'jwk' }),
      keyObjects.pk.export({ format: 'jwk' }),
    )
    t.deepEqual(
      V4.bytesToKeyObject(raw.sk).export({ format: 'jwk' }),
      keyObjects.sk.export({ format: 'jwk' }),
    )
  })
}
