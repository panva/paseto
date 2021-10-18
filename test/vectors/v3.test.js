const crypto = require('crypto')

const test = require('ava')
const sinon = require('sinon').createSandbox()

const { decode, V3 } = require('../../lib')
const vectors = require('./v3.json')

test.afterEach(() => sinon.restore())

for (const vector of vectors.tests.filter(({ name }) => name.startsWith('3-E-'))) {
  async function testLocal(t, vector, sk) {
    sinon.stub(crypto, 'randomBytes').returns(Buffer.from(vector.nonce, 'hex'))
    const token = vector.token
    const footer = vector.footer || undefined
    const expected = vector.payload
    const assertion = vector['implicit-assertion']

    t.deepEqual(decode(token), {
      payload: undefined,
      purpose: 'local',
      version: 'v3',
      footer: footer ? Buffer.from(footer) : undefined,
    })
    t.deepEqual(await V3.decrypt(token, sk, { ignoreExp: true, assertion }), expected)
    t.deepEqual(await V3.encrypt(expected, sk, { footer, iat: false, assertion }), token)
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
    `k3.local.${Buffer.from(vector.key, 'hex').toString('base64url')}`,
  )
}

for (const vector of vectors.tests.filter(({ name }) => name.startsWith('3-S-'))) {
  async function testPublic(t, vector, pk, sk) {
    let token = vector.token
    const footer = vector.footer || undefined
    const expected = vector.payload
    const assertion = vector['implicit-assertion']

    token = await V3.sign(expected, sk, { footer, iat: false, assertion })

    t.deepEqual(decode(token), {
      payload: expected,
      purpose: 'public',
      version: 'v3',
      footer: footer ? Buffer.from(footer) : undefined,
    })
    t.deepEqual(await V3.verify(token, pk, { ignoreExp: true, assertion }), expected)
  }

  test(
    `${vectors.name} - ${vector.name} (bytesToKeyObject)`,
    testPublic,
    vector,
    V3.bytesToKeyObject(Buffer.from(vector['public-key'], 'hex')),
    V3.bytesToKeyObject(Buffer.from(vector['secret-key'], 'hex')),
  )

  test(
    `${vectors.name} - ${vector.name} (PASERK)`,
    testPublic,
    vector,
    `k3.public.${Buffer.from(vector['public-key'], 'hex').toString('base64url')}`,
    `k3.secret.${Buffer.from(vector['secret-key'], 'hex').toString('base64url')}`,
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

    t.deepEqual(V3.keyObjectToBytes(keyObjects.pk), raw.pk)
    t.deepEqual(V3.keyObjectToBytes(keyObjects.sk), raw.sk)

    t.deepEqual(
      V3.bytesToKeyObject(raw.pk).export({ format: 'jwk' }),
      keyObjects.pk.export({ format: 'jwk' }),
    )
    t.deepEqual(
      V3.bytesToKeyObject(raw.sk).export({ format: 'jwk' }),
      keyObjects.sk.export({ format: 'jwk' }),
    )

    const { x, y } = keyObjects.pk.export({ format: 'jwk' })
    t.deepEqual(
      V3.keyObjectToBytes(
        V3.bytesToKeyObject(
          Buffer.concat([Buffer.from([0x04]), Buffer.from(x, 'base64'), Buffer.from(y, 'base64')]),
        ),
      ),
      raw.pk,
    )
  })
}
