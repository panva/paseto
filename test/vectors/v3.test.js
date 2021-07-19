const { createSecretKey, createPublicKey, createPrivateKey } = require('crypto')

const test = require('ava')

const { decode, V3 } = require('../../lib')
const vectors = require('./v3.json')

function importPrivateKey(buffer) {
  return createPrivateKey({
    key: Buffer.concat([
      Buffer.from('303e0201010430', 'hex'),
      buffer,
      Buffer.from('a00706052b81040022', 'hex'),
    ]),
    format: 'der',
    type: 'sec1',
  })
}

function importPublicKey(buffer) {
  return createPublicKey({
    key: Buffer.concat([
      Buffer.from('3046301006072a8648ce3d020106052b81040022033200', 'hex'),
      buffer,
    ]),
    format: 'der',
    type: 'spki',
  })
}

for (const vector of vectors.tests.filter(({ token }) => token.startsWith('v3.local.'))) {
  test(`${vectors.name} - ${vector.name}`, async (t) => {
    const sk = createSecretKey(Buffer.from(vector.key, 'hex'))
    const nonce = Buffer.from(vector.nonce, 'hex')
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
    t.deepEqual(await V3.encrypt(expected, sk, { footer, nonce, iat: false, assertion }), token)
  })
}

for (const vector of vectors.tests.filter(({ token }) => token.startsWith('v3.public.'))) {
  test(`${vectors.name} - ${vector.name} (raw)`, async (t) => {
    const pk = importPublicKey(Buffer.from(vector['public-key'], 'hex'))
    const sk = importPrivateKey(Buffer.from(vector['secret-key'], 'hex'))
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
    t.deepEqual(await V3.verify(token, sk, { ignoreExp: true, assertion }), expected)
  })

  test(`${vectors.name} - ${vector.name} (pem)`, async (t) => {
    const pk = createPublicKey(vector['public-key-pem'])
    const sk = createPrivateKey(vector['secret-key-pem'])
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
    t.deepEqual(await V3.verify(token, sk, { ignoreExp: true, assertion }), expected)
  })
}
