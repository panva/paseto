const test = require('ava')
const crypto = require('crypto')

const { V2: { encrypt, decrypt, generateKey }, errors } = require('../../lib')

;[Buffer.from('foo'), 'foo', { kid: 'foo' }].forEach((footer) => {
  test(`footer can be a ${Buffer.isBuffer(footer) ? 'Buffer' : typeof footer}`, async t => {
    const key = await generateKey('local')
    const paseto = await encrypt({}, key, { footer })
    ;({ footer } = await decrypt(paseto, key, { complete: true }))
    t.true(Buffer.isBuffer(footer))
  })
})

test('decryption failed', async t => {
  const [k1, k2] = await Promise.all([
    generateKey('local'),
    generateKey('local')
  ])

  const paseto = await encrypt({}, k1)

  await t.throwsAsync(() => decrypt(paseto, k2), {
    message: 'decryption failed',
    instanceOf: errors.PasetoDecryptionFailed,
    code: 'ERR_PASETO_DECRYPTION_FAILED'
  })
})

test('not a v2.local paseto', async t => {
  const key = await generateKey('local')

  let paseto = await encrypt({}, key)
  paseto = paseto.replace('v2.local', 'v1.local')

  await t.throwsAsync(() => decrypt(paseto, key), {
    message: 'token is not a v2.local PASETO',
    instanceOf: errors.PasetoInvalid,
    code: 'ERR_PASETO_INVALID'
  })

  await t.throwsAsync(() => decrypt('foobar', key), {
    message: 'token is not a v2.local PASETO',
    instanceOf: errors.PasetoInvalid,
    code: 'ERR_PASETO_INVALID'
  })
})

test('invalid paseto', async t => {
  const key = await generateKey('local')

  let token = `${await encrypt({}, key, { footer: 'foo' })}.foo`

  await t.throwsAsync(() => decrypt(token, key), {
    message: 'token value is not a PASETO formatted value',
    instanceOf: errors.PasetoInvalid,
    code: 'ERR_PASETO_INVALID'
  })

  await t.throwsAsync(() => decrypt(3.12, key), {
    message: 'token must be a string, got: number',
    instanceOf: TypeError
  })
})

test('invalid key length', async t => {
  const key = crypto.randomBytes(64)

  await t.throwsAsync(() => encrypt({}, key), {
    message: 'v2.local secret key must be 256 bytes long symmetric key',
    instanceOf: TypeError
  })
})

test('invalid key type', async t => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519')
  privateKey.symmetricKeySize = 32

  await t.throwsAsync(() => encrypt({}, privateKey), {
    message: 'v2.local secret key must be 256 bytes long symmetric key',
    instanceOf: TypeError
  })
})

test('invalid payload', async t => {
  const key = await generateKey('local')
  await t.throwsAsync(() => encrypt('foo', key), {
    message: 'payload must be a plain object',
    instanceOf: TypeError
  })
  class Foo {}
  await t.throwsAsync(() => encrypt(new Foo(), key), {
    message: 'payload must be a plain object',
    instanceOf: TypeError
  })
  await t.throwsAsync(() => encrypt([], key), {
    message: 'payload must be a plain object',
    instanceOf: TypeError
  })
})

test('invalid footer', async t => {
  const key = await generateKey('local')
  await t.throwsAsync(() => encrypt('foo', key), {
    message: 'payload must be a plain object',
    instanceOf: TypeError
  })
  class Foo {}
  await t.throwsAsync(() => encrypt(new Foo(), key), {
    message: 'payload must be a plain object',
    instanceOf: TypeError
  })
  await t.throwsAsync(() => encrypt([], key), {
    message: 'payload must be a plain object',
    instanceOf: TypeError
  })
})
