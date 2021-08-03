const test = require('ava')
const crypto = require('crypto')
const { promisify } = require('util')
const generateKeyPair = promisify(crypto.generateKeyPair)

const { errors, V1, V2, V3, V4 } = require('../lib')

test('V1.sign needs a RSA key', async (t) => {
  const { privateKey } = await generateKeyPair('ec', { namedCurve: 'P-256' })
  return t.throwsAsync(V1.sign({}, privateKey), {
    instanceOf: TypeError,
    message: 'v1.public signing key must be a private RSA key with 2048 bit modulus length',
  })
})

test('V1.sign needs a private key', async (t) => {
  const { publicKey } = await generateKeyPair('rsa', { modulusLength: 2048 })
  return t.throwsAsync(V1.sign({}, publicKey), {
    instanceOf: TypeError,
    message: 'v1.public signing key must be a private RSA key with 2048 bit modulus length',
  })
})

test('V3.sign needs an EC key', async (t) => {
  const { privateKey } = await generateKeyPair('rsa', { modulusLength: 2048 })
  return t.throwsAsync(V3.sign({}, privateKey), {
    instanceOf: TypeError,
    message: 'v3.public signing key must be a private EC P-384 key',
  })
})

test('V3.sign needs a private key', async (t) => {
  const { publicKey } = await generateKeyPair('ec', { namedCurve: 'P-384' })
  return t.throwsAsync(V3.sign({}, publicKey), {
    instanceOf: TypeError,
    message: 'v3.public signing key must be a private EC P-384 key',
  })
})

test('V2.sign needs a ed25519 key', async (t) => {
  const { privateKey } = await generateKeyPair('ec', { namedCurve: 'P-256' })
  return t.throwsAsync(V2.sign({}, privateKey), {
    instanceOf: TypeError,
    message: 'v2.public signing key must be a private ed25519 key',
  })
})

test('V2.sign needs a private key', async (t) => {
  const { publicKey } = await generateKeyPair('ed25519')
  return t.throwsAsync(V2.sign({}, publicKey), {
    instanceOf: TypeError,
    message: 'v2.public signing key must be a private ed25519 key',
  })
})

test('V4.sign needs a ed25519 key', async (t) => {
  const { privateKey } = await generateKeyPair('ec', { namedCurve: 'P-256' })
  return t.throwsAsync(V4.sign({}, privateKey), {
    instanceOf: TypeError,
    message: 'v4.public signing key must be a private ed25519 key',
  })
})

test('V4.sign needs a private key', async (t) => {
  const { publicKey } = await generateKeyPair('ed25519')
  return t.throwsAsync(V4.sign({}, publicKey), {
    instanceOf: TypeError,
    message: 'v4.public signing key must be a private ed25519 key',
  })
})

test('V1.verify needs a RSA key', async (t) => {
  const { privateKey } = await generateKeyPair('ec', { namedCurve: 'P-256' })
  return t.throwsAsync(V1.verify({}, privateKey), {
    instanceOf: TypeError,
    message: 'v1.public verify key must be a public RSA key with 2048 bit modulus length',
  })
})

test('V3.verify needs an EC key', async (t) => {
  const { privateKey } = await generateKeyPair('rsa', { modulusLength: 2048 })
  return t.throwsAsync(V3.verify({}, privateKey), {
    instanceOf: TypeError,
    message: 'v3.public verify key must be a public EC P-384 key',
  })
})

test('V2.verify needs a ed25519 key', async (t) => {
  const { privateKey } = await generateKeyPair('ec', { namedCurve: 'P-256' })
  return t.throwsAsync(V2.verify({}, privateKey), {
    instanceOf: TypeError,
    message: 'v2.public verify key must be a public ed25519 key',
  })
})

test('V4.verify needs a ed25519 key', async (t) => {
  const { privateKey } = await generateKeyPair('ec', { namedCurve: 'P-256' })
  return t.throwsAsync(V4.verify({}, privateKey), {
    instanceOf: TypeError,
    message: 'v4.public verify key must be a public ed25519 key',
  })
})

test('token must be a string', async (t) => {
  const k = await V2.generateKey('public')
  return t.throwsAsync(V2.verify(1, k), {
    instanceOf: TypeError,
    message: 'token must be a string, got: number',
  })
})

test('token must be a a valid paseto', async (t) => {
  const k = await V2.generateKey('public')
  return t.throwsAsync(V2.verify('v2.public...', k), {
    instanceOf: errors.PasetoInvalid,
    code: 'ERR_PASETO_INVALID',
    message: 'token is not a PASETO formatted value',
  })
})

test('invalid RSA key length for v1.public', async (t) => {
  const { privateKey } = await generateKeyPair('rsa', { modulusLength: 1024 })
  await t.throwsAsync(V1.sign({}, privateKey), {
    instanceOf: TypeError,
    message: 'v1.public signing key must be a private RSA key with 2048 bit modulus length',
  })
})

test('invalid EC curve for v3.public', async (t) => {
  const { privateKey } = await generateKeyPair('ec', { namedCurve: 'P-521' })
  await t.throwsAsync(V3.sign({}, privateKey), {
    instanceOf: TypeError,
    message: 'v3.public signing key must be a private EC P-384 key',
  })
})

test('V1.validate needs a JSON payload', async (t) => {
  const k = await V1.generateKey('public')

  const token = await V1.sign(Buffer.from('test'), k)

  return t.throwsAsync(V1.verify(token, k), {
    instanceOf: errors.PasetoInvalid,
    code: 'ERR_PASETO_INVALID',
    message: 'All PASETO payloads MUST be a JSON object',
  })
})

test('V2.validate needs a JSON payload', async (t) => {
  const k = await V2.generateKey('public')

  const token = await V2.sign(Buffer.from('test'), k)

  return t.throwsAsync(V2.verify(token, k), {
    instanceOf: errors.PasetoInvalid,
    code: 'ERR_PASETO_INVALID',
    message: 'All PASETO payloads MUST be a JSON object',
  })
})

test('V3.validate needs a JSON payload', async (t) => {
  const k = await V3.generateKey('public')

  const token = await V3.sign(Buffer.from('test'), k)

  return t.throwsAsync(V3.verify(token, k), {
    instanceOf: errors.PasetoInvalid,
    code: 'ERR_PASETO_INVALID',
    message: 'All PASETO payloads MUST be a JSON object',
  })
})

test('V4.validate needs a JSON payload', async (t) => {
  const k = await V4.generateKey('public')

  const token = await V4.sign(Buffer.from('test'), k)

  return t.throwsAsync(V4.verify(token, k), {
    instanceOf: errors.PasetoInvalid,
    code: 'ERR_PASETO_INVALID',
    message: 'All PASETO payloads MUST be a JSON object',
  })
})

test('V1.sign can use Buffer as payload', async (t) => {
  const k = await V1.generateKey('public')

  const token = await V1.sign(Buffer.from('test'), k)

  const payload = await V1.verify(token, k, { buffer: true })
  t.true(Buffer.isBuffer(payload))
})

test('V2.sign can use Buffer as payload', async (t) => {
  const k = await V2.generateKey('public')

  const token = await V2.sign(Buffer.from('test'), k)

  const payload = await V2.verify(token, k, { buffer: true })
  t.true(Buffer.isBuffer(payload))
})

test('V3.sign can use Buffer as payload', async (t) => {
  const k = await V3.generateKey('public')

  const token = await V3.sign(Buffer.from('test'), k)

  const payload = await V3.verify(token, k, { buffer: true })
  t.true(Buffer.isBuffer(payload))
})

test('V4.sign can use Buffer as payload', async (t) => {
  const k = await V4.generateKey('public')

  const token = await V4.sign(Buffer.from('test'), k)

  const payload = await V4.verify(token, k, { buffer: true })
  t.true(Buffer.isBuffer(payload))
})
