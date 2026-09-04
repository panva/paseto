import fixture from './p384-fixtures.json' with { type: 'json' }

export const fromHex = (hex) => Uint8Array.from(hex.match(/../g), (byte) => parseInt(byte, 16))
const toHex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
const fromBase64Url = (value) =>
  Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), (char) =>
    char.charCodeAt(0),
  )

function equal(actual, expected) {
  if (actual !== expected) throw new Error(`Expected ${expected}, received ${actual}`)
}

// Reference points calculated independently with @noble/curves, shared with HPKE.
// Covers leading zeros, both y parities, and order - 1 in real browsers too.
export async function checkP384Keys(api, toCryptoKey) {
  for (const vector of fixture.keys) {
    const raw = fromHex(vector.publicKey)
    const compressed = api.compressP384(raw)
    equal(toHex(await api.decompressP384(compressed)), vector.publicKey)
    for (const [algorithm, usage] of [
      ['ECDSA', 'sign'],
      ['ECDH', 'deriveBits'],
    ]) {
      const scalar = fromHex(vector.privateKey)
      const importing = api.p384RawPublicFromSecret(scalar, algorithm, usage)
      scalar.fill(0)
      equal(toHex(await importing), vector.publicKey)
    }
    for (const extractable of [false, true]) {
      const scalar = fromHex(vector.privateKey)
      const importing = api.importP384SecretKey(scalar, extractable)
      scalar.fill(0)
      const key = toCryptoKey(await importing)
      equal(key.extractable, extractable)
      equal(key.usages.join(), 'sign')
      if (extractable) {
        const jwk = await crypto.subtle.exportKey('jwk', key)
        equal(toHex(fromBase64Url(jwk.d)), vector.privateKey)
        equal('04' + toHex(fromBase64Url(jwk.x)) + toHex(fromBase64Url(jwk.y)), vector.publicKey)
      }
      const publicKey = await api.p384PublicCryptoKey(compressed, 'ECDSA', ['verify'])
      const message = Uint8Array.of(1, 2, 3)
      const algorithm = { name: 'ECDSA', hash: 'SHA-384' }
      const signature = await crypto.subtle.sign(algorithm, key, message)
      equal(await crypto.subtle.verify(algorithm, publicKey, signature, message), true)
    }
  }
  for (const scalar of [
    new Uint8Array(48),
    fromHex(fixture.order),
    new Uint8Array(48).fill(0xff),
  ]) {
    for (const [algorithm, usage] of [
      ['ECDSA', 'sign'],
      ['ECDH', 'deriveBits'],
    ]) {
      try {
        await api.p384RawPublicFromSecret(scalar, algorithm, usage)
      } catch (error) {
        equal(error.message, 'Invalid P-384 secret scalar')
        continue
      }
      throw new Error('Accepted an invalid scalar')
    }
  }
  const invalidPoints = [
    new Uint8Array(48),
    new Uint8Array(49),
    Uint8Array.of(4, ...new Uint8Array(48)),
    Uint8Array.of(2, ...new Uint8Array(48).fill(0xff)),
    // x = 1 has no point on P-384.
    Uint8Array.of(2, ...new Uint8Array(47), 1),
  ]
  for (const point of invalidPoints) {
    try {
      await api.decompressP384(point)
    } catch (error) {
      equal(error.code, 'ERR_PASETO_INVALID_KEY')
      continue
    }
    throw new Error('Accepted an invalid compressed point')
  }
}
