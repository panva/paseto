export default async (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, keylen: number) => {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  const ab = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-384', salt, info },
    k,
    keylen << 3,
  )
  return new Uint8Array(ab)
}
