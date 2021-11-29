export default async (data: Uint8Array, key: Uint8Array) => {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-384' }, false, [
    'sign',
  ])
  const ab = await crypto.subtle.sign({ name: 'HMAC' }, k, data)
  return new Uint8Array(ab)
}
