export async function encrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'AES-CTR' }, false, ['encrypt'])
  // @deno-expect-error
  const ab = await crypto.subtle.encrypt({ name: 'AES-CTR', counter: iv, length: 32 }, k, data)
  return new Uint8Array(ab)
}

export async function decrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'AES-CTR' }, false, ['decrypt'])
  // @deno-expect-error
  const ab = await crypto.subtle.decrypt({ name: 'AES-CTR', counter: iv, length: 32 }, k, data)
  return new Uint8Array(ab)
}
