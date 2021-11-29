import * as crypto from 'crypto'

const fallback = (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, keylen: number) => {
  const prk = crypto
    .createHmac('sha384', salt.byteLength ? salt : new Uint8Array(48))
    .update(ikm)
    .digest()

  // T(0) = empty
  // T(1) = HMAC(PRK, T(0) | info | 0x01)
  // T(2) = HMAC(PRK, T(1) | info | 0x02)
  // T(3) = HMAC(PRK, T(2) | info | 0x03)
  // ...
  // T(N) = HMAC(PRK, T(N-1) | info | N)

  const N = Math.ceil(keylen / 48)

  // Single T buffer to accomodate T = T(1) | T(2) | T(3) | ... | T(N)
  // with a little extra for info | N during T(N)
  const T = new Uint8Array(48 * N + info.byteLength + 1)
  let prev = 0
  let start = 0
  for (let c = 1; c <= N; c++) {
    T.set(info, start)
    T[start + info.byteLength] = c

    T.set(
      crypto
        .createHmac('sha384', prk)
        .update(T.subarray(prev, start + info.byteLength + 1))
        .digest(),
      start,
    )

    prev = start
    start += 48
  }

  // OKM, releasing T
  return T.slice(0, keylen)
}

let hkdf: (
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  keylen: number,
) => Promise<Uint8Array>

if (typeof crypto.hkdf === 'function' && !process.versions.electron) {
  hkdf = async (...args) =>
    new Promise((resolve, reject) => {
      crypto.hkdf('sha384', ...args, (err, arrayBuffer) => {
        if (err) reject(err)
        else resolve(new Uint8Array(arrayBuffer))
      })
    })
}

export default async (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, keylen: number) =>
  (hkdf || fallback)(ikm, salt, info, keylen)
