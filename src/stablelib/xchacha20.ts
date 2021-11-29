// Copyright (C) 2019 Kyle Den Hartog
// MIT License. See LICENSE file for details.

/**
 * Package xchacha20 implements XChaCha20 stream cipher.
 */

import { writeUint32LE } from './binary.js'
import { wipe } from './wipe.js'
import { streamXOR as chachaStreamXOR } from './chacha.js'

// Number of ChaCha rounds (ChaCha20).
const ROUNDS = 20

/**
 * Encrypt src with XChaCha20 stream generated for the given 32-byte key and
 * 8-byte (as in original implementation) or 12-byte (as in RFC7539) nonce and
 * write the result into dst and return it.
 *
 * dst and src may be the same, but otherwise must not overlap.
 *
 * Nonce length is set in such a way that given it's generated via a CSPRNG
 * then there's little concern of collision for roughly 2^96 messages while
 * reusing a secret key and not encountering nonce reuse vulnerabilities.
 */
export function streamXOR(
  key: Uint8Array,
  nonce: Uint8Array,
  src: Uint8Array,
  dst: Uint8Array,
): Uint8Array {
  if (nonce.length !== 24) {
    throw new Error('XChaCha20 nonce must be 24 bytes')
  }

  // Use HChaCha one-way function to transform first 16 bytes of
  // 24-byte extended nonce and key into a new key for Salsa
  // stream -- "subkey".
  const subkey = hchacha(key, nonce.subarray(0, 16), new Uint8Array(32))

  // Use last 8 bytes of 24-byte extended nonce as an actual nonce prefixed by 4 zero bytes,
  // and a subkey derived in the previous step as key to encrypt.
  const modifiedNonce = new Uint8Array(12)
  modifiedNonce.set(nonce.subarray(16), 4)
  // If nonceInplaceCounterLength > 0, we'll still pass the correct
  // nonce || counter, as we don't limit the end of nonce subarray.
  const result = chachaStreamXOR(subkey, modifiedNonce, src, dst)

  // Clean subkey.
  wipe(subkey)

  return result
}

/**
 * Generate XChaCha20 stream for the given 32-byte key and 12-byte
 * nonce (last 8 bytes of 24 byte nonce prefixed with 4 zero bytes)
 * and write it into dst and return it.
 *
 * Nonces MUST be generated using an CSPRNG to generate a sufficiently
 * random nonce such that a collision is highly unlikely to occur.
 *
 * stream is like streamXOR with all-zero src.
 */
export function stream(key: Uint8Array, nonce: Uint8Array, dst: Uint8Array): Uint8Array {
  wipe(dst)
  return streamXOR(key, nonce, dst, dst)
}

/**
 * HChaCha is a one-way function used in XChaCha to extend nonce.
 *
 * It takes 32-byte key and 16-byte src and writes 32-byte result
 * into dst and returns it.
 */
export function hchacha(key: Uint8Array, src: Uint8Array, dst: Uint8Array): Uint8Array {
  let j0 = 0x61707865 // "expa"  -- ChaCha's "sigma" constant
  let j1 = 0x3320646e // "nd 3"     for 32-byte keys
  let j2 = 0x79622d32 // "2-by"
  let j3 = 0x6b206574 // "te k"
  let j4 = (key[3] << 24) | (key[2] << 16) | (key[1] << 8) | key[0]
  let j5 = (key[7] << 24) | (key[6] << 16) | (key[5] << 8) | key[4]
  let j6 = (key[11] << 24) | (key[10] << 16) | (key[9] << 8) | key[8]
  let j7 = (key[15] << 24) | (key[14] << 16) | (key[13] << 8) | key[12]
  let j8 = (key[19] << 24) | (key[18] << 16) | (key[17] << 8) | key[16]
  let j9 = (key[23] << 24) | (key[22] << 16) | (key[21] << 8) | key[20]
  let j10 = (key[27] << 24) | (key[26] << 16) | (key[25] << 8) | key[24]
  let j11 = (key[31] << 24) | (key[30] << 16) | (key[29] << 8) | key[28]
  let j12 = (src[3] << 24) | (src[2] << 16) | (src[1] << 8) | src[0]
  let j13 = (src[7] << 24) | (src[6] << 16) | (src[5] << 8) | src[4]
  let j14 = (src[11] << 24) | (src[10] << 16) | (src[9] << 8) | src[8]
  let j15 = (src[15] << 24) | (src[14] << 16) | (src[13] << 8) | src[12]

  let x0 = j0
  let x1 = j1
  let x2 = j2
  let x3 = j3
  let x4 = j4
  let x5 = j5
  let x6 = j6
  let x7 = j7
  let x8 = j8
  let x9 = j9
  let x10 = j10
  let x11 = j11
  let x12 = j12
  let x13 = j13
  let x14 = j14
  let x15 = j15

  for (let i = 0; i < ROUNDS; i += 2) {
    x0 = (x0 + x4) | 0
    x12 ^= x0
    x12 = (x12 >>> (32 - 16)) | (x12 << 16)
    x8 = (x8 + x12) | 0
    x4 ^= x8
    x4 = (x4 >>> (32 - 12)) | (x4 << 12)
    x1 = (x1 + x5) | 0
    x13 ^= x1
    x13 = (x13 >>> (32 - 16)) | (x13 << 16)
    x9 = (x9 + x13) | 0
    x5 ^= x9
    x5 = (x5 >>> (32 - 12)) | (x5 << 12)

    x2 = (x2 + x6) | 0
    x14 ^= x2
    x14 = (x14 >>> (32 - 16)) | (x14 << 16)
    x10 = (x10 + x14) | 0
    x6 ^= x10
    x6 = (x6 >>> (32 - 12)) | (x6 << 12)
    x3 = (x3 + x7) | 0
    x15 ^= x3
    x15 = (x15 >>> (32 - 16)) | (x15 << 16)
    x11 = (x11 + x15) | 0
    x7 ^= x11
    x7 = (x7 >>> (32 - 12)) | (x7 << 12)

    x2 = (x2 + x6) | 0
    x14 ^= x2
    x14 = (x14 >>> (32 - 8)) | (x14 << 8)
    x10 = (x10 + x14) | 0
    x6 ^= x10
    x6 = (x6 >>> (32 - 7)) | (x6 << 7)
    x3 = (x3 + x7) | 0
    x15 ^= x3
    x15 = (x15 >>> (32 - 8)) | (x15 << 8)
    x11 = (x11 + x15) | 0
    x7 ^= x11
    x7 = (x7 >>> (32 - 7)) | (x7 << 7)

    x1 = (x1 + x5) | 0
    x13 ^= x1
    x13 = (x13 >>> (32 - 8)) | (x13 << 8)
    x9 = (x9 + x13) | 0
    x5 ^= x9
    x5 = (x5 >>> (32 - 7)) | (x5 << 7)
    x0 = (x0 + x4) | 0
    x12 ^= x0
    x12 = (x12 >>> (32 - 8)) | (x12 << 8)
    x8 = (x8 + x12) | 0
    x4 ^= x8
    x4 = (x4 >>> (32 - 7)) | (x4 << 7)

    x0 = (x0 + x5) | 0
    x15 ^= x0
    x15 = (x15 >>> (32 - 16)) | (x15 << 16)
    x10 = (x10 + x15) | 0
    x5 ^= x10
    x5 = (x5 >>> (32 - 12)) | (x5 << 12)
    x1 = (x1 + x6) | 0
    x12 ^= x1
    x12 = (x12 >>> (32 - 16)) | (x12 << 16)
    x11 = (x11 + x12) | 0
    x6 ^= x11
    x6 = (x6 >>> (32 - 12)) | (x6 << 12)

    x2 = (x2 + x7) | 0
    x13 ^= x2
    x13 = (x13 >>> (32 - 16)) | (x13 << 16)
    x8 = (x8 + x13) | 0
    x7 ^= x8
    x7 = (x7 >>> (32 - 12)) | (x7 << 12)
    x3 = (x3 + x4) | 0
    x14 ^= x3
    x14 = (x14 >>> (32 - 16)) | (x14 << 16)
    x9 = (x9 + x14) | 0
    x4 ^= x9
    x4 = (x4 >>> (32 - 12)) | (x4 << 12)

    x2 = (x2 + x7) | 0
    x13 ^= x2
    x13 = (x13 >>> (32 - 8)) | (x13 << 8)
    x8 = (x8 + x13) | 0
    x7 ^= x8
    x7 = (x7 >>> (32 - 7)) | (x7 << 7)
    x3 = (x3 + x4) | 0
    x14 ^= x3
    x14 = (x14 >>> (32 - 8)) | (x14 << 8)
    x9 = (x9 + x14) | 0
    x4 ^= x9
    x4 = (x4 >>> (32 - 7)) | (x4 << 7)

    x1 = (x1 + x6) | 0
    x12 ^= x1
    x12 = (x12 >>> (32 - 8)) | (x12 << 8)
    x11 = (x11 + x12) | 0
    x6 ^= x11
    x6 = (x6 >>> (32 - 7)) | (x6 << 7)
    x0 = (x0 + x5) | 0
    x15 ^= x0
    x15 = (x15 >>> (32 - 8)) | (x15 << 8)
    x10 = (x10 + x15) | 0
    x5 ^= x10
    x5 = (x5 >>> (32 - 7)) | (x5 << 7)
  }
  writeUint32LE(x0, dst, 0)
  writeUint32LE(x1, dst, 4)
  writeUint32LE(x2, dst, 8)
  writeUint32LE(x3, dst, 12)
  writeUint32LE(x12, dst, 16)
  writeUint32LE(x13, dst, 20)
  writeUint32LE(x14, dst, 24)
  writeUint32LE(x15, dst, 28)
  return dst
}
