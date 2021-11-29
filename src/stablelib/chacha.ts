// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package chacha implements ChaCha stream cipher.
 */

import { writeUint32LE } from './binary.js'
import { wipe } from './wipe.js'

// Number of ChaCha rounds (ChaCha20).
const ROUNDS = 20

// Applies the ChaCha core function to 16-byte input,
// 32-byte key key, and puts the result into 64-byte array out.
function core(out: Uint8Array, input: Uint8Array, key: Uint8Array): void {
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
  let j12 = (input[3] << 24) | (input[2] << 16) | (input[1] << 8) | input[0]
  let j13 = (input[7] << 24) | (input[6] << 16) | (input[5] << 8) | input[4]
  let j14 = (input[11] << 24) | (input[10] << 16) | (input[9] << 8) | input[8]
  let j15 = (input[15] << 24) | (input[14] << 16) | (input[13] << 8) | input[12]

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
  writeUint32LE((x0 + j0) | 0, out, 0)
  writeUint32LE((x1 + j1) | 0, out, 4)
  writeUint32LE((x2 + j2) | 0, out, 8)
  writeUint32LE((x3 + j3) | 0, out, 12)
  writeUint32LE((x4 + j4) | 0, out, 16)
  writeUint32LE((x5 + j5) | 0, out, 20)
  writeUint32LE((x6 + j6) | 0, out, 24)
  writeUint32LE((x7 + j7) | 0, out, 28)
  writeUint32LE((x8 + j8) | 0, out, 32)
  writeUint32LE((x9 + j9) | 0, out, 36)
  writeUint32LE((x10 + j10) | 0, out, 40)
  writeUint32LE((x11 + j11) | 0, out, 44)
  writeUint32LE((x12 + j12) | 0, out, 48)
  writeUint32LE((x13 + j13) | 0, out, 52)
  writeUint32LE((x14 + j14) | 0, out, 56)
  writeUint32LE((x15 + j15) | 0, out, 60)
}

/**
 * Encrypt src with ChaCha20 stream generated for the given 32-byte key and
 * 8-byte (as in original implementation) or 12-byte (as in RFC7539) nonce and
 * write the result into dst and return it.
 *
 * dst and src may be the same, but otherwise must not overlap.
 *
 * If nonce is 12 bytes, users should not encrypt more than 256 GiB with the
 * same key and nonce, otherwise the stream will repeat. The function will
 * throw error if counter overflows to prevent this.
 *
 * If nonce is 8 bytes, the output is practically unlimited (2^70 bytes, which
 * is more than a million petabytes). However, it is not recommended to
 * generate 8-byte nonces randomly, as the chance of collision is high.
 *
 * Never use the same key and nonce to encrypt more than one message.
 *
 * If nonceInplaceCounterLength is not 0, the nonce is assumed to be a 16-byte
 * array with stream counter in first nonceInplaceCounterLength bytes and nonce
 * in the last remaining bytes. The counter will be incremented inplace for
 * each ChaCha block. This is useful if you need to encrypt one stream of data
 * in chunks.
 */
export function streamXOR(
  key: Uint8Array,
  nonce: Uint8Array,
  src: Uint8Array,
  dst: Uint8Array,
  nonceInplaceCounterLength = 0,
): Uint8Array {
  // We only support 256-bit keys.
  if (key.length !== 32) {
    throw new Error('ChaCha: key size must be 32 bytes')
  }

  if (dst.length < src.length) {
    throw new Error('ChaCha: destination is shorter than source')
  }

  let nc: Uint8Array
  let counterLength: number

  if (nonceInplaceCounterLength === 0) {
    if (nonce.length !== 8 && nonce.length !== 12) {
      throw new Error('ChaCha nonce must be 8 or 12 bytes')
    }
    nc = new Uint8Array(16)
    // First counterLength bytes of nc are counter, starting with zero.
    counterLength = nc.length - nonce.length
    // Last bytes of nc after counterLength are nonce, set them.
    nc.set(nonce, counterLength)
  } else {
    if (nonce.length !== 16) {
      throw new Error('ChaCha nonce with counter must be 16 bytes')
    }
    // This will update passed nonce with counter inplace.
    nc = nonce
    counterLength = nonceInplaceCounterLength
  }

  // Allocate temporary space for ChaCha block.
  const block = new Uint8Array(64)

  for (let i = 0; i < src.length; i += 64) {
    // Generate a block.
    core(block, nc, key)

    // XOR block bytes with src into dst.
    for (let j = i; j < i + 64 && j < src.length; j++) {
      dst[j] = src[j] ^ block[j - i]
    }

    // Increment counter.
    incrementCounter(nc, 0, counterLength)
  }

  // Cleanup temporary space.
  wipe(block)

  if (nonceInplaceCounterLength === 0) {
    // Cleanup counter.
    wipe(nc)
  }

  return dst
}

/**
 * Generate ChaCha20 stream for the given 32-byte key and 8-byte or 12-byte
 * nonce and write it into dst and return it.
 *
 * Never use the same key and nonce to generate more than one stream.
 *
 * If nonceInplaceCounterLength is not 0, it behaves the same with respect to
 * the nonce as described in the streamXOR documentation.
 *
 * stream is like streamXOR with all-zero src.
 */
export function stream(
  key: Uint8Array,
  nonce: Uint8Array,
  dst: Uint8Array,
  nonceInplaceCounterLength = 0,
): Uint8Array {
  wipe(dst)
  return streamXOR(key, nonce, dst, dst, nonceInplaceCounterLength)
}

function incrementCounter(counter: Uint8Array, pos: number, len: number) {
  let carry = 1
  while (len--) {
    carry = (carry + (counter[pos] & 0xff)) | 0
    counter[pos] = carry & 0xff
    carry >>>= 8
    pos++
  }
  if (carry > 0) {
    throw new Error('ChaCha: counter overflow')
  }
}
