// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package sha512 implements SHA-2-512 cryptographic hash function.
 */

import { SerializableHash } from './hash.js'
import { readUint32BE, writeUint32BE } from './binary.js'
import { wipe } from './wipe.js'

export const DIGEST_LENGTH = 64
export const BLOCK_SIZE = 128

/**
 * SHA-2-512 cryptographic hash algorithm.
 */
export class SHA512 implements SerializableHash {
  /** Length of hash output */
  readonly digestLength: number = DIGEST_LENGTH

  /** Block size */
  readonly blockSize: number = BLOCK_SIZE

  // Note: Int32Array is used instead of Uint32Array for performance reasons.
  protected _stateHi = new Int32Array(8) // hash state, high bytes
  protected _stateLo = new Int32Array(8) // hash state, low bytes
  private _tempHi = new Int32Array(16) // temporary state, high bytes
  private _tempLo = new Int32Array(16) // temporary state, low bytes
  private _buffer = new Uint8Array(256) // buffer for data to hash
  private _bufferLength = 0 // number of bytes in buffer
  private _bytesHashed = 0 // number of total bytes hashed
  private _finished = false // indicates whether the hash was finalized

  constructor() {
    this.reset()
  }

  protected _initState() {
    this._stateHi[0] = 0x6a09e667
    this._stateHi[1] = 0xbb67ae85
    this._stateHi[2] = 0x3c6ef372
    this._stateHi[3] = 0xa54ff53a
    this._stateHi[4] = 0x510e527f
    this._stateHi[5] = 0x9b05688c
    this._stateHi[6] = 0x1f83d9ab
    this._stateHi[7] = 0x5be0cd19

    this._stateLo[0] = 0xf3bcc908
    this._stateLo[1] = 0x84caa73b
    this._stateLo[2] = 0xfe94f82b
    this._stateLo[3] = 0x5f1d36f1
    this._stateLo[4] = 0xade682d1
    this._stateLo[5] = 0x2b3e6c1f
    this._stateLo[6] = 0xfb41bd6b
    this._stateLo[7] = 0x137e2179
  }

  /**
   * Resets hash state making it possible
   * to re-use this instance to hash other data.
   */
  reset(): this {
    this._initState()
    this._bufferLength = 0
    this._bytesHashed = 0
    this._finished = false
    return this
  }

  /**
   * Cleans internal buffers and resets hash state.
   */
  clean() {
    wipe(this._buffer)
    wipe(this._tempHi)
    wipe(this._tempLo)
    this.reset()
  }

  /**
   * Updates hash state with the given data.
   *
   * Throws error when trying to update already finalized hash:
   * instance must be reset to update it again.
   */
  update(data: Uint8Array, dataLength: number = data.length): this {
    if (this._finished) {
      throw new Error("SHA512: can't update because hash was finished.")
    }
    let dataPos = 0
    this._bytesHashed += dataLength
    if (this._bufferLength > 0) {
      while (this._bufferLength < BLOCK_SIZE && dataLength > 0) {
        this._buffer[this._bufferLength++] = data[dataPos++]
        dataLength--
      }
      if (this._bufferLength === this.blockSize) {
        hashBlocks(
          this._tempHi,
          this._tempLo,
          this._stateHi,
          this._stateLo,
          this._buffer,
          0,
          this.blockSize,
        )
        this._bufferLength = 0
      }
    }
    if (dataLength >= this.blockSize) {
      dataPos = hashBlocks(
        this._tempHi,
        this._tempLo,
        this._stateHi,
        this._stateLo,
        data,
        dataPos,
        dataLength,
      )
      dataLength %= this.blockSize
    }
    while (dataLength > 0) {
      this._buffer[this._bufferLength++] = data[dataPos++]
      dataLength--
    }
    return this
  }

  /**
   * Finalizes hash state and puts hash into out.
   * If hash was already finalized, puts the same value.
   */
  finish(out: Uint8Array): this {
    if (!this._finished) {
      const bytesHashed = this._bytesHashed
      const left = this._bufferLength
      const bitLenHi = (bytesHashed / 0x20000000) | 0
      const bitLenLo = bytesHashed << 3
      const padLength = bytesHashed % 128 < 112 ? 128 : 256

      this._buffer[left] = 0x80
      for (let i = left + 1; i < padLength - 8; i++) {
        this._buffer[i] = 0
      }
      writeUint32BE(bitLenHi, this._buffer, padLength - 8)
      writeUint32BE(bitLenLo, this._buffer, padLength - 4)

      hashBlocks(
        this._tempHi,
        this._tempLo,
        this._stateHi,
        this._stateLo,
        this._buffer,
        0,
        padLength,
      )

      this._finished = true
    }

    for (let i = 0; i < this.digestLength / 8; i++) {
      writeUint32BE(this._stateHi[i], out, i * 8)
      writeUint32BE(this._stateLo[i], out, i * 8 + 4)
    }

    return this
  }

  /**
   * Returns the final hash digest.
   */
  digest(): Uint8Array {
    const out = new Uint8Array(this.digestLength)
    this.finish(out)
    return out
  }

  /**
   * Function useful for HMAC/PBKDF2 optimization. Returns hash state to be
   * used with restoreState(). Only chain value is saved, not buffers or
   * other state variables.
   */
  saveState(): SavedState {
    if (this._finished) {
      throw new Error('SHA256: cannot save finished state')
    }
    return {
      stateHi: new Int32Array(this._stateHi),
      stateLo: new Int32Array(this._stateLo),
      buffer: this._bufferLength > 0 ? new Uint8Array(this._buffer) : undefined,
      bufferLength: this._bufferLength,
      bytesHashed: this._bytesHashed,
    }
  }

  /**
   * Function useful for HMAC/PBKDF2 optimization. Restores state saved by
   * saveState() and sets bytesHashed to the given value.
   */
  restoreState(savedState: SavedState): this {
    this._stateHi.set(savedState.stateHi)
    this._stateLo.set(savedState.stateLo)
    this._bufferLength = savedState.bufferLength
    if (savedState.buffer) {
      this._buffer.set(savedState.buffer)
    }
    this._bytesHashed = savedState.bytesHashed
    this._finished = false
    return this
  }

  /**
   * Cleans state returned by saveState().
   */
  cleanSavedState(savedState: SavedState) {
    wipe(savedState.stateHi)
    wipe(savedState.stateLo)
    if (savedState.buffer) {
      wipe(savedState.buffer)
    }
    savedState.bufferLength = 0
    savedState.bytesHashed = 0
  }
}

export type SavedState = {
  stateHi: Int32Array
  stateLo: Int32Array
  buffer: Uint8Array | undefined
  bufferLength: number
  bytesHashed: number
}

// Constants
const K = new Int32Array([
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
  0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
  0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
  0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
  0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
  0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
  0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
  0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
  0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
  0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
  0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
  0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
])

function hashBlocks(
  wh: Int32Array,
  wl: Int32Array,
  hh: Int32Array,
  hl: Int32Array,
  m: Uint8Array,
  pos: number,
  len: number,
): number {
  let ah0 = hh[0],
    ah1 = hh[1],
    ah2 = hh[2],
    ah3 = hh[3],
    ah4 = hh[4],
    ah5 = hh[5],
    ah6 = hh[6],
    ah7 = hh[7],
    al0 = hl[0],
    al1 = hl[1],
    al2 = hl[2],
    al3 = hl[3],
    al4 = hl[4],
    al5 = hl[5],
    al6 = hl[6],
    al7 = hl[7]

  let h: number, l: number
  let th: number, tl: number
  let a: number, b: number, c: number, d: number

  while (len >= 128) {
    for (let i = 0; i < 16; i++) {
      const j = 8 * i + pos
      wh[i] = readUint32BE(m, j)
      wl[i] = readUint32BE(m, j + 4)
    }
    for (let i = 0; i < 80; i++) {
      let bh0 = ah0
      let bh1 = ah1
      let bh2 = ah2
      let bh3 = ah3
      let bh4 = ah4
      let bh5 = ah5
      let bh6 = ah6
      let bh7 = ah7

      let bl0 = al0
      let bl1 = al1
      let bl2 = al2
      let bl3 = al3
      let bl4 = al4
      let bl5 = al5
      let bl6 = al6
      let bl7 = al7

      // add
      h = ah7
      l = al7

      a = l & 0xffff
      b = l >>> 16
      c = h & 0xffff
      d = h >>> 16

      // Sigma1
      h =
        ((ah4 >>> 14) | (al4 << (32 - 14))) ^
        ((ah4 >>> 18) | (al4 << (32 - 18))) ^
        ((al4 >>> (41 - 32)) | (ah4 << (32 - (41 - 32))))
      l =
        ((al4 >>> 14) | (ah4 << (32 - 14))) ^
        ((al4 >>> 18) | (ah4 << (32 - 18))) ^
        ((ah4 >>> (41 - 32)) | (al4 << (32 - (41 - 32))))

      a += l & 0xffff
      b += l >>> 16
      c += h & 0xffff
      d += h >>> 16

      // Ch
      h = (ah4 & ah5) ^ (~ah4 & ah6)
      l = (al4 & al5) ^ (~al4 & al6)

      a += l & 0xffff
      b += l >>> 16
      c += h & 0xffff
      d += h >>> 16

      // K
      h = K[i * 2]
      l = K[i * 2 + 1]

      a += l & 0xffff
      b += l >>> 16
      c += h & 0xffff
      d += h >>> 16

      // w
      h = wh[i % 16]
      l = wl[i % 16]

      a += l & 0xffff
      b += l >>> 16
      c += h & 0xffff
      d += h >>> 16

      b += a >>> 16
      c += b >>> 16
      d += c >>> 16

      th = (c & 0xffff) | (d << 16)
      tl = (a & 0xffff) | (b << 16)

      // add
      h = th
      l = tl

      a = l & 0xffff
      b = l >>> 16
      c = h & 0xffff
      d = h >>> 16

      // Sigma0
      h =
        ((ah0 >>> 28) | (al0 << (32 - 28))) ^
        ((al0 >>> (34 - 32)) | (ah0 << (32 - (34 - 32)))) ^
        ((al0 >>> (39 - 32)) | (ah0 << (32 - (39 - 32))))
      l =
        ((al0 >>> 28) | (ah0 << (32 - 28))) ^
        ((ah0 >>> (34 - 32)) | (al0 << (32 - (34 - 32)))) ^
        ((ah0 >>> (39 - 32)) | (al0 << (32 - (39 - 32))))

      a += l & 0xffff
      b += l >>> 16
      c += h & 0xffff
      d += h >>> 16

      // Maj
      h = (ah0 & ah1) ^ (ah0 & ah2) ^ (ah1 & ah2)
      l = (al0 & al1) ^ (al0 & al2) ^ (al1 & al2)

      a += l & 0xffff
      b += l >>> 16
      c += h & 0xffff
      d += h >>> 16

      b += a >>> 16
      c += b >>> 16
      d += c >>> 16

      bh7 = (c & 0xffff) | (d << 16)
      bl7 = (a & 0xffff) | (b << 16)

      // add
      h = bh3
      l = bl3

      a = l & 0xffff
      b = l >>> 16
      c = h & 0xffff
      d = h >>> 16

      h = th
      l = tl

      a += l & 0xffff
      b += l >>> 16
      c += h & 0xffff
      d += h >>> 16

      b += a >>> 16
      c += b >>> 16
      d += c >>> 16

      bh3 = (c & 0xffff) | (d << 16)
      bl3 = (a & 0xffff) | (b << 16)

      ah1 = bh0
      ah2 = bh1
      ah3 = bh2
      ah4 = bh3
      ah5 = bh4
      ah6 = bh5
      ah7 = bh6
      ah0 = bh7

      al1 = bl0
      al2 = bl1
      al3 = bl2
      al4 = bl3
      al5 = bl4
      al6 = bl5
      al7 = bl6
      al0 = bl7

      if (i % 16 === 15) {
        for (let j = 0; j < 16; j++) {
          // add
          h = wh[j]
          l = wl[j]

          a = l & 0xffff
          b = l >>> 16
          c = h & 0xffff
          d = h >>> 16

          h = wh[(j + 9) % 16]
          l = wl[(j + 9) % 16]

          a += l & 0xffff
          b += l >>> 16
          c += h & 0xffff
          d += h >>> 16

          // sigma0
          th = wh[(j + 1) % 16]
          tl = wl[(j + 1) % 16]
          h = ((th >>> 1) | (tl << (32 - 1))) ^ ((th >>> 8) | (tl << (32 - 8))) ^ (th >>> 7)
          l =
            ((tl >>> 1) | (th << (32 - 1))) ^
            ((tl >>> 8) | (th << (32 - 8))) ^
            ((tl >>> 7) | (th << (32 - 7)))

          a += l & 0xffff
          b += l >>> 16
          c += h & 0xffff
          d += h >>> 16

          // sigma1
          th = wh[(j + 14) % 16]
          tl = wl[(j + 14) % 16]
          h =
            ((th >>> 19) | (tl << (32 - 19))) ^
            ((tl >>> (61 - 32)) | (th << (32 - (61 - 32)))) ^
            (th >>> 6)
          l =
            ((tl >>> 19) | (th << (32 - 19))) ^
            ((th >>> (61 - 32)) | (tl << (32 - (61 - 32)))) ^
            ((tl >>> 6) | (th << (32 - 6)))

          a += l & 0xffff
          b += l >>> 16
          c += h & 0xffff
          d += h >>> 16

          b += a >>> 16
          c += b >>> 16
          d += c >>> 16

          wh[j] = (c & 0xffff) | (d << 16)
          wl[j] = (a & 0xffff) | (b << 16)
        }
      }
    }

    // add
    h = ah0
    l = al0

    a = l & 0xffff
    b = l >>> 16
    c = h & 0xffff
    d = h >>> 16

    h = hh[0]
    l = hl[0]

    a += l & 0xffff
    b += l >>> 16
    c += h & 0xffff
    d += h >>> 16

    b += a >>> 16
    c += b >>> 16
    d += c >>> 16

    hh[0] = ah0 = (c & 0xffff) | (d << 16)
    hl[0] = al0 = (a & 0xffff) | (b << 16)

    h = ah1
    l = al1

    a = l & 0xffff
    b = l >>> 16
    c = h & 0xffff
    d = h >>> 16

    h = hh[1]
    l = hl[1]

    a += l & 0xffff
    b += l >>> 16
    c += h & 0xffff
    d += h >>> 16

    b += a >>> 16
    c += b >>> 16
    d += c >>> 16

    hh[1] = ah1 = (c & 0xffff) | (d << 16)
    hl[1] = al1 = (a & 0xffff) | (b << 16)

    h = ah2
    l = al2

    a = l & 0xffff
    b = l >>> 16
    c = h & 0xffff
    d = h >>> 16

    h = hh[2]
    l = hl[2]

    a += l & 0xffff
    b += l >>> 16
    c += h & 0xffff
    d += h >>> 16

    b += a >>> 16
    c += b >>> 16
    d += c >>> 16

    hh[2] = ah2 = (c & 0xffff) | (d << 16)
    hl[2] = al2 = (a & 0xffff) | (b << 16)

    h = ah3
    l = al3

    a = l & 0xffff
    b = l >>> 16
    c = h & 0xffff
    d = h >>> 16

    h = hh[3]
    l = hl[3]

    a += l & 0xffff
    b += l >>> 16
    c += h & 0xffff
    d += h >>> 16

    b += a >>> 16
    c += b >>> 16
    d += c >>> 16

    hh[3] = ah3 = (c & 0xffff) | (d << 16)
    hl[3] = al3 = (a & 0xffff) | (b << 16)

    h = ah4
    l = al4

    a = l & 0xffff
    b = l >>> 16
    c = h & 0xffff
    d = h >>> 16

    h = hh[4]
    l = hl[4]

    a += l & 0xffff
    b += l >>> 16
    c += h & 0xffff
    d += h >>> 16

    b += a >>> 16
    c += b >>> 16
    d += c >>> 16

    hh[4] = ah4 = (c & 0xffff) | (d << 16)
    hl[4] = al4 = (a & 0xffff) | (b << 16)

    h = ah5
    l = al5

    a = l & 0xffff
    b = l >>> 16
    c = h & 0xffff
    d = h >>> 16

    h = hh[5]
    l = hl[5]

    a += l & 0xffff
    b += l >>> 16
    c += h & 0xffff
    d += h >>> 16

    b += a >>> 16
    c += b >>> 16
    d += c >>> 16

    hh[5] = ah5 = (c & 0xffff) | (d << 16)
    hl[5] = al5 = (a & 0xffff) | (b << 16)

    h = ah6
    l = al6

    a = l & 0xffff
    b = l >>> 16
    c = h & 0xffff
    d = h >>> 16

    h = hh[6]
    l = hl[6]

    a += l & 0xffff
    b += l >>> 16
    c += h & 0xffff
    d += h >>> 16

    b += a >>> 16
    c += b >>> 16
    d += c >>> 16

    hh[6] = ah6 = (c & 0xffff) | (d << 16)
    hl[6] = al6 = (a & 0xffff) | (b << 16)

    h = ah7
    l = al7

    a = l & 0xffff
    b = l >>> 16
    c = h & 0xffff
    d = h >>> 16

    h = hh[7]
    l = hl[7]

    a += l & 0xffff
    b += l >>> 16
    c += h & 0xffff
    d += h >>> 16

    b += a >>> 16
    c += b >>> 16
    d += c >>> 16

    hh[7] = ah7 = (c & 0xffff) | (d << 16)
    hl[7] = al7 = (a & 0xffff) | (b << 16)

    pos += 128
    len -= 128
  }

  return pos
}

export function hash(data: Uint8Array): Uint8Array {
  const h = new SHA512()
  h.update(data)
  const digest = h.digest()
  h.clean()
  return digest
}
