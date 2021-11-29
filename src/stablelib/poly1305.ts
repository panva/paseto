// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package poly1305 implements Poly1305 one-time message authentication algorithm.
 */

import { equal as constantTimeEqual } from './constant-time.js'
import { wipe } from './wipe.js'

export const DIGEST_LENGTH = 16

// Port of Andrew Moon's Poly1305-donna-16. Public domain.
// https://github.com/floodyberry/poly1305-donna

/**
 * Poly1305 computes 16-byte authenticator of message using
 * a one-time 32-byte key.
 *
 * Important: key should be used for only one message,
 * it should never repeat.
 */
export class Poly1305 {
  readonly digestLength = DIGEST_LENGTH

  private _buffer = new Uint8Array(16)
  private _r = new Uint16Array(10)
  private _h = new Uint16Array(10)
  private _pad = new Uint16Array(8)
  private _leftover = 0
  private _fin = 0
  private _finished = false

  constructor(key: Uint8Array) {
    let t0 = key[0] | (key[1] << 8)
    this._r[0] = t0 & 0x1fff
    let t1 = key[2] | (key[3] << 8)
    this._r[1] = ((t0 >>> 13) | (t1 << 3)) & 0x1fff
    let t2 = key[4] | (key[5] << 8)
    this._r[2] = ((t1 >>> 10) | (t2 << 6)) & 0x1f03
    let t3 = key[6] | (key[7] << 8)
    this._r[3] = ((t2 >>> 7) | (t3 << 9)) & 0x1fff
    let t4 = key[8] | (key[9] << 8)
    this._r[4] = ((t3 >>> 4) | (t4 << 12)) & 0x00ff
    this._r[5] = (t4 >>> 1) & 0x1ffe
    let t5 = key[10] | (key[11] << 8)
    this._r[6] = ((t4 >>> 14) | (t5 << 2)) & 0x1fff
    let t6 = key[12] | (key[13] << 8)
    this._r[7] = ((t5 >>> 11) | (t6 << 5)) & 0x1f81
    let t7 = key[14] | (key[15] << 8)
    this._r[8] = ((t6 >>> 8) | (t7 << 8)) & 0x1fff
    this._r[9] = (t7 >>> 5) & 0x007f

    this._pad[0] = key[16] | (key[17] << 8)
    this._pad[1] = key[18] | (key[19] << 8)
    this._pad[2] = key[20] | (key[21] << 8)
    this._pad[3] = key[22] | (key[23] << 8)
    this._pad[4] = key[24] | (key[25] << 8)
    this._pad[5] = key[26] | (key[27] << 8)
    this._pad[6] = key[28] | (key[29] << 8)
    this._pad[7] = key[30] | (key[31] << 8)
  }

  private _blocks(m: Uint8Array, mpos: number, bytes: number) {
    let hibit = this._fin ? 0 : 1 << 11

    let h0 = this._h[0],
      h1 = this._h[1],
      h2 = this._h[2],
      h3 = this._h[3],
      h4 = this._h[4],
      h5 = this._h[5],
      h6 = this._h[6],
      h7 = this._h[7],
      h8 = this._h[8],
      h9 = this._h[9]

    let r0 = this._r[0],
      r1 = this._r[1],
      r2 = this._r[2],
      r3 = this._r[3],
      r4 = this._r[4],
      r5 = this._r[5],
      r6 = this._r[6],
      r7 = this._r[7],
      r8 = this._r[8],
      r9 = this._r[9]

    while (bytes >= 16) {
      let t0 = m[mpos + 0] | (m[mpos + 1] << 8)
      h0 += t0 & 0x1fff
      let t1 = m[mpos + 2] | (m[mpos + 3] << 8)
      h1 += ((t0 >>> 13) | (t1 << 3)) & 0x1fff
      let t2 = m[mpos + 4] | (m[mpos + 5] << 8)
      h2 += ((t1 >>> 10) | (t2 << 6)) & 0x1fff
      let t3 = m[mpos + 6] | (m[mpos + 7] << 8)
      h3 += ((t2 >>> 7) | (t3 << 9)) & 0x1fff
      let t4 = m[mpos + 8] | (m[mpos + 9] << 8)
      h4 += ((t3 >>> 4) | (t4 << 12)) & 0x1fff
      h5 += (t4 >>> 1) & 0x1fff
      let t5 = m[mpos + 10] | (m[mpos + 11] << 8)
      h6 += ((t4 >>> 14) | (t5 << 2)) & 0x1fff
      let t6 = m[mpos + 12] | (m[mpos + 13] << 8)
      h7 += ((t5 >>> 11) | (t6 << 5)) & 0x1fff
      let t7 = m[mpos + 14] | (m[mpos + 15] << 8)
      h8 += ((t6 >>> 8) | (t7 << 8)) & 0x1fff
      h9 += (t7 >>> 5) | hibit

      let c = 0

      let d0 = c
      d0 += h0 * r0
      d0 += h1 * (5 * r9)
      d0 += h2 * (5 * r8)
      d0 += h3 * (5 * r7)
      d0 += h4 * (5 * r6)
      c = d0 >>> 13
      d0 &= 0x1fff
      d0 += h5 * (5 * r5)
      d0 += h6 * (5 * r4)
      d0 += h7 * (5 * r3)
      d0 += h8 * (5 * r2)
      d0 += h9 * (5 * r1)
      c += d0 >>> 13
      d0 &= 0x1fff

      let d1 = c
      d1 += h0 * r1
      d1 += h1 * r0
      d1 += h2 * (5 * r9)
      d1 += h3 * (5 * r8)
      d1 += h4 * (5 * r7)
      c = d1 >>> 13
      d1 &= 0x1fff
      d1 += h5 * (5 * r6)
      d1 += h6 * (5 * r5)
      d1 += h7 * (5 * r4)
      d1 += h8 * (5 * r3)
      d1 += h9 * (5 * r2)
      c += d1 >>> 13
      d1 &= 0x1fff

      let d2 = c
      d2 += h0 * r2
      d2 += h1 * r1
      d2 += h2 * r0
      d2 += h3 * (5 * r9)
      d2 += h4 * (5 * r8)
      c = d2 >>> 13
      d2 &= 0x1fff
      d2 += h5 * (5 * r7)
      d2 += h6 * (5 * r6)
      d2 += h7 * (5 * r5)
      d2 += h8 * (5 * r4)
      d2 += h9 * (5 * r3)
      c += d2 >>> 13
      d2 &= 0x1fff

      let d3 = c
      d3 += h0 * r3
      d3 += h1 * r2
      d3 += h2 * r1
      d3 += h3 * r0
      d3 += h4 * (5 * r9)
      c = d3 >>> 13
      d3 &= 0x1fff
      d3 += h5 * (5 * r8)
      d3 += h6 * (5 * r7)
      d3 += h7 * (5 * r6)
      d3 += h8 * (5 * r5)
      d3 += h9 * (5 * r4)
      c += d3 >>> 13
      d3 &= 0x1fff

      let d4 = c
      d4 += h0 * r4
      d4 += h1 * r3
      d4 += h2 * r2
      d4 += h3 * r1
      d4 += h4 * r0
      c = d4 >>> 13
      d4 &= 0x1fff
      d4 += h5 * (5 * r9)
      d4 += h6 * (5 * r8)
      d4 += h7 * (5 * r7)
      d4 += h8 * (5 * r6)
      d4 += h9 * (5 * r5)
      c += d4 >>> 13
      d4 &= 0x1fff

      let d5 = c
      d5 += h0 * r5
      d5 += h1 * r4
      d5 += h2 * r3
      d5 += h3 * r2
      d5 += h4 * r1
      c = d5 >>> 13
      d5 &= 0x1fff
      d5 += h5 * r0
      d5 += h6 * (5 * r9)
      d5 += h7 * (5 * r8)
      d5 += h8 * (5 * r7)
      d5 += h9 * (5 * r6)
      c += d5 >>> 13
      d5 &= 0x1fff

      let d6 = c
      d6 += h0 * r6
      d6 += h1 * r5
      d6 += h2 * r4
      d6 += h3 * r3
      d6 += h4 * r2
      c = d6 >>> 13
      d6 &= 0x1fff
      d6 += h5 * r1
      d6 += h6 * r0
      d6 += h7 * (5 * r9)
      d6 += h8 * (5 * r8)
      d6 += h9 * (5 * r7)
      c += d6 >>> 13
      d6 &= 0x1fff

      let d7 = c
      d7 += h0 * r7
      d7 += h1 * r6
      d7 += h2 * r5
      d7 += h3 * r4
      d7 += h4 * r3
      c = d7 >>> 13
      d7 &= 0x1fff
      d7 += h5 * r2
      d7 += h6 * r1
      d7 += h7 * r0
      d7 += h8 * (5 * r9)
      d7 += h9 * (5 * r8)
      c += d7 >>> 13
      d7 &= 0x1fff

      let d8 = c
      d8 += h0 * r8
      d8 += h1 * r7
      d8 += h2 * r6
      d8 += h3 * r5
      d8 += h4 * r4
      c = d8 >>> 13
      d8 &= 0x1fff
      d8 += h5 * r3
      d8 += h6 * r2
      d8 += h7 * r1
      d8 += h8 * r0
      d8 += h9 * (5 * r9)
      c += d8 >>> 13
      d8 &= 0x1fff

      let d9 = c
      d9 += h0 * r9
      d9 += h1 * r8
      d9 += h2 * r7
      d9 += h3 * r6
      d9 += h4 * r5
      c = d9 >>> 13
      d9 &= 0x1fff
      d9 += h5 * r4
      d9 += h6 * r3
      d9 += h7 * r2
      d9 += h8 * r1
      d9 += h9 * r0
      c += d9 >>> 13
      d9 &= 0x1fff

      c = ((c << 2) + c) | 0
      c = (c + d0) | 0
      d0 = c & 0x1fff
      c = c >>> 13
      d1 += c

      h0 = d0
      h1 = d1
      h2 = d2
      h3 = d3
      h4 = d4
      h5 = d5
      h6 = d6
      h7 = d7
      h8 = d8
      h9 = d9

      mpos += 16
      bytes -= 16
    }
    this._h[0] = h0
    this._h[1] = h1
    this._h[2] = h2
    this._h[3] = h3
    this._h[4] = h4
    this._h[5] = h5
    this._h[6] = h6
    this._h[7] = h7
    this._h[8] = h8
    this._h[9] = h9
  }

  finish(mac: Uint8Array, macpos = 0): this {
    const g = new Uint16Array(10)
    let c: number
    let mask: number
    let f: number
    let i: number

    if (this._leftover) {
      i = this._leftover
      this._buffer[i++] = 1
      for (; i < 16; i++) {
        this._buffer[i] = 0
      }
      this._fin = 1
      this._blocks(this._buffer, 0, 16)
    }

    c = this._h[1] >>> 13
    this._h[1] &= 0x1fff
    for (i = 2; i < 10; i++) {
      this._h[i] += c
      c = this._h[i] >>> 13
      this._h[i] &= 0x1fff
    }
    this._h[0] += c * 5
    c = this._h[0] >>> 13
    this._h[0] &= 0x1fff
    this._h[1] += c
    c = this._h[1] >>> 13
    this._h[1] &= 0x1fff
    this._h[2] += c

    g[0] = this._h[0] + 5
    c = g[0] >>> 13
    g[0] &= 0x1fff
    for (i = 1; i < 10; i++) {
      g[i] = this._h[i] + c
      c = g[i] >>> 13
      g[i] &= 0x1fff
    }
    g[9] -= 1 << 13

    mask = (c ^ 1) - 1
    for (i = 0; i < 10; i++) {
      g[i] &= mask
    }
    mask = ~mask
    for (i = 0; i < 10; i++) {
      this._h[i] = (this._h[i] & mask) | g[i]
    }

    this._h[0] = (this._h[0] | (this._h[1] << 13)) & 0xffff
    this._h[1] = ((this._h[1] >>> 3) | (this._h[2] << 10)) & 0xffff
    this._h[2] = ((this._h[2] >>> 6) | (this._h[3] << 7)) & 0xffff
    this._h[3] = ((this._h[3] >>> 9) | (this._h[4] << 4)) & 0xffff
    this._h[4] = ((this._h[4] >>> 12) | (this._h[5] << 1) | (this._h[6] << 14)) & 0xffff
    this._h[5] = ((this._h[6] >>> 2) | (this._h[7] << 11)) & 0xffff
    this._h[6] = ((this._h[7] >>> 5) | (this._h[8] << 8)) & 0xffff
    this._h[7] = ((this._h[8] >>> 8) | (this._h[9] << 5)) & 0xffff

    f = this._h[0] + this._pad[0]
    this._h[0] = f & 0xffff
    for (i = 1; i < 8; i++) {
      f = (((this._h[i] + this._pad[i]) | 0) + (f >>> 16)) | 0
      this._h[i] = f & 0xffff
    }

    mac[macpos + 0] = this._h[0] >>> 0
    mac[macpos + 1] = this._h[0] >>> 8
    mac[macpos + 2] = this._h[1] >>> 0
    mac[macpos + 3] = this._h[1] >>> 8
    mac[macpos + 4] = this._h[2] >>> 0
    mac[macpos + 5] = this._h[2] >>> 8
    mac[macpos + 6] = this._h[3] >>> 0
    mac[macpos + 7] = this._h[3] >>> 8
    mac[macpos + 8] = this._h[4] >>> 0
    mac[macpos + 9] = this._h[4] >>> 8
    mac[macpos + 10] = this._h[5] >>> 0
    mac[macpos + 11] = this._h[5] >>> 8
    mac[macpos + 12] = this._h[6] >>> 0
    mac[macpos + 13] = this._h[6] >>> 8
    mac[macpos + 14] = this._h[7] >>> 0
    mac[macpos + 15] = this._h[7] >>> 8

    this._finished = true
    return this
  }

  update(m: Uint8Array): this {
    let mpos = 0
    let bytes = m.length
    let want: number

    if (this._leftover) {
      want = 16 - this._leftover
      if (want > bytes) {
        want = bytes
      }
      for (let i = 0; i < want; i++) {
        this._buffer[this._leftover + i] = m[mpos + i]
      }
      bytes -= want
      mpos += want
      this._leftover += want
      if (this._leftover < 16) {
        return this
      }
      this._blocks(this._buffer, 0, 16)
      this._leftover = 0
    }

    if (bytes >= 16) {
      want = bytes - (bytes % 16)
      this._blocks(m, mpos, want)
      mpos += want
      bytes -= want
    }

    if (bytes) {
      for (let i = 0; i < bytes; i++) {
        this._buffer[this._leftover + i] = m[mpos + i]
      }
      this._leftover += bytes
    }

    return this
  }

  digest(): Uint8Array {
    // TODO(dchest): it behaves differently than other hashes/HMAC,
    // because it throws when finished — others just return saved result.
    if (this._finished) {
      throw new Error('Poly1305 was finished')
    }
    let mac = new Uint8Array(16)
    this.finish(mac)
    return mac
  }

  clean(): this {
    wipe(this._buffer)
    wipe(this._r)
    wipe(this._h)
    wipe(this._pad)
    this._leftover = 0
    this._fin = 0
    this._finished = true // mark as finished even if not
    return this
  }
}

/**
 * Returns 16-byte authenticator of data using a one-time 32-byte key.
 *
 * Important: key should be used for only one message, it should never repeat.
 */
export function oneTimeAuth(key: Uint8Array, data: Uint8Array): Uint8Array {
  const h = new Poly1305(key)
  h.update(data)
  const digest = h.digest()
  h.clean()
  return digest
}

/**
 * Returns true if two authenticators are 16-byte long and equal.
 * Uses contant-time comparison to avoid leaking timing information.
 */
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== DIGEST_LENGTH || b.length !== DIGEST_LENGTH) {
    return false
  }
  return constantTimeEqual(a, b)
}
