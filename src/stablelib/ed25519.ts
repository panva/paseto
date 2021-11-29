// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package ed25519 implements Ed25519 public-key signature algorithm.
 */

import { hash, SHA512 } from './sha512.js'

export const SIGNATURE_LENGTH = 64
export const PUBLIC_KEY_LENGTH = 32
export const SECRET_KEY_LENGTH = 64
export const SEED_LENGTH = 32

// Ported from TweetNaCl.js, which was ported from TweetNaCl
// by Dmitry Chestnykh and Devi Mandiri.
// Public domain.
// https://tweetnacl.js.org

// TweetNaCl contributors:
// Daniel J. Bernstein, Bernard van Gastel, Wesley Janssen,
// Tanja Lange, Peter Schwabe, Sjaak Smetsers.
// Public domain.
// https://tweetnacl.cr.yp.to/

type GF = Float64Array

// Returns new zero-filled 16-element GF (Float64Array).
// If passed an array of numbers, prefills the returned
// array with them.
//
// We use Float64Array, because we need 48-bit numbers
// for this implementation.
function gf(init?: number[]): GF {
  const r = new Float64Array(16)
  if (init) {
    for (let i = 0; i < init.length; i++) {
      r[i] = init[i]
    }
  }
  return r
}

const gf0 = gf()

const gf1 = gf([1])

const D = gf([
  0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7,
  0xfe73, 0x2b6f, 0x6cee, 0x5203,
])

const D2 = gf([
  0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e,
  0xfce7, 0x56df, 0xd9dc, 0x2406,
])

const X = gf([
  0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
  0x53fe, 0xcd6e, 0x36d3, 0x2169,
])

const Y = gf([
  0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
  0x6666, 0x6666, 0x6666, 0x6666,
])

const I = gf([
  0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
  0xdf0b, 0x4fc1, 0x2480, 0x2b83,
])

function set25519(r: GF, a: GF) {
  for (let i = 0; i < 16; i++) {
    r[i] = a[i] | 0
  }
}

function car25519(o: GF) {
  let c = 1
  for (let i = 0; i < 16; i++) {
    let v = o[i] + c + 65535
    c = Math.floor(v / 65536)
    o[i] = v - c * 65536
  }
  o[0] += c - 1 + 37 * (c - 1)
}

function sel25519(p: GF, q: GF, b: number) {
  const c = ~(b - 1)
  for (let i = 0; i < 16; i++) {
    const t = c & (p[i] ^ q[i])
    p[i] ^= t
    q[i] ^= t
  }
}

function pack25519(o: Uint8Array, n: GF) {
  const m = gf()
  const t = gf()
  for (let i = 0; i < 16; i++) {
    t[i] = n[i]
  }
  car25519(t)
  car25519(t)
  car25519(t)
  for (let j = 0; j < 2; j++) {
    m[0] = t[0] - 0xffed
    for (let i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1)
      m[i - 1] &= 0xffff
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1)
    const b = (m[15] >> 16) & 1
    m[14] &= 0xffff
    sel25519(t, m, 1 - b)
  }
  for (let i = 0; i < 16; i++) {
    o[2 * i] = t[i] & 0xff
    o[2 * i + 1] = t[i] >> 8
  }
}

function verify32(x: Uint8Array, y: Uint8Array) {
  let d = 0
  for (let i = 0; i < 32; i++) {
    d |= x[i] ^ y[i]
  }
  return (1 & ((d - 1) >>> 8)) - 1
}

function neq25519(a: GF, b: GF) {
  const c = new Uint8Array(32)
  const d = new Uint8Array(32)
  pack25519(c, a)
  pack25519(d, b)
  return verify32(c, d)
}

function par25519(a: GF) {
  const d = new Uint8Array(32)
  pack25519(d, a)
  return d[0] & 1
}

function unpack25519(o: GF, n: Uint8Array) {
  for (let i = 0; i < 16; i++) {
    o[i] = n[2 * i] + (n[2 * i + 1] << 8)
  }
  o[15] &= 0x7fff
}

function add(o: GF, a: GF, b: GF) {
  for (let i = 0; i < 16; i++) {
    o[i] = a[i] + b[i]
  }
}

function sub(o: GF, a: GF, b: GF) {
  for (let i = 0; i < 16; i++) {
    o[i] = a[i] - b[i]
  }
}

function mul(o: GF, a: GF, b: GF) {
  let v: number,
    c: number,
    t0 = 0,
    t1 = 0,
    t2 = 0,
    t3 = 0,
    t4 = 0,
    t5 = 0,
    t6 = 0,
    t7 = 0,
    t8 = 0,
    t9 = 0,
    t10 = 0,
    t11 = 0,
    t12 = 0,
    t13 = 0,
    t14 = 0,
    t15 = 0,
    t16 = 0,
    t17 = 0,
    t18 = 0,
    t19 = 0,
    t20 = 0,
    t21 = 0,
    t22 = 0,
    t23 = 0,
    t24 = 0,
    t25 = 0,
    t26 = 0,
    t27 = 0,
    t28 = 0,
    t29 = 0,
    t30 = 0,
    b0 = b[0],
    b1 = b[1],
    b2 = b[2],
    b3 = b[3],
    b4 = b[4],
    b5 = b[5],
    b6 = b[6],
    b7 = b[7],
    b8 = b[8],
    b9 = b[9],
    b10 = b[10],
    b11 = b[11],
    b12 = b[12],
    b13 = b[13],
    b14 = b[14],
    b15 = b[15]

  v = a[0]
  t0 += v * b0
  t1 += v * b1
  t2 += v * b2
  t3 += v * b3
  t4 += v * b4
  t5 += v * b5
  t6 += v * b6
  t7 += v * b7
  t8 += v * b8
  t9 += v * b9
  t10 += v * b10
  t11 += v * b11
  t12 += v * b12
  t13 += v * b13
  t14 += v * b14
  t15 += v * b15
  v = a[1]
  t1 += v * b0
  t2 += v * b1
  t3 += v * b2
  t4 += v * b3
  t5 += v * b4
  t6 += v * b5
  t7 += v * b6
  t8 += v * b7
  t9 += v * b8
  t10 += v * b9
  t11 += v * b10
  t12 += v * b11
  t13 += v * b12
  t14 += v * b13
  t15 += v * b14
  t16 += v * b15
  v = a[2]
  t2 += v * b0
  t3 += v * b1
  t4 += v * b2
  t5 += v * b3
  t6 += v * b4
  t7 += v * b5
  t8 += v * b6
  t9 += v * b7
  t10 += v * b8
  t11 += v * b9
  t12 += v * b10
  t13 += v * b11
  t14 += v * b12
  t15 += v * b13
  t16 += v * b14
  t17 += v * b15
  v = a[3]
  t3 += v * b0
  t4 += v * b1
  t5 += v * b2
  t6 += v * b3
  t7 += v * b4
  t8 += v * b5
  t9 += v * b6
  t10 += v * b7
  t11 += v * b8
  t12 += v * b9
  t13 += v * b10
  t14 += v * b11
  t15 += v * b12
  t16 += v * b13
  t17 += v * b14
  t18 += v * b15
  v = a[4]
  t4 += v * b0
  t5 += v * b1
  t6 += v * b2
  t7 += v * b3
  t8 += v * b4
  t9 += v * b5
  t10 += v * b6
  t11 += v * b7
  t12 += v * b8
  t13 += v * b9
  t14 += v * b10
  t15 += v * b11
  t16 += v * b12
  t17 += v * b13
  t18 += v * b14
  t19 += v * b15
  v = a[5]
  t5 += v * b0
  t6 += v * b1
  t7 += v * b2
  t8 += v * b3
  t9 += v * b4
  t10 += v * b5
  t11 += v * b6
  t12 += v * b7
  t13 += v * b8
  t14 += v * b9
  t15 += v * b10
  t16 += v * b11
  t17 += v * b12
  t18 += v * b13
  t19 += v * b14
  t20 += v * b15
  v = a[6]
  t6 += v * b0
  t7 += v * b1
  t8 += v * b2
  t9 += v * b3
  t10 += v * b4
  t11 += v * b5
  t12 += v * b6
  t13 += v * b7
  t14 += v * b8
  t15 += v * b9
  t16 += v * b10
  t17 += v * b11
  t18 += v * b12
  t19 += v * b13
  t20 += v * b14
  t21 += v * b15
  v = a[7]
  t7 += v * b0
  t8 += v * b1
  t9 += v * b2
  t10 += v * b3
  t11 += v * b4
  t12 += v * b5
  t13 += v * b6
  t14 += v * b7
  t15 += v * b8
  t16 += v * b9
  t17 += v * b10
  t18 += v * b11
  t19 += v * b12
  t20 += v * b13
  t21 += v * b14
  t22 += v * b15
  v = a[8]
  t8 += v * b0
  t9 += v * b1
  t10 += v * b2
  t11 += v * b3
  t12 += v * b4
  t13 += v * b5
  t14 += v * b6
  t15 += v * b7
  t16 += v * b8
  t17 += v * b9
  t18 += v * b10
  t19 += v * b11
  t20 += v * b12
  t21 += v * b13
  t22 += v * b14
  t23 += v * b15
  v = a[9]
  t9 += v * b0
  t10 += v * b1
  t11 += v * b2
  t12 += v * b3
  t13 += v * b4
  t14 += v * b5
  t15 += v * b6
  t16 += v * b7
  t17 += v * b8
  t18 += v * b9
  t19 += v * b10
  t20 += v * b11
  t21 += v * b12
  t22 += v * b13
  t23 += v * b14
  t24 += v * b15
  v = a[10]
  t10 += v * b0
  t11 += v * b1
  t12 += v * b2
  t13 += v * b3
  t14 += v * b4
  t15 += v * b5
  t16 += v * b6
  t17 += v * b7
  t18 += v * b8
  t19 += v * b9
  t20 += v * b10
  t21 += v * b11
  t22 += v * b12
  t23 += v * b13
  t24 += v * b14
  t25 += v * b15
  v = a[11]
  t11 += v * b0
  t12 += v * b1
  t13 += v * b2
  t14 += v * b3
  t15 += v * b4
  t16 += v * b5
  t17 += v * b6
  t18 += v * b7
  t19 += v * b8
  t20 += v * b9
  t21 += v * b10
  t22 += v * b11
  t23 += v * b12
  t24 += v * b13
  t25 += v * b14
  t26 += v * b15
  v = a[12]
  t12 += v * b0
  t13 += v * b1
  t14 += v * b2
  t15 += v * b3
  t16 += v * b4
  t17 += v * b5
  t18 += v * b6
  t19 += v * b7
  t20 += v * b8
  t21 += v * b9
  t22 += v * b10
  t23 += v * b11
  t24 += v * b12
  t25 += v * b13
  t26 += v * b14
  t27 += v * b15
  v = a[13]
  t13 += v * b0
  t14 += v * b1
  t15 += v * b2
  t16 += v * b3
  t17 += v * b4
  t18 += v * b5
  t19 += v * b6
  t20 += v * b7
  t21 += v * b8
  t22 += v * b9
  t23 += v * b10
  t24 += v * b11
  t25 += v * b12
  t26 += v * b13
  t27 += v * b14
  t28 += v * b15
  v = a[14]
  t14 += v * b0
  t15 += v * b1
  t16 += v * b2
  t17 += v * b3
  t18 += v * b4
  t19 += v * b5
  t20 += v * b6
  t21 += v * b7
  t22 += v * b8
  t23 += v * b9
  t24 += v * b10
  t25 += v * b11
  t26 += v * b12
  t27 += v * b13
  t28 += v * b14
  t29 += v * b15
  v = a[15]
  t15 += v * b0
  t16 += v * b1
  t17 += v * b2
  t18 += v * b3
  t19 += v * b4
  t20 += v * b5
  t21 += v * b6
  t22 += v * b7
  t23 += v * b8
  t24 += v * b9
  t25 += v * b10
  t26 += v * b11
  t27 += v * b12
  t28 += v * b13
  t29 += v * b14
  t30 += v * b15

  t0 += 38 * t16
  t1 += 38 * t17
  t2 += 38 * t18
  t3 += 38 * t19
  t4 += 38 * t20
  t5 += 38 * t21
  t6 += 38 * t22
  t7 += 38 * t23
  t8 += 38 * t24
  t9 += 38 * t25
  t10 += 38 * t26
  t11 += 38 * t27
  t12 += 38 * t28
  t13 += 38 * t29
  t14 += 38 * t30
  // t15 left as is

  // first car
  c = 1
  v = t0 + c + 65535
  c = Math.floor(v / 65536)
  t0 = v - c * 65536
  v = t1 + c + 65535
  c = Math.floor(v / 65536)
  t1 = v - c * 65536
  v = t2 + c + 65535
  c = Math.floor(v / 65536)
  t2 = v - c * 65536
  v = t3 + c + 65535
  c = Math.floor(v / 65536)
  t3 = v - c * 65536
  v = t4 + c + 65535
  c = Math.floor(v / 65536)
  t4 = v - c * 65536
  v = t5 + c + 65535
  c = Math.floor(v / 65536)
  t5 = v - c * 65536
  v = t6 + c + 65535
  c = Math.floor(v / 65536)
  t6 = v - c * 65536
  v = t7 + c + 65535
  c = Math.floor(v / 65536)
  t7 = v - c * 65536
  v = t8 + c + 65535
  c = Math.floor(v / 65536)
  t8 = v - c * 65536
  v = t9 + c + 65535
  c = Math.floor(v / 65536)
  t9 = v - c * 65536
  v = t10 + c + 65535
  c = Math.floor(v / 65536)
  t10 = v - c * 65536
  v = t11 + c + 65535
  c = Math.floor(v / 65536)
  t11 = v - c * 65536
  v = t12 + c + 65535
  c = Math.floor(v / 65536)
  t12 = v - c * 65536
  v = t13 + c + 65535
  c = Math.floor(v / 65536)
  t13 = v - c * 65536
  v = t14 + c + 65535
  c = Math.floor(v / 65536)
  t14 = v - c * 65536
  v = t15 + c + 65535
  c = Math.floor(v / 65536)
  t15 = v - c * 65536
  t0 += c - 1 + 37 * (c - 1)

  // second car
  c = 1
  v = t0 + c + 65535
  c = Math.floor(v / 65536)
  t0 = v - c * 65536
  v = t1 + c + 65535
  c = Math.floor(v / 65536)
  t1 = v - c * 65536
  v = t2 + c + 65535
  c = Math.floor(v / 65536)
  t2 = v - c * 65536
  v = t3 + c + 65535
  c = Math.floor(v / 65536)
  t3 = v - c * 65536
  v = t4 + c + 65535
  c = Math.floor(v / 65536)
  t4 = v - c * 65536
  v = t5 + c + 65535
  c = Math.floor(v / 65536)
  t5 = v - c * 65536
  v = t6 + c + 65535
  c = Math.floor(v / 65536)
  t6 = v - c * 65536
  v = t7 + c + 65535
  c = Math.floor(v / 65536)
  t7 = v - c * 65536
  v = t8 + c + 65535
  c = Math.floor(v / 65536)
  t8 = v - c * 65536
  v = t9 + c + 65535
  c = Math.floor(v / 65536)
  t9 = v - c * 65536
  v = t10 + c + 65535
  c = Math.floor(v / 65536)
  t10 = v - c * 65536
  v = t11 + c + 65535
  c = Math.floor(v / 65536)
  t11 = v - c * 65536
  v = t12 + c + 65535
  c = Math.floor(v / 65536)
  t12 = v - c * 65536
  v = t13 + c + 65535
  c = Math.floor(v / 65536)
  t13 = v - c * 65536
  v = t14 + c + 65535
  c = Math.floor(v / 65536)
  t14 = v - c * 65536
  v = t15 + c + 65535
  c = Math.floor(v / 65536)
  t15 = v - c * 65536
  t0 += c - 1 + 37 * (c - 1)

  o[0] = t0
  o[1] = t1
  o[2] = t2
  o[3] = t3
  o[4] = t4
  o[5] = t5
  o[6] = t6
  o[7] = t7
  o[8] = t8
  o[9] = t9
  o[10] = t10
  o[11] = t11
  o[12] = t12
  o[13] = t13
  o[14] = t14
  o[15] = t15
}

function square(o: GF, a: GF) {
  mul(o, a, a)
}

function inv25519(o: GF, i: GF) {
  const c = gf()
  let a: number
  for (a = 0; a < 16; a++) {
    c[a] = i[a]
  }
  for (a = 253; a >= 0; a--) {
    square(c, c)
    if (a !== 2 && a !== 4) {
      mul(c, c, i)
    }
  }
  for (a = 0; a < 16; a++) {
    o[a] = c[a]
  }
}

function pow2523(o: GF, i: GF) {
  const c = gf()
  let a: number
  for (a = 0; a < 16; a++) {
    c[a] = i[a]
  }
  for (a = 250; a >= 0; a--) {
    square(c, c)
    if (a !== 1) {
      mul(c, c, i)
    }
  }
  for (a = 0; a < 16; a++) {
    o[a] = c[a]
  }
}

function edadd(p: GF[], q: GF[]) {
  const a = gf(),
    b = gf(),
    c = gf(),
    d = gf(),
    e = gf(),
    f = gf(),
    g = gf(),
    h = gf(),
    t = gf()

  sub(a, p[1], p[0])
  sub(t, q[1], q[0])
  mul(a, a, t)
  add(b, p[0], p[1])
  add(t, q[0], q[1])
  mul(b, b, t)
  mul(c, p[3], q[3])
  mul(c, c, D2)
  mul(d, p[2], q[2])
  add(d, d, d)
  sub(e, b, a)
  sub(f, d, c)
  add(g, d, c)
  add(h, b, a)

  mul(p[0], e, f)
  mul(p[1], h, g)
  mul(p[2], g, f)
  mul(p[3], e, h)
}

function cswap(p: GF[], q: GF[], b: number) {
  for (let i = 0; i < 4; i++) {
    sel25519(p[i], q[i], b)
  }
}

function pack(r: Uint8Array, p: GF[]) {
  const tx = gf(),
    ty = gf(),
    zi = gf()
  inv25519(zi, p[2])
  mul(tx, p[0], zi)
  mul(ty, p[1], zi)
  pack25519(r, ty)
  r[31] ^= par25519(tx) << 7
}

function scalarmult(p: GF[], q: GF[], s: Uint8Array) {
  set25519(p[0], gf0)
  set25519(p[1], gf1)
  set25519(p[2], gf1)
  set25519(p[3], gf0)
  for (let i = 255; i >= 0; --i) {
    const b = (s[(i / 8) | 0] >> (i & 7)) & 1
    cswap(p, q, b)
    edadd(q, p)
    edadd(p, p)
    cswap(p, q, b)
  }
}

function scalarbase(p: GF[], s: Uint8Array) {
  const q = [gf(), gf(), gf(), gf()]
  set25519(q[0], X)
  set25519(q[1], Y)
  set25519(q[2], gf1)
  mul(q[3], X, Y)
  scalarmult(p, q, s)
}

export interface KeyPair {
  publicKey: Uint8Array
  secretKey: Uint8Array
}

// Generates key pair from secret 32-byte seed.
export function generateKeyPairFromSeed(seed: Uint8Array): KeyPair {
  if (seed.length !== SEED_LENGTH) {
    throw new Error(`ed25519: seed must be ${SEED_LENGTH} bytes`)
  }

  const d = hash(seed)
  d[0] &= 248
  d[31] &= 127
  d[31] |= 64

  const publicKey = new Uint8Array(32)
  const p = [gf(), gf(), gf(), gf()]
  scalarbase(p, d)
  pack(publicKey, p)

  const secretKey = new Uint8Array(64)
  secretKey.set(seed)
  secretKey.set(publicKey, 32)

  return {
    publicKey,
    secretKey,
  }
}

export function extractPublicKeyFromSecretKey(secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== SECRET_KEY_LENGTH) {
    throw new Error(`ed25519: secret key must be ${SECRET_KEY_LENGTH} bytes`)
  }
  return new Uint8Array(secretKey.subarray(32))
}

const L = new Float64Array([
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
])

function modL(r: Uint8Array, x: Float64Array) {
  let carry: number
  let i: number
  let j: number
  let k: number
  for (i = 63; i >= 32; --i) {
    carry = 0
    for (j = i - 32, k = i - 12; j < k; ++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)]
      carry = Math.floor((x[j] + 128) / 256)
      x[j] -= carry * 256
    }
    x[j] += carry
    x[i] = 0
  }
  carry = 0
  for (j = 0; j < 32; j++) {
    x[j] += carry - (x[31] >> 4) * L[j]
    carry = x[j] >> 8
    x[j] &= 255
  }
  for (j = 0; j < 32; j++) {
    x[j] -= carry * L[j]
  }
  for (i = 0; i < 32; i++) {
    x[i + 1] += x[i] >> 8
    r[i] = x[i] & 255
  }
}

function reduce(r: Uint8Array) {
  const x = new Float64Array(64)
  for (let i = 0; i < 64; i++) {
    x[i] = r[i]
  }
  for (let i = 0; i < 64; i++) {
    r[i] = 0
  }
  modL(r, x)
}

// Returns 64-byte signature of the message under the 64-byte secret key.
export function sign(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  const x = new Float64Array(64)
  const p = [gf(), gf(), gf(), gf()]

  const d = hash(secretKey.subarray(0, 32))
  d[0] &= 248
  d[31] &= 127
  d[31] |= 64

  const signature = new Uint8Array(64)
  signature.set(d.subarray(32), 32)

  const hs = new SHA512()
  hs.update(signature.subarray(32))
  hs.update(message)
  const r = hs.digest()
  hs.clean()
  reduce(r)
  scalarbase(p, r)
  pack(signature, p)

  hs.reset()
  hs.update(signature.subarray(0, 32))
  hs.update(secretKey.subarray(32))
  hs.update(message)
  const h = hs.digest()
  reduce(h)

  for (let i = 0; i < 32; i++) {
    x[i] = r[i]
  }
  for (let i = 0; i < 32; i++) {
    for (let j = 0; j < 32; j++) {
      x[i + j] += h[i] * d[j]
    }
  }
  modL(signature.subarray(32), x)

  return signature
}

function unpackneg(r: GF[], p: Uint8Array) {
  const t = gf(),
    chk = gf(),
    num = gf(),
    den = gf(),
    den2 = gf(),
    den4 = gf(),
    den6 = gf()

  set25519(r[2], gf1)
  unpack25519(r[1], p)
  square(num, r[1])
  mul(den, num, D)
  sub(num, num, r[2])
  add(den, r[2], den)

  square(den2, den)
  square(den4, den2)
  mul(den6, den4, den2)
  mul(t, den6, num)
  mul(t, t, den)

  pow2523(t, t)
  mul(t, t, num)
  mul(t, t, den)
  mul(t, t, den)
  mul(r[0], t, den)

  square(chk, r[0])
  mul(chk, chk, den)
  if (neq25519(chk, num)) {
    mul(r[0], r[0], I)
  }

  square(chk, r[0])
  mul(chk, chk, den)
  if (neq25519(chk, num)) {
    return -1
  }

  if (par25519(r[0]) === p[31] >> 7) {
    sub(r[0], gf0, r[0])
  }

  mul(r[3], r[0], r[1])
  return 0
}

export function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  const t = new Uint8Array(32)
  const p = [gf(), gf(), gf(), gf()]
  const q = [gf(), gf(), gf(), gf()]

  if (signature.length !== SIGNATURE_LENGTH) {
    throw new Error(`ed25519: signature must be ${SIGNATURE_LENGTH} bytes`)
  }

  if (unpackneg(q, publicKey)) {
    return false
  }

  const hs = new SHA512()
  hs.update(signature.subarray(0, 32))
  hs.update(publicKey)
  hs.update(message)
  const h = hs.digest()
  reduce(h)
  scalarmult(p, q, h)

  scalarbase(q, signature.subarray(32))
  edadd(p, q)
  pack(t, p)

  if (verify32(signature, t)) {
    return false
  }
  return true
}
