// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package binary provides functions for encoding and decoding numbers in byte arrays.
 */

import { isSafeInteger } from './int.js'

// TODO(dchest): add asserts for correct value ranges and array offsets.

/**
 * Reads 2 bytes from array starting at offset as big-endian
 * signed 16-bit integer and returns it.
 */
export function readInt16BE(array: Uint8Array, offset = 0): number {
  return (((array[offset + 0] << 8) | array[offset + 1]) << 16) >> 16
}

/**
 * Reads 2 bytes from array starting at offset as big-endian
 * unsigned 16-bit integer and returns it.
 */
export function readUint16BE(array: Uint8Array, offset = 0): number {
  return ((array[offset + 0] << 8) | array[offset + 1]) >>> 0
}

/**
 * Reads 2 bytes from array starting at offset as little-endian
 * signed 16-bit integer and returns it.
 */
export function readInt16LE(array: Uint8Array, offset = 0): number {
  return (((array[offset + 1] << 8) | array[offset]) << 16) >> 16
}

/**
 * Reads 2 bytes from array starting at offset as little-endian
 * unsigned 16-bit integer and returns it.
 */
export function readUint16LE(array: Uint8Array, offset = 0): number {
  return ((array[offset + 1] << 8) | array[offset]) >>> 0
}

/**
 * Writes 2-byte big-endian representation of 16-bit unsigned
 * value to byte array starting at offset.
 *
 * If byte array is not given, creates a new 2-byte one.
 *
 * Returns the output byte array.
 */
export function writeUint16BE(value: number, out = new Uint8Array(2), offset = 0): Uint8Array {
  out[offset + 0] = value >>> 8
  out[offset + 1] = value >>> 0
  return out
}

export const writeInt16BE = writeUint16BE

/**
 * Writes 2-byte little-endian representation of 16-bit unsigned
 * value to array starting at offset.
 *
 * If byte array is not given, creates a new 2-byte one.
 *
 * Returns the output byte array.
 */
export function writeUint16LE(value: number, out = new Uint8Array(2), offset = 0): Uint8Array {
  out[offset + 0] = value >>> 0
  out[offset + 1] = value >>> 8
  return out
}

export const writeInt16LE = writeUint16LE

/**
 * Reads 4 bytes from array starting at offset as big-endian
 * signed 32-bit integer and returns it.
 */
export function readInt32BE(array: Uint8Array, offset = 0): number {
  return (
    (array[offset] << 24) | (array[offset + 1] << 16) | (array[offset + 2] << 8) | array[offset + 3]
  )
}

/**
 * Reads 4 bytes from array starting at offset as big-endian
 * unsigned 32-bit integer and returns it.
 */
export function readUint32BE(array: Uint8Array, offset = 0): number {
  return (
    ((array[offset] << 24) |
      (array[offset + 1] << 16) |
      (array[offset + 2] << 8) |
      array[offset + 3]) >>>
    0
  )
}

/**
 * Reads 4 bytes from array starting at offset as little-endian
 * signed 32-bit integer and returns it.
 */
export function readInt32LE(array: Uint8Array, offset = 0): number {
  return (
    (array[offset + 3] << 24) | (array[offset + 2] << 16) | (array[offset + 1] << 8) | array[offset]
  )
}

/**
 * Reads 4 bytes from array starting at offset as little-endian
 * unsigned 32-bit integer and returns it.
 */
export function readUint32LE(array: Uint8Array, offset = 0): number {
  return (
    ((array[offset + 3] << 24) |
      (array[offset + 2] << 16) |
      (array[offset + 1] << 8) |
      array[offset]) >>>
    0
  )
}

/**
 * Writes 4-byte big-endian representation of 32-bit unsigned
 * value to byte array starting at offset.
 *
 * If byte array is not given, creates a new 4-byte one.
 *
 * Returns the output byte array.
 */
export function writeUint32BE(value: number, out = new Uint8Array(4), offset = 0): Uint8Array {
  out[offset + 0] = value >>> 24
  out[offset + 1] = value >>> 16
  out[offset + 2] = value >>> 8
  out[offset + 3] = value >>> 0
  return out
}

export const writeInt32BE = writeUint32BE

/**
 * Writes 4-byte little-endian representation of 32-bit unsigned
 * value to array starting at offset.
 *
 * If byte array is not given, creates a new 4-byte one.
 *
 * Returns the output byte array.
 */
export function writeUint32LE(value: number, out = new Uint8Array(4), offset = 0): Uint8Array {
  out[offset + 0] = value >>> 0
  out[offset + 1] = value >>> 8
  out[offset + 2] = value >>> 16
  out[offset + 3] = value >>> 24
  return out
}

export const writeInt32LE = writeUint32LE

/**
 * Reads 8 bytes from array starting at offset as big-endian
 * signed 64-bit integer and returns it.
 *
 * IMPORTANT: due to JavaScript limitation, supports exact
 * numbers in range -9007199254740991 to 9007199254740991.
 * If the number stored in the byte array is outside this range,
 * the result is not exact.
 */
export function readInt64BE(array: Uint8Array, offset = 0): number {
  const hi = readInt32BE(array, offset)
  const lo = readInt32BE(array, offset + 4)
  return hi * 0x100000000 + lo - (lo >> 31) * 0x100000000
}

/**
 * Reads 8 bytes from array starting at offset as big-endian
 * unsigned 64-bit integer and returns it.
 *
 * IMPORTANT: due to JavaScript limitation, supports values up to 2^53-1.
 */
export function readUint64BE(array: Uint8Array, offset = 0): number {
  const hi = readUint32BE(array, offset)
  const lo = readUint32BE(array, offset + 4)
  return hi * 0x100000000 + lo
}

/**
 * Reads 8 bytes from array starting at offset as little-endian
 * signed 64-bit integer and returns it.
 *
 * IMPORTANT: due to JavaScript limitation, supports exact
 * numbers in range -9007199254740991 to 9007199254740991.
 * If the number stored in the byte array is outside this range,
 * the result is not exact.
 */
export function readInt64LE(array: Uint8Array, offset = 0): number {
  const lo = readInt32LE(array, offset)
  const hi = readInt32LE(array, offset + 4)
  return hi * 0x100000000 + lo - (lo >> 31) * 0x100000000
}

/**
 * Reads 8 bytes from array starting at offset as little-endian
 * unsigned 64-bit integer and returns it.
 *
 * IMPORTANT: due to JavaScript limitation, supports values up to 2^53-1.
 */
export function readUint64LE(array: Uint8Array, offset = 0): number {
  const lo = readUint32LE(array, offset)
  const hi = readUint32LE(array, offset + 4)
  return hi * 0x100000000 + lo
}

/**
 * Writes 8-byte big-endian representation of 64-bit unsigned
 * value to byte array starting at offset.
 *
 * Due to JavaScript limitation, supports values up to 2^53-1.
 *
 * If byte array is not given, creates a new 8-byte one.
 *
 * Returns the output byte array.
 */
export function writeUint64BE(value: number, out = new Uint8Array(8), offset = 0): Uint8Array {
  writeUint32BE((value / 0x100000000) >>> 0, out, offset)
  writeUint32BE(value >>> 0, out, offset + 4)
  return out
}

export const writeInt64BE = writeUint64BE

/**
 * Writes 8-byte little-endian representation of 64-bit unsigned
 * value to byte array starting at offset.
 *
 * Due to JavaScript limitation, supports values up to 2^53-1.
 *
 * If byte array is not given, creates a new 8-byte one.
 *
 * Returns the output byte array.
 */
export function writeUint64LE(value: number, out = new Uint8Array(8), offset = 0): Uint8Array {
  writeUint32LE(value >>> 0, out, offset)
  writeUint32LE((value / 0x100000000) >>> 0, out, offset + 4)
  return out
}

export const writeInt64LE = writeUint64LE

/**
 * Reads bytes from array starting at offset as big-endian
 * unsigned bitLen-bit integer and returns it.
 *
 * Supports bit lengths divisible by 8, up to 48.
 */
export function readUintBE(bitLength: number, array: Uint8Array, offset = 0): number {
  // TODO(dchest): implement support for bitLengths non-divisible by 8
  if (bitLength % 8 !== 0) {
    throw new Error('readUintBE supports only bitLengths divisible by 8')
  }
  if (bitLength / 8 > array.length - offset) {
    throw new Error('readUintBE: array is too short for the given bitLength')
  }
  let result = 0
  let mul = 1
  for (let i = bitLength / 8 + offset - 1; i >= offset; i--) {
    result += array[i] * mul
    mul *= 256
  }
  return result
}

/**
 * Reads bytes from array starting at offset as little-endian
 * unsigned bitLen-bit integer and returns it.
 *
 * Supports bit lengths divisible by 8, up to 48.
 */
export function readUintLE(bitLength: number, array: Uint8Array, offset = 0): number {
  // TODO(dchest): implement support for bitLengths non-divisible by 8
  if (bitLength % 8 !== 0) {
    throw new Error('readUintLE supports only bitLengths divisible by 8')
  }
  if (bitLength / 8 > array.length - offset) {
    throw new Error('readUintLE: array is too short for the given bitLength')
  }
  let result = 0
  let mul = 1
  for (let i = offset; i < offset + bitLength / 8; i++) {
    result += array[i] * mul
    mul *= 256
  }
  return result
}

/**
 * Writes a big-endian representation of bitLen-bit unsigned
 * value to array starting at offset.
 *
 * Supports bit lengths divisible by 8, up to 48.
 *
 * If byte array is not given, creates a new one.
 *
 * Returns the output byte array.
 */
export function writeUintBE(
  bitLength: number,
  value: number,
  out = new Uint8Array(bitLength / 8),
  offset = 0,
): Uint8Array {
  // TODO(dchest): implement support for bitLengths non-divisible by 8
  if (bitLength % 8 !== 0) {
    throw new Error('writeUintBE supports only bitLengths divisible by 8')
  }
  if (!isSafeInteger(value)) {
    throw new Error('writeUintBE value must be an integer')
  }
  let div = 1
  for (let i = bitLength / 8 + offset - 1; i >= offset; i--) {
    out[i] = (value / div) & 0xff
    div *= 256
  }
  return out
}

/**
 * Writes a little-endian representation of bitLen-bit unsigned
 * value to array starting at offset.
 *
 * Supports bit lengths divisible by 8, up to 48.
 *
 * If byte array is not given, creates a new one.
 *
 * Returns the output byte array.
 */
export function writeUintLE(
  bitLength: number,
  value: number,
  out = new Uint8Array(bitLength / 8),
  offset = 0,
): Uint8Array {
  // TODO(dchest): implement support for bitLengths non-divisible by 8
  if (bitLength % 8 !== 0) {
    throw new Error('writeUintLE supports only bitLengths divisible by 8')
  }
  if (!isSafeInteger(value)) {
    throw new Error('writeUintLE value must be an integer')
  }
  let div = 1
  for (let i = offset; i < offset + bitLength / 8; i++) {
    out[i] = (value / div) & 0xff
    div *= 256
  }
  return out
}

/**
 * Reads 4 bytes from array starting at offset as big-endian
 * 32-bit floating-point number and returns it.
 */
export function readFloat32BE(array: Uint8Array, offset = 0): number {
  const view = new DataView(array.buffer, array.byteOffset, array.byteLength)
  return view.getFloat32(offset)
}

/**
 * Reads 4 bytes from array starting at offset as little-endian
 * 32-bit floating-point number and returns it.
 */
export function readFloat32LE(array: Uint8Array, offset = 0): number {
  const view = new DataView(array.buffer, array.byteOffset, array.byteLength)
  return view.getFloat32(offset, true)
}

/**
 * Reads 8 bytes from array starting at offset as big-endian
 * 64-bit floating-point number ("double") and returns it.
 */
export function readFloat64BE(array: Uint8Array, offset = 0): number {
  const view = new DataView(array.buffer, array.byteOffset, array.byteLength)
  return view.getFloat64(offset)
}

/**
 * Reads 8 bytes from array starting at offset as little-endian
 * 64-bit floating-point number ("double") and returns it.
 */
export function readFloat64LE(array: Uint8Array, offset = 0): number {
  const view = new DataView(array.buffer, array.byteOffset, array.byteLength)
  return view.getFloat64(offset, true)
}

/**
 * Writes 4-byte big-endian floating-point representation of value
 * to byte array starting at offset.
 *
 * If byte array is not given, creates a new 4-byte one.
 *
 * Returns the output byte array.
 */
export function writeFloat32BE(value: number, out = new Uint8Array(4), offset = 0): Uint8Array {
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength)
  view.setFloat32(offset, value)
  return out
}

/**
 * Writes 4-byte little-endian floating-point representation of value
 * to byte array starting at offset.
 *
 * If byte array is not given, creates a new 4-byte one.
 *
 * Returns the output byte array.
 */
export function writeFloat32LE(value: number, out = new Uint8Array(4), offset = 0): Uint8Array {
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength)
  view.setFloat32(offset, value, true)
  return out
}

/**
 * Writes 8-byte big-endian floating-point representation of value
 * to byte array starting at offset.
 *
 * If byte array is not given, creates a new 8-byte one.
 *
 * Returns the output byte array.
 */
export function writeFloat64BE(value: number, out = new Uint8Array(8), offset = 0): Uint8Array {
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength)
  view.setFloat64(offset, value)
  return out
}

/**
 * Writes 8-byte little-endian floating-point representation of value
 * to byte array starting at offset.
 *
 * If byte array is not given, creates a new 8-byte one.
 *
 * Returns the output byte array.
 */
export function writeFloat64LE(value: number, out = new Uint8Array(8), offset = 0): Uint8Array {
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength)
  view.setFloat64(offset, value, true)
  return out
}
