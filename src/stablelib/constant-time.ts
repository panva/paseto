// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package constant-time provides functions for performing algorithmically constant-time operations.
 */

/**
 * NOTE! Due to the inability to guarantee real constant time evaluation of
 * anything in JavaScript VM, this is module is the best effort.
 */

/**
 * Returns resultIfOne if subject is 1, or resultIfZero if subject is 0.
 *
 * Supports only 32-bit integers, so resultIfOne or resultIfZero are not
 * integers, they'll be converted to them with bitwise operations.
 */
export function select(subject: number, resultIfOne: number, resultIfZero: number): number {
  return (~(subject - 1) & resultIfOne) | ((subject - 1) & resultIfZero)
}

/**
 * Returns 1 if a <= b, or 0 if not.
 * Arguments must be positive 32-bit integers less than or equal to 2^31 - 1.
 */
export function lessOrEqual(a: number, b: number): number {
  return (((a | 0) - (b | 0) - 1) >>> 31) & 1
}

/**
 * Returns 1 if a and b are of equal length and their contents
 * are equal, or 0 otherwise.
 *
 * Note that unlike in equal(), zero-length inputs are considered
 * the same, so this function will return 1.
 */
export function compare(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) {
    return 0
  }
  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i]
  }
  return 1 & ((result - 1) >>> 8)
}

/**
 * Returns true if a and b are of equal non-zero length,
 * and their contents are equal, or false otherwise.
 *
 * Note that unlike in compare() zero-length inputs are considered
 * _not_ equal, so this function will return false.
 */
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length === 0 || b.length === 0) {
    return false
  }
  return compare(a, b) !== 0
}
