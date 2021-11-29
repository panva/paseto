// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package hash provides interface for hash functions.
 */

/**
 * Hash interface describes properties of
 * cryptographic hash functions.
 */
export interface Hash {
  readonly digestLength: number
  readonly blockSize: number
  update(data: Uint8Array): this
  reset(): this
  finish(out: Uint8Array): this
  digest(): Uint8Array
  clean(): void
}

export interface SerializableHash extends Hash {
  saveState(): any
  restoreState(savedState: any): this
  cleanSavedState(savedState: any): void
}

export function isSerializableHash(h: Hash): h is SerializableHash {
  return (
    typeof (h as SerializableHash).saveState !== 'undefined' &&
    typeof (h as SerializableHash).restoreState !== 'undefined' &&
    typeof (h as SerializableHash).cleanSavedState !== 'undefined'
  )
}

// TODO(dchest): figure out the standardized interface for XOF such as
// SHAKE and BLAKE2X.
