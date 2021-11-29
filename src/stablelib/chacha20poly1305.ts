// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Package chacha20poly1305 implements ChaCha20-Poly1305 AEAD.
 */

import { AEAD } from './aead.js'
import { streamXOR, stream } from './chacha.js'
import { Poly1305 } from './poly1305.js'
import { wipe } from './wipe.js'
import { writeUint64LE } from './binary.js'
import { equal } from './constant-time.js'

export const KEY_LENGTH = 32
export const NONCE_LENGTH = 12
export const TAG_LENGTH = 16

const ZEROS = new Uint8Array(16)

/**
 * ChaCha20-Poly1305 Authenticated Encryption with Associated Data.
 *
 * Defined in RFC7539.
 */
export class ChaCha20Poly1305 implements AEAD {
  readonly nonceLength = NONCE_LENGTH
  readonly tagLength = TAG_LENGTH

  private _key: Uint8Array

  /**
   * Creates a new instance with the given 32-byte key.
   */
  constructor(key: Uint8Array) {
    if (key.length !== KEY_LENGTH) {
      throw new Error('ChaCha20Poly1305 needs 32-byte key')
    }
    // Copy key.
    this._key = new Uint8Array(key)
  }

  /**
   * Encrypts and authenticates plaintext, authenticates associated data,
   * and returns sealed ciphertext, which includes authentication tag.
   *
   * RFC7539 specifies 12 bytes for nonce. It may be this 12-byte nonce
   * ("IV"), or full 16-byte counter (called "32-bit fixed-common part")
   * and nonce.
   *
   * If dst is given (it must be the size of plaintext + the size of tag
   * length) the result will be put into it. Dst and plaintext must not
   * overlap.
   */
  seal(
    nonce: Uint8Array,
    plaintext: Uint8Array,
    associatedData?: Uint8Array,
    dst?: Uint8Array,
  ): Uint8Array {
    if (nonce.length > 16) {
      throw new Error('ChaCha20Poly1305: incorrect nonce length')
    }

    // Allocate space for counter, and set nonce as last bytes of it.
    const counter = new Uint8Array(16)
    counter.set(nonce, counter.length - nonce.length)

    // Generate authentication key by taking first 32-bytes of stream.
    // We pass full counter, which has 12-byte nonce and 4-byte block counter,
    // and it will get incremented after generating the block, which is
    // exactly what we need: we only use the first 32 bytes of 64-byte
    // ChaCha block and discard the next 32 bytes.
    const authKey = new Uint8Array(32)
    stream(this._key, counter, authKey, 4)

    // Allocate space for sealed ciphertext.
    const resultLength = plaintext.length + this.tagLength
    let result
    if (dst) {
      if (dst.length !== resultLength) {
        throw new Error('ChaCha20Poly1305: incorrect destination length')
      }
      result = dst
    } else {
      result = new Uint8Array(resultLength)
    }

    // Encrypt plaintext.
    streamXOR(this._key, counter, plaintext, result, 4)

    // Authenticate.
    // XXX: can "simplify" here: pass full result (which is already padded
    // due to zeroes prepared for tag), and ciphertext length instead of
    // subarray of result.
    this._authenticate(
      result.subarray(result.length - this.tagLength, result.length),
      authKey,
      result.subarray(0, result.length - this.tagLength),
      associatedData,
    )

    // Cleanup.
    wipe(counter)

    return result
  }

  /**
   * Authenticates sealed ciphertext (which includes authentication tag) and
   * associated data, decrypts ciphertext and returns decrypted plaintext.
   *
   * RFC7539 specifies 12 bytes for nonce. It may be this 12-byte nonce
   * ("IV"), or full 16-byte counter (called "32-bit fixed-common part")
   * and nonce.
   *
   * If authentication fails, it returns null.
   *
   * If dst is given (it must be of ciphertext length minus tag length),
   * the result will be put into it. Dst and plaintext must not overlap.
   */
  open(
    nonce: Uint8Array,
    sealed: Uint8Array,
    associatedData?: Uint8Array,
    dst?: Uint8Array,
  ): Uint8Array | null {
    if (nonce.length > 16) {
      throw new Error('ChaCha20Poly1305: incorrect nonce length')
    }

    // Sealed ciphertext should at least contain tag.
    if (sealed.length < this.tagLength) {
      // TODO(dchest): should we throw here instead?
      return null
    }

    // Allocate space for counter, and set nonce as last bytes of it.
    const counter = new Uint8Array(16)
    counter.set(nonce, counter.length - nonce.length)

    // Generate authentication key by taking first 32-bytes of stream.
    const authKey = new Uint8Array(32)
    stream(this._key, counter, authKey, 4)

    // Authenticate.
    // XXX: can simplify and avoid allocation: since authenticate()
    // already allocates tag (from Poly1305.digest(), it can return)
    // it instead of copying to calculatedTag. But then in seal()
    // we'll need to copy it.
    const calculatedTag = new Uint8Array(this.tagLength)
    this._authenticate(
      calculatedTag,
      authKey,
      sealed.subarray(0, sealed.length - this.tagLength),
      associatedData,
    )

    // Constant-time compare tags and return null if they differ.
    if (!equal(calculatedTag, sealed.subarray(sealed.length - this.tagLength, sealed.length))) {
      return null
    }

    // Allocate space for decrypted plaintext.
    const resultLength = sealed.length - this.tagLength
    let result
    if (dst) {
      if (dst.length !== resultLength) {
        throw new Error('ChaCha20Poly1305: incorrect destination length')
      }
      result = dst
    } else {
      result = new Uint8Array(resultLength)
    }

    // Decrypt.
    streamXOR(this._key, counter, sealed.subarray(0, sealed.length - this.tagLength), result, 4)

    // Cleanup.
    wipe(counter)

    return result
  }

  clean(): this {
    wipe(this._key)
    return this
  }

  private _authenticate(
    tagOut: Uint8Array,
    authKey: Uint8Array,
    ciphertext: Uint8Array,
    associatedData?: Uint8Array,
  ) {
    // Initialize Poly1305 with authKey.
    const h = new Poly1305(authKey)

    // Authenticate padded associated data.
    if (associatedData) {
      h.update(associatedData)
      if (associatedData.length % 16 > 0) {
        h.update(ZEROS.subarray(associatedData.length % 16))
      }
    }

    // Authenticate padded ciphertext.
    h.update(ciphertext)
    if (ciphertext.length % 16 > 0) {
      h.update(ZEROS.subarray(ciphertext.length % 16))
    }

    // Authenticate length of associated data.
    // XXX: can avoid allocation here?
    const length = new Uint8Array(8)
    if (associatedData) {
      writeUint64LE(associatedData.length, length)
    }
    h.update(length)

    // Authenticate length of ciphertext.
    writeUint64LE(ciphertext.length, length)
    h.update(length)

    // Get tag and copy it into tagOut.
    const tag = h.digest()
    for (let i = 0; i < tag.length; i++) {
      tagOut[i] = tag[i]
    }

    // Cleanup.
    h.clean()
    wipe(tag)
    wipe(length)
  }
}
