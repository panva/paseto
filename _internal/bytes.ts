import { InvalidTokenError, PAE } from '../index.ts'

const encoder = /* @__PURE__ */ new TextEncoder()
const decoder = /* @__PURE__ */ new TextDecoder('utf-8', { fatal: true })

export const empty: Uint8Array = /* @__PURE__ */ new Uint8Array()

export function checkBytes(
  value: unknown,
  name: string,
  length?: number,
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) throw new TypeError(`"${name}" must be a Uint8Array`)
  if (length !== undefined && value.byteLength !== length) {
    throw new TypeError(`"${name}" must be ${length} bytes`)
  }
}

export function copyBytes(value: Uint8Array): Uint8Array {
  return new Uint8Array(value)
}

export function concat(...pieces: readonly Uint8Array[]): Uint8Array {
  let length = 0
  for (const piece of pieces) {
    checkBytes(piece, 'piece')
    length += piece.byteLength
  }
  const output = new Uint8Array(length)
  let offset = 0
  for (const piece of pieces) {
    output.set(piece, offset)
    offset += piece.byteLength
  }
  return output
}

export function ascii(value: string): Uint8Array {
  return encoder.encode(value)
}

export function decodeUtf8(value: Uint8Array): string {
  return decoder.decode(value)
}

export function randomBytes(length: number): Uint8Array {
  const output = new Uint8Array(length)
  crypto.getRandomValues(output)
  return output
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false
  let mismatch = 0
  for (let i = 0; i < left.byteLength; i++) mismatch |= left[i]! ^ right[i]!
  return mismatch === 0
}

function fromBase64(input: string, alphabet: 'base64' | 'base64url'): Uint8Array {
  // @ts-ignore Uint8Array Base64 methods are not yet in every TypeScript library.
  const decoded = Uint8Array.fromBase64?.(input, { alphabet })
  if (decoded !== undefined) return decoded

  let binary: string
  try {
    const normalized =
      alphabet === 'base64url'
        ? input
            .replaceAll('-', '+')
            .replaceAll('_', '/')
            .padEnd((input.length + 3) & ~3, '=')
        : input
    binary = atob(normalized)
  } catch (cause) {
    throw new InvalidTokenError('Invalid base64url', { cause })
  }
  const output = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) output[i] = binary.charCodeAt(i)
  return output
}

function toBase64(input: Uint8Array): string {
  // @ts-ignore Uint8Array Base64 methods are not yet in every TypeScript library.
  const encoded = input.toBase64?.({ alphabet: 'base64' })
  if (encoded !== undefined) return encoded

  let binary = ''
  for (let i = 0; i < input.byteLength; i += 0x8000) {
    binary += String.fromCharCode(...input.subarray(i, i + 0x8000))
  }
  return btoa(binary)
}

export function toB64u(input: Uint8Array): string {
  // @ts-ignore Uint8Array Base64 methods are not yet in every TypeScript library.
  const encoded = input.toBase64?.({ alphabet: 'base64url', omitPadding: true })
  if (encoded !== undefined) return encoded
  return toBase64(input).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

export function b64u(input: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/u.test(input) || input.length % 4 === 1) {
    throw new InvalidTokenError('Invalid base64url')
  }
  try {
    const output = fromBase64(input, 'base64url')
    if (toB64u(output) !== input) throw new Error('non-canonical')
    return output
  } catch (cause) {
    throw new InvalidTokenError('Invalid base64url', { cause })
  }
}

export function b64(input: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(input) || input.length % 4 !== 0) {
    throw new InvalidTokenError('Invalid base64')
  }
  try {
    const output = fromBase64(input, 'base64')
    if (toBase64(output) !== input) throw new Error('non-canonical')
    return output
  } catch (cause) {
    throw new InvalidTokenError('Invalid base64', { cause })
  }
}

export function decodeBase64url(input: string, name: string): Uint8Array {
  try {
    return b64u(input)
  } catch (cause) {
    throw new InvalidTokenError(`Invalid ${name}`, { cause })
  }
}

export function uint32be(value: number): Uint8Array {
  const output = new Uint8Array(4)
  new DataView(output.buffer).setUint32(0, value)
  return output
}

export function readUint32be(input: Uint8Array, offset: number): number {
  return new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(offset)
}

export function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`"${name}" must be a positive integer`)
  }
  return value
}

export function webCryptoBytes(input: Uint8Array): Uint8Array<ArrayBuffer> {
  checkBytes(input, 'Web Cryptography input')
  return input as Uint8Array<ArrayBuffer>
}

export { PAE }
