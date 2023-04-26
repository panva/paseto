/// <reference types="node" />
// TypeScript Version: 3.6
import { KeyObject, PrivateKeyInput, PublicKeyInput, JsonWebKeyInput } from 'crypto'
type JsonObject = { [Key in string]?: JsonValue }
type JsonArray = JsonValue[]
type JsonPrimitive = string | number | boolean | null
type JsonValue = JsonPrimitive | JsonObject | JsonArray
export interface ProduceOptions {
  assertion?: string | Buffer
  audience?: string
  expiresIn?: string
  footer?: Record<PropertyKey, unknown> | string | Buffer
  iat?: boolean
  issuer?: string
  jti?: string
  kid?: string
  notBefore?: string
  now?: Date
  subject?: string
}
export interface ConsumeOptions<TComplete extends boolean> {
  assertion?: string | Buffer
  audience?: string
  clockTolerance?: string
  complete?: TComplete
  buffer?: false
  ignoreExp?: boolean
  ignoreIat?: boolean
  ignoreNbf?: boolean
  issuer?: string
  maxTokenAge?: string
  now?: Date
  subject?: string
}
export interface CompleteResult<T = Record<string, JsonValue | undefined>> {
  footer?: Buffer
  payload: T
  purpose: 'local' | 'public'
  version: string
}
export interface ConsumeOptionsBuffer<TComplete extends boolean> {
  assertion?: string | Buffer
  complete?: TComplete
  buffer: true
}
export interface CompleteResultBuffer {
  footer?: Buffer
  payload: Buffer
  purpose: 'local' | 'public'
  version: string
}
export interface DecodeResult<T = Record<string, JsonValue | undefined>> {
  footer?: Buffer
  payload?: T
  purpose: 'local' | 'public'
  version: string
}
export interface DecodeResultBuffer {
  footer?: Buffer
  payload?: Buffer
  purpose: 'local' | 'public'
  version: string
}
export function decode<T = Record<string, JsonValue | undefined>>(token: string): DecodeResult<T>
export namespace V1 {
  function sign(
    payload: Record<PropertyKey, unknown> | Buffer,
    key: KeyObject | Buffer | PrivateKeyInput | JsonWebKeyInput | string,
    options?: Omit<ProduceOptions, 'assertion'>,
  ): Promise<string>
  function encrypt(
    payload: Record<PropertyKey, unknown> | Buffer,
    key: KeyObject | Buffer | string,
    options?: Omit<ProduceOptions, 'assertion'>,
  ): Promise<string>
  function verify<T = Record<string, JsonValue | undefined>>(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: Omit<ConsumeOptions<false>, 'assertion'>,
  ): Promise<T>
  function verify<T = Record<string, JsonValue | undefined>>(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: Omit<ConsumeOptions<true>, 'assertion'>,
  ): Promise<CompleteResult<T>>
  function verify(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: Omit<ConsumeOptionsBuffer<false>, 'assertion'>,
  ): Promise<Buffer>
  function verify(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: Omit<ConsumeOptionsBuffer<true>, 'assertion'>,
  ): Promise<CompleteResultBuffer>
  function decrypt<T = Record<string, JsonValue | undefined>>(
    token: string,
    key: KeyObject | Buffer | string,
    options?: Omit<ConsumeOptions<false>, 'assertion'>,
  ): Promise<T>
  function decrypt<T = Record<string, JsonValue | undefined>>(
    token: string,
    key: KeyObject | Buffer | string,
    options?: Omit<ConsumeOptions<true>, 'assertion'>,
  ): Promise<CompleteResult<T>>
  function decrypt(
    token: string,
    key: KeyObject | Buffer | string,
    options?: Omit<ConsumeOptionsBuffer<false>, 'assertion'>,
  ): Promise<Buffer>
  function decrypt(
    token: string,
    key: KeyObject | Buffer | string,
    options?: Omit<ConsumeOptionsBuffer<true>, 'assertion'>,
  ): Promise<CompleteResultBuffer>
  function generateKey(purpose: 'local' | 'public'): Promise<KeyObject>
  function generateKey(purpose: 'local' | 'public', options: { format: 'keyobject' }): Promise<KeyObject>
  function generateKey(purpose: 'local', options: { format: 'paserk' }): Promise<string>
  function generateKey(purpose: 'public', options: { format: 'paserk' }): Promise<{ secretKey: string, publicKey: string }>
}
export namespace V2 {
  function sign(
    payload: Record<PropertyKey, unknown> | Buffer,
    key: KeyObject | Buffer | PrivateKeyInput | JsonWebKeyInput | string,
    options?: Omit<ProduceOptions, 'assertion'>,
  ): Promise<string>
  function verify<T = Record<string, JsonValue | undefined>>(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: Omit<ConsumeOptions<false>, 'assertion'>,
  ): Promise<T>
  function verify<T = Record<string, JsonValue | undefined>>(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: Omit<ConsumeOptions<true>, 'assertion'>,
  ): Promise<CompleteResult<T>>
  function verify(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: Omit<ConsumeOptionsBuffer<false>, 'assertion'>,
  ): Promise<Buffer>
  function verify(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: Omit<ConsumeOptionsBuffer<true>, 'assertion'>,
  ): Promise<CompleteResultBuffer>
  function generateKey(purpose: 'public'): Promise<KeyObject>
  function generateKey(purpose: 'public', options: { format: 'keyobject' }): Promise<KeyObject>
  function generateKey(purpose: 'public', options: { format: 'paserk' }): Promise<{ secretKey: string, publicKey: string }>
  function bytesToKeyObject(bytes: Buffer): KeyObject
  function keyObjectToBytes(keyObject: KeyObject): Buffer
}
export namespace V3 {
  function sign(
    payload: Record<PropertyKey, unknown> | Buffer,
    key: KeyObject | Buffer | PrivateKeyInput | JsonWebKeyInput | string,
    options?: ProduceOptions,
  ): Promise<string>
  function encrypt(
    payload: Record<PropertyKey, unknown> | Buffer,
    key: KeyObject | Buffer | string,
    options?: ProduceOptions,
  ): Promise<string>
  function verify<T = Record<string, JsonValue | undefined>>(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: ConsumeOptions<false>,
  ): Promise<T>
  function verify<T = Record<string, JsonValue | undefined>>(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: ConsumeOptions<true>,
  ): Promise<CompleteResult<T>>
  function verify(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: ConsumeOptionsBuffer<false>,
  ): Promise<Buffer>
  function verify(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: ConsumeOptionsBuffer<true>,
  ): Promise<CompleteResultBuffer>
  function decrypt<T = Record<string, JsonValue | undefined>>(
    token: string,
    key: KeyObject | Buffer | string,
    options?: ConsumeOptions<false>,
  ): Promise<T>
  function decrypt<T = Record<string, JsonValue | undefined>>(
    token: string,
    key: KeyObject | Buffer | string,
    options?: ConsumeOptions<true>,
  ): Promise<CompleteResult<T>>
  function decrypt(
    token: string,
    key: KeyObject | Buffer | string,
    options?: ConsumeOptionsBuffer<false>,
  ): Promise<Buffer>
  function decrypt(
    token: string,
    key: KeyObject | Buffer | string,
    options?: ConsumeOptionsBuffer<true>,
  ): Promise<CompleteResultBuffer>
  function generateKey(purpose: 'local' | 'public'): Promise<KeyObject>
  function generateKey(purpose: 'local' | 'public', options: { format: 'keyobject' }): Promise<KeyObject>
  function generateKey(purpose: 'local', options: { format: 'paserk' }): Promise<string>
  function generateKey(purpose: 'public', options: { format: 'paserk' }): Promise<{ secretKey: string, publicKey: string }>
  function bytesToKeyObject(bytes: Buffer): KeyObject
  function keyObjectToBytes(keyObject: KeyObject): Buffer
}
export namespace V4 {
  function sign(
    payload: Record<PropertyKey, unknown> | Buffer,
    key: KeyObject | Buffer | PrivateKeyInput | JsonWebKeyInput | string,
    options?: ProduceOptions,
  ): Promise<string>
  function verify<T = Record<string, JsonValue | undefined>>(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: ConsumeOptions<false>,
  ): Promise<T>
  function verify<T = Record<string, JsonValue | undefined>>(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: ConsumeOptions<true>,
  ): Promise<CompleteResult<T>>
  function verify(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: ConsumeOptionsBuffer<false>,
  ): Promise<Buffer>
  function verify(
    token: string,
    key: KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput | string,
    options?: ConsumeOptionsBuffer<true>,
  ): Promise<CompleteResultBuffer>
  function generateKey(purpose: 'public'): Promise<KeyObject>
  function generateKey(purpose: 'public', options: { format: 'keyobject' }): Promise<KeyObject>
  function generateKey(purpose: 'public', options: { format: 'paserk' }): Promise<{ secretKey: string, publicKey: string }>
  function bytesToKeyObject(bytes: Buffer): KeyObject
  function keyObjectToBytes(keyObject: KeyObject): Buffer
}
export namespace errors {
  class PasetoError extends Error {}
  class PasetoClaimInvalid extends PasetoError {}
  class PasetoDecryptionFailed extends PasetoError {}
  class PasetoInvalid extends PasetoError {}
  class PasetoNotSupported extends PasetoError {}
  class PasetoVerificationFailed extends PasetoError {}
}
