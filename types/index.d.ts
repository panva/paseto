/// <reference types="node" />
// TypeScript Version: 3.6
import { KeyObject, PrivateKeyInput, PublicKeyInput, JsonWebKeyInput } from 'crypto'
export interface ProduceOptions {
  assertion?: string | Buffer
  audience?: string
  expiresIn?: string
  footer?: object | string | Buffer
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
export interface CompleteResult {
  footer?: Buffer
  payload: object
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
export interface DecodeResult {
  footer?: Buffer
  payload?: object
  purpose: 'local' | 'public'
  version: string
}
export interface DecodeResultBuffer {
  footer?: Buffer
  payload?: Buffer
  purpose: 'local' | 'public'
  version: string
}
export function decode(token: string): DecodeResult
export namespace V1 {
  function sign(
    payload: object | Buffer,
    key: KeyObject | PrivateKeyInput | JsonWebKeyInput,
    options?: Omit<ProduceOptions, 'assertion'>,
  ): Promise<string>
  function encrypt(
    payload: object | Buffer,
    key: KeyObject | Buffer,
    options?: Omit<ProduceOptions, 'assertion'>,
  ): Promise<string>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: Omit<ConsumeOptions<false>, 'assertion'>,
  ): Promise<object>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: Omit<ConsumeOptions<true>, 'assertion'>,
  ): Promise<CompleteResult>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: Omit<ConsumeOptionsBuffer<false>, 'assertion'>,
  ): Promise<Buffer>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: Omit<ConsumeOptionsBuffer<true>, 'assertion'>,
  ): Promise<CompleteResultBuffer>
  function decrypt(
    token: string,
    key: KeyObject | Buffer,
    options?: Omit<ConsumeOptions<false>, 'assertion'>,
  ): Promise<object>
  function decrypt(
    token: string,
    key: KeyObject | Buffer,
    options?: Omit<ConsumeOptions<true>, 'assertion'>,
  ): Promise<CompleteResult>
  function decrypt(
    token: string,
    key: KeyObject | Buffer,
    options?: Omit<ConsumeOptionsBuffer<false>, 'assertion'>,
  ): Promise<Buffer>
  function decrypt(
    token: string,
    key: KeyObject | Buffer,
    options?: Omit<ConsumeOptionsBuffer<true>, 'assertion'>,
  ): Promise<CompleteResultBuffer>
  function generateKey(purpose: 'local' | 'public'): Promise<KeyObject>
}
export namespace V2 {
  function sign(
    payload: object | Buffer,
    key: KeyObject | PrivateKeyInput | JsonWebKeyInput,
    options?: Omit<ProduceOptions, 'assertion'>,
  ): Promise<string>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: Omit<ConsumeOptions<false>, 'assertion'>,
  ): Promise<object>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: Omit<ConsumeOptions<true>, 'assertion'>,
  ): Promise<CompleteResult>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: Omit<ConsumeOptionsBuffer<false>, 'assertion'>,
  ): Promise<Buffer>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: Omit<ConsumeOptionsBuffer<true>, 'assertion'>,
  ): Promise<CompleteResultBuffer>
  function generateKey(purpose: 'public'): Promise<KeyObject>
}
export namespace V3 {
  function sign(
    payload: object | Buffer,
    key: KeyObject | PrivateKeyInput | JsonWebKeyInput,
    options?: ProduceOptions,
  ): Promise<string>
  function encrypt(
    payload: object | Buffer,
    key: KeyObject | Buffer,
    options?: ProduceOptions,
  ): Promise<string>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: ConsumeOptions<false>,
  ): Promise<object>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: ConsumeOptions<true>,
  ): Promise<CompleteResult>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: ConsumeOptionsBuffer<false>,
  ): Promise<Buffer>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: ConsumeOptionsBuffer<true>,
  ): Promise<CompleteResultBuffer>
  function decrypt(
    token: string,
    key: KeyObject | Buffer,
    options?: ConsumeOptions<false>,
  ): Promise<object>
  function decrypt(
    token: string,
    key: KeyObject | Buffer,
    options?: ConsumeOptions<true>,
  ): Promise<CompleteResult>
  function decrypt(
    token: string,
    key: KeyObject | Buffer,
    options?: ConsumeOptionsBuffer<false>,
  ): Promise<Buffer>
  function decrypt(
    token: string,
    key: KeyObject | Buffer,
    options?: ConsumeOptionsBuffer<true>,
  ): Promise<CompleteResultBuffer>
  function generateKey(purpose: 'local' | 'public'): Promise<KeyObject>
}
export namespace V4 {
  function sign(
    payload: object | Buffer,
    key: KeyObject | PrivateKeyInput | JsonWebKeyInput,
    options?: ProduceOptions,
  ): Promise<string>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: ConsumeOptions<false>,
  ): Promise<object>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: ConsumeOptions<true>,
  ): Promise<CompleteResult>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: ConsumeOptionsBuffer<false>,
  ): Promise<Buffer>
  function verify(
    token: string,
    key: KeyObject | PublicKeyInput | JsonWebKeyInput,
    options?: ConsumeOptionsBuffer<true>,
  ): Promise<CompleteResultBuffer>
  function generateKey(purpose: 'public'): Promise<KeyObject>
}
export namespace errors {
  class PasetoError extends Error {}
  class PasetoClaimInvalid extends PasetoError {}
  class PasetoDecryptionFailed extends PasetoError {}
  class PasetoInvalid extends PasetoError {}
  class PasetoNotSupported extends PasetoError {}
  class PasetoVerificationFailed extends PasetoError {}
}
