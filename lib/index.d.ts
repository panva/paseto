/// <reference types="node" />

import { KeyObject, PrivateKeyInput, PublicKeyInput } from 'crypto'

interface ProduceOptions {
    audience?: string,
    expiresIn?: string,
    footer?: object | string | Buffer,
    iat?: boolean,
    issuer?: string,
    jti?: string,
    kid?: string,
    notBefore?: string,
    now?: Date,
    subject?: string
}

interface ConsumeOptions<komplet> {
    audience?: string,
    clockTolerance?: string,
    complete?: komplet,
    ignoreExp?: boolean,
    ignoreIat?: boolean,
    ignoreNbf?: boolean,
    issuer?: string,
    maxTokenAge?: string,
    now?: Date,
    subject?: string
}

interface completeResult {
    footer: Buffer | undefined,
    payload: object,
    purpose: string,
    version: string
}

interface DecodeResult {
    footer: Buffer | undefined,
    payload: object | undefined,
    purpose: string,
    version: string
}

export function decode(token: string): DecodeResultParsed

export namespace V1 {
    export function sign(payload: object, key: KeyObject | PrivateKeyInput, options?: ProduceOptions): Promise<string>
    export function encrypt(payload: object, key: KeyObject | Buffer, options?: ProduceOptions): Promise<string>

    export function verify(token: string, key: KeyObject | PublicKeyInput, options?: ConsumeOptions<false>): Promise<object>
    export function verify(token: string, key: KeyObject | PublicKeyInput, options?: ConsumeOptions<true>): Promise<completeResult>

    export function decrypt(token: string, key: KeyObject | Buffer, options?: ConsumeOptions<false>): Promise<object>
    export function decrypt(token: string, key: KeyObject | Buffer, options?: ConsumeOptions<true>): Promise<completeResult>

    export function generateKey(purpose: 'local' | 'public'): Promise<KeyObject>
}

export namespace V2 {
    export function sign(payload: object, key: KeyObject | PrivateKeyInput, options?: ProduceOptions): Promise<string>
    export function encrypt(payload: object, key: KeyObject | Buffer, options?: ProduceOptions): Promise<string>

    export function verify(token: string, key: KeyObject | PublicKeyInput, options?: ConsumeOptions<false>): Promise<object>
    export function verify(token: string, key: KeyObject | PublicKeyInput, options?: ConsumeOptions<true>): Promise<completeResult>

    export function decrypt(token: string, key: KeyObject | Buffer, options?: ConsumeOptions<false>): Promise<object>
    export function decrypt(token: string, key: KeyObject | Buffer, options?: ConsumeOptions<true>): Promise<completeResult>

    export function generateKey(purpose: 'local' | 'public'): Promise<KeyObject>
}

export namespace errors {
    export class PasetoError extends Error {}

    export class PasetoClaimInvalid extends PasetoError {}
    export class PasetoDecryptionFailed extends PasetoError {}
    export class PasetoInvalid extends PasetoError {}
    export class PasetoNotSupported extends PasetoError {}
    export class PasetoVerificationFailed extends PasetoError {}
}
