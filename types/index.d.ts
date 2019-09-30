/// <reference types="node" />
// TypeScript Version: 3.6

import { KeyObject, PrivateKeyInput, PublicKeyInput } from 'crypto';

export interface ProduceOptions {
    audience?: string;
    expiresIn?: string;
    footer?: object | string | Buffer;
    iat?: boolean;
    issuer?: string;
    jti?: string;
    kid?: string;
    notBefore?: string;
    now?: Date;
    subject?: string;
}

export interface ConsumeOptions<komplet> {
    audience?: string;
    clockTolerance?: string;
    complete?: komplet;
    ignoreExp?: boolean;
    ignoreIat?: boolean;
    ignoreNbf?: boolean;
    issuer?: string;
    maxTokenAge?: string;
    now?: Date;
    subject?: string;
}

export interface completeResult {
    footer: Buffer | undefined;
    payload: object;
    purpose: string;
    version: string;
}

export interface DecodeResult {
    footer: Buffer | undefined;
    payload: object | undefined;
    purpose: string;
    version: string;
}

export function decode(token: string): DecodeResult;

export namespace V1 {
    function sign(payload: object, key: KeyObject | PrivateKeyInput, options?: ProduceOptions): Promise<string>;
    function encrypt(payload: object, key: KeyObject | Buffer, options?: ProduceOptions): Promise<string>;

    function verify(token: string, key: KeyObject | PublicKeyInput, options?: ConsumeOptions<false>): Promise<object>;
    function verify(token: string, key: KeyObject | PublicKeyInput, options?: ConsumeOptions<true>): Promise<completeResult>;

    function decrypt(token: string, key: KeyObject | Buffer, options?: ConsumeOptions<false>): Promise<object>;
    function decrypt(token: string, key: KeyObject | Buffer, options?: ConsumeOptions<true>): Promise<completeResult>;

    function generateKey(purpose: 'local' | 'public'): Promise<KeyObject>;
}

export namespace V2 {
    function sign(payload: object, key: KeyObject | PrivateKeyInput, options?: ProduceOptions): Promise<string>;
    function encrypt(payload: object, key: KeyObject | Buffer, options?: ProduceOptions): Promise<string>;

    function verify(token: string, key: KeyObject | PublicKeyInput, options?: ConsumeOptions<false>): Promise<object>;
    function verify(token: string, key: KeyObject | PublicKeyInput, options?: ConsumeOptions<true>): Promise<completeResult>;

    function decrypt(token: string, key: KeyObject | Buffer, options?: ConsumeOptions<false>): Promise<object>;
    function decrypt(token: string, key: KeyObject | Buffer, options?: ConsumeOptions<true>): Promise<completeResult>;

    function generateKey(purpose: 'local' | 'public'): Promise<KeyObject>;
}

export namespace errors {
    class PasetoError extends Error {}

    class PasetoClaimInvalid extends PasetoError {}
    class PasetoDecryptionFailed extends PasetoError {}
    class PasetoInvalid extends PasetoError {}
    class PasetoNotSupported extends PasetoError {}
    class PasetoVerificationFailed extends PasetoError {}
}
