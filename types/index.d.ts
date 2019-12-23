/// <reference types="node" />
// TypeScript Version: 3.6

/* tslint:disable:strict-export-declare-modifiers */

import { KeyObject, PrivateKeyInput, PublicKeyInput } from 'crypto';

export interface ProduceOptions<TFooter = object> {
    audience?: string;
    expiresIn?: string;
    footer?: TFooter | string | Buffer;
    iat?: string;
    issuer?: string;
    jti?: string;
    kid?: string;
    notBefore?: string;
    now?: Date;
    subject?: string;
}

export interface ConsumeOptions<TComplete> {
    audience?: string;
    clockTolerance?: string;
    complete?: TComplete;
    ignoreExp?: boolean;
    ignoreIat?: boolean;
    ignoreNbf?: boolean;
    issuer?: string;
    maxTokenAge?: string;
    now?: Date;
    subject?: string;
}

export interface CompleteResult<TPayload = object> {
    footer: Buffer | undefined;
    payload: TPayload;
    purpose: string;
    version: string;
}

export interface DecodeResult<TPayload = object> {
    footer: Buffer | undefined;
    payload: TPayload | undefined;
    purpose: string;
    version: string;
}

export function decode(token: string): DecodeResult;

export namespace V1 {
    function sign(payload: object, key: KeyObject | PrivateKeyInput, options?: ProduceOptions): Promise<string>;
    function encrypt(payload: object, key: KeyObject | Buffer, options?: ProduceOptions): Promise<string>;

    function verify(token: string, key: KeyObject | PublicKeyInput, options?: ConsumeOptions<false>): Promise<object>;
    function verify(token: string, key: KeyObject | PublicKeyInput, options?: ConsumeOptions<true>): Promise<CompleteResult>;

    function decrypt(token: string, key: KeyObject | Buffer, options?: ConsumeOptions<false>): Promise<object>;
    function decrypt(token: string, key: KeyObject | Buffer, options?: ConsumeOptions<true>): Promise<CompleteResult>;

    function generateKey(purpose: 'local' | 'public'): Promise<KeyObject>;
}

export namespace V2 {
    function sign(payload: object, key: KeyObject | PrivateKeyInput, options?: ProduceOptions): Promise<string>;
    function encrypt(payload: object, key: KeyObject | Buffer, options?: ProduceOptions): Promise<string>;

    function verify(token: string, key: KeyObject | PublicKeyInput, options?: ConsumeOptions<false>): Promise<object>;
    function verify(token: string, key: KeyObject | PublicKeyInput, options?: ConsumeOptions<true>): Promise<CompleteResult>;

    function decrypt(token: string, key: KeyObject | Buffer, options?: ConsumeOptions<false>): Promise<object>;
    function decrypt(token: string, key: KeyObject | Buffer, options?: ConsumeOptions<true>): Promise<CompleteResult>;

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
