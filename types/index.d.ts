/// <reference types="node" />
// TypeScript Version: 3.6

import { KeyObject, PrivateKeyInput, PublicKeyInput } from 'crypto';

export interface ProduceOptions {
    /** PASETO Audience, "aud" claim value, if provided it will replace "aud" found in the payload */
    audience?: string;
    /**
     * PASETO Expiration Time, "exp" claim value, specified as string which is added to the current unix epoch timestamp,
     * if provided it will replace Expiration Time found in the payload
     * @example "24 hours", "20 m", "60s"
     */
    expiresIn?: string;
    /** PASETO footer */
    footer?: object | string | Buffer;
    /**
     * When true it pushes the "iat" to the PASETO payload
     * @default true
     */
    iat?: boolean;
    /** PASETO Issuer, "iss" claim value, if provided it will replace "iss" found in the payload */
    issuer?: string;
    /** Token ID, "jti" claim value, if provided it will replace "jti" found in the payload */
    jti?: string;
    /** Key ID, "kid" claim value, if provided it will replace "kid" found in the payload */
    kid?: string;
    /**
     * PASETO Not Before, "nbf" claim value, specified as string which is added to the current unix epoch timestamp,
     * if provided it will replace Not Before found in the payload
     * @example "24 hours", "20 m", "60s"
     */
    notBefore?: string;
    /**
     * Date object to be used instead of the current unix epoch timestamp. Default: 'new Date()'
     * @default new Date()
     */
    now?: Date;
    /** PASETO subject, "sub" claim value, if provided it will replace "sub" found in the payload */
    subject?: string;
}

export interface ConsumeOptions<TComplete extends boolean> {
    /** Expected audience value. An exact match must be found in the payload */
    audience?: string;
    /**
     * Clock Tolerance for comparing timestamps, provided as timespan string
     * @example "120s", "2 minutes", etc.
     * @default no clock tolerance
     */
    clockTolerance?: string;
    /**
     * When false only the parsed payload is returned, otherwise an object with a parsed payload and footer (as a Buffer) will be returned
     * @default false
     */
    complete?: TComplete;
    /**
     * When false the parsed payload is returned, otherwise the raw payload (as a Buffer) will be returned
     * @default false
     */
    buffer?: false;
    /**
     * When true will not be validating the "exp" claim value to be in the future from now
     * @default false
     */
    ignoreExp?: boolean;
    /**
     * When true will not be validating the "iat" claim value to be in the past from now
     * @default false
     */
    ignoreIat?: boolean;
    /**
     * When true will not be validating the "nbf" claim value to be in the past from now
     * @default false
     */
    ignoreNbf?: boolean;
    /** Expected issuer value. An exact match must be found in the payload */
    issuer?: string;
    /**
     * When provided the payload is checked to have the "iat" claim and its value is validated not to be older than the provided timespan string
     * @example "30m", "24 hours"
     */
    maxTokenAge?: string;
    /**
     * Date object to be used instead of the current unix epoch timestamp
     * @default new Date()
     */
    now?: Date;
    /** Expected subject value. An exact match must be found in the payload */
    subject?: string;
}

export interface CompleteResult {
    /** PASETO footer */
    footer?: Buffer;
    /** PASETO Payload claims */
    payload: object;
    /** PASETO purpose */
    purpose: 'local' | 'public';
    /** Protocol version */
    version: string;
}

export interface ConsumeOptionsBuffer<TComplete extends boolean> {
    /**
     * When false only the parsed payload is returned, otherwise an object with a parsed payload and footer (as a Buffer) will be returned
     * @default false
     */
    complete?: TComplete;
    /**
     * When false the parsed payload is returned, otherwise the raw payload (as a Buffer) will be returned
     * @default true
     */
    buffer: true;
}

export interface CompleteResultBuffer {
    /** PASETO footer */
    footer?: Buffer;
    /** PASETO payload */
    payload: Buffer;
    /** PASETO purpose */
    purpose: 'local' | 'public';
    /** Protocol version */
    version: string;
}

export interface DecodeResult {
    /** PASETO footer */
    footer?: Buffer;
    /** PASETO Payload claims */
    payload?: object;
    /** PASETO purpose */
    purpose: 'local' | 'public';
    /** Protocol version */
    version: string;
}

export interface DecodeResultBuffer {
    /** PASETO footer */
    footer?: Buffer;
    /** PASETO payload */
    payload?: Buffer;
    /** PASETO purpose */
    purpose: 'local' | 'public';
    /** Protocol version */
    version: string;
}

export function decode(token: string): DecodeResult;

export namespace V1 {
    /**
     * Serializes and signs the payload as a PASETO using the provided private key
     * @example
     * const { createPrivateKey } = require('crypto')
     * const { V1 } = require('paseto')
     *
     * const key = createPrivateKey(privateKey)
     *
     * const payload = {
     *   'urn:example:claim': 'foo'
     * }
     *
     * (async () => {
     *   const token = await V1.sign(payload, key, {
     *     audience: 'urn:example:client',
     *     issuer: 'https://op.example.com',
     *     expiresIn: '2 hours'
     *   })
     *   // v1.public.eyJ1cm46ZXhhbXBsZTpjbGFpbSI6ImZvbyIsImlhdCI6IjIwMTktMDctMDJUMTQ6MDI6MjIuNDg5WiIsImV4cCI6IjIwMTktMDctMDJUMTY6MDI6MjIuNDg5WiIsImF1ZCI6InVybjpleGFtcGxlOmNsaWVudCIsImlzcyI6Imh0dHBzOi8vb3AuZXhhbXBsZS5jb20ifbCaLu19MdLxjrexKh4WTyKr6UoeXzDly_Po1ZNv4wD5CglfY84QqQYTGXLlcLAqZagM3cWJn6xge-lBlT63km6OtOsiWTaKOnYg4MBtQTKmLsjpehpPtDSl_39h2BenB-r911qjYwNNuaRukjrtSVKQtfxdoAoFKEz_eulsDTclEBV7bJrL9Bo0epkJhFShZ6-K8qNd6rTg6Q3YOZCheW1FqNjqfoUYJ9nqPZl2OVbcPdAW3HBeLJefmlL_QGVSRClE2MXOVDrcyf7vGZ0SIj3ylnr6jmEJpzG8o0ap7FblQZI3xp91e-gmw30o6njhSq1ZVWpLqp7FYzq0pknJzGE
     * })()
     */
    function sign(
        /** PASETO Payload claims or payload */
        payload: object | Buffer,
        /** The key to sign with. Alternatively any input that works for `crypto.createPrivateKey` */
        key: KeyObject | PrivateKeyInput,
        options?: ProduceOptions,
    ): Promise<string>;
    /**
     * Serializes and encrypts the payload as a PASETO using the provided secret key
     * @example
     * const { createSecretKey } = require('crypto')
     * const { V1 } = require('paseto')
     *
     * const key = createSecretKey(secret)
     *
     * const payload = {
     *   'urn:example:claim': 'foo'
     * }
     *
     * (async () => {
     *   const token = await V1.encrypt(payload, key, {
     *     audience: 'urn:example:client',
     *     issuer: 'https://op.example.com',
     *     expiresIn: '2 hours'
     *   })
     *   // v1.local.1X8AshBYnBXTevpH6s21lTZzPL8k-pVaRBsfU5uFfpDWAoG8NZAB5LwQgUpcsgAbZj-wpDMix1Mzw_viBbntWjqEZAVOe-BTMhVKSe43u3fUM2EfRcNFHzPVY_2I_CqGjhW2qs6twNvgv5kEhOiUnTSgZMtCn9h6L_KlKz8YrWcGdGypBYcs5ooMClKvOhb2_M8wHqG_PCgAkgO5PBbHk1g6UnTgGgztuEMrcchLd7UJqNDU2I7TyQ9x7ofvndE35ODYaf-SefrJb72tuXaUqFbkAwKPs77EwvnWE5dgo6bbsp5KMdxq
     * })()
     */
    function encrypt(
        /** PASETO Payload claims or payload */
        payload: object | Buffer,
        /** The secret key to encrypt with. Alternatively any input that works for `crypto.createSecretKey` */
        key: KeyObject | Buffer,
        options?: ProduceOptions,
    ): Promise<string>;

    /**
     * Verifies the claims and signature of a PASETO
     * @example
     * const { createPublicKey } = require('crypto')
     * const { V1 } = require('paseto')
     *
     * const key = createPrivateKey(publicKey)
     *
     * const token = 'v1.public.eyJ1cm46ZXhhbXBsZTpjbGFpbSI6ImZvbyIsImlhdCI6IjIwMTktMDctMDJUMTQ6MDI6MjIuNDg5WiIsImV4cCI6IjIwMTktMDctMDJUMTY6MDI6MjIuNDg5WiIsImF1ZCI6InVybjpleGFtcGxlOmNsaWVudCIsImlzcyI6Imh0dHBzOi8vb3AuZXhhbXBsZS5jb20ifbCaLu19MdLxjrexKh4WTyKr6UoeXzDly_Po1ZNv4wD5CglfY84QqQYTGXLlcLAqZagM3cWJn6xge-lBlT63km6OtOsiWTaKOnYg4MBtQTKmLsjpehpPtDSl_39h2BenB-r911qjYwNNuaRukjrtSVKQtfxdoAoFKEz_eulsDTclEBV7bJrL9Bo0epkJhFShZ6-K8qNd6rTg6Q3YOZCheW1FqNjqfoUYJ9nqPZl2OVbcPdAW3HBeLJefmlL_QGVSRClE2MXOVDrcyf7vGZ0SIj3ylnr6jmEJpzG8o0ap7FblQZI3xp91e-gmw30o6njhSq1ZVWpLqp7FYzq0pknJzGE'
     *
     * (async () => {
     *   await V1.verify(token, key, {
     *     audience: 'urn:example:client',
     *     issuer: 'https://op.example.com',
     *     clockTolerance: '1 min'
     *   })
     * // {
     * //   'urn:example:claim': 'foo',
     * //   iat: '2019-07-02T14:02:22.489Z',
     * //   exp: '2019-07-02T16:02:22.489Z',
     * //   aud: 'urn:example:client',
     * //   iss: 'https://op.example.com'
     * // }
     * })()
     */
    function verify(
        /** PASETO to verify */
        token: string,
        /** The key to verify with. Alternatively any input that works for `crypto.createPublicKey` */
        key: KeyObject | PublicKeyInput,
        options?: ConsumeOptions<false>,
    ): Promise<object>;
    function verify(
        /** PASETO to verify */
        token: string,
        /** The key to verify with. Alternatively any input that works for `crypto.createPublicKey` */
        key: KeyObject | PublicKeyInput,
        options?: ConsumeOptions<true>,
    ): Promise<CompleteResult>;
    function verify(
        /** PASETO to verify */
        token: string,
        /** The key to verify with. Alternatively any input that works for `crypto.createPublicKey` */
        key: KeyObject | PublicKeyInput,
        options?: ConsumeOptionsBuffer<false>,
    ): Promise<Buffer>;
    function verify(
        /** PASETO to verify */
        token: string,
        /** The key to verify with. Alternatively any input that works for `crypto.createPublicKey` */
        key: KeyObject | PublicKeyInput,
        options?: ConsumeOptionsBuffer<true>,
    ): Promise<CompleteResultBuffer>;

    /**
     * Decrypts and validates the claims of a PASETO
     * @example
     * const { createSecretKey } = require('crypto')
     * const { V1 } = require('paseto')
     *
     * const key = createSecretKey(secret)
     *
     * const token = 'v1.public.eyJ1cm46ZXhhbXBsZTpjbGFpbSI6ImZvbyIsImlhdCI6IjIwMTktMDctMDJUMTQ6MDI6MjIuNDg5WiIsImV4cCI6IjIwMTktMDctMDJUMTY6MDI6MjIuNDg5WiIsImF1ZCI6InVybjpleGFtcGxlOmNsaWVudCIsImlzcyI6Imh0dHBzOi8vb3AuZXhhbXBsZS5jb20ifbCaLu19MdLxjrexKh4WTyKr6UoeXzDly_Po1ZNv4wD5CglfY84QqQYTGXLlcLAqZagM3cWJn6xge-lBlT63km6OtOsiWTaKOnYg4MBtQTKmLsjpehpPtDSl_39h2BenB-r911qjYwNNuaRukjrtSVKQtfxdoAoFKEz_eulsDTclEBV7bJrL9Bo0epkJhFShZ6-K8qNd6rTg6Q3YOZCheW1FqNjqfoUYJ9nqPZl2OVbcPdAW3HBeLJefmlL_QGVSRClE2MXOVDrcyf7vGZ0SIj3ylnr6jmEJpzG8o0ap7FblQZI3xp91e-gmw30o6njhSq1ZVWpLqp7FYzq0pknJzGE'
     *
     * (async () => {
     *   await V1.decrypt(token, key, {
     *     audience: 'urn:example:client',
     *     issuer: 'https://op.example.com',
     *     clockTolerance: '1 min'
     *   })
     *   // {
     *   //   'urn:example:claim': 'foo',
     *   //   iat: '2019-07-02T14:03:39.631Z',
     *   //   exp: '2019-07-02T16:03:39.631Z',
     *   //   aud: 'urn:example:client',
     *   //   iss: 'https://op.example.com'
     *   // }
     * })()
     */
    function decrypt(
        /** PASETO to decrypt and validate */
        token: string,
        /** The secret key to decrypt with. Alternatively any input that works for `crypto.createSecretKey` */
        key: KeyObject | Buffer,
        options?: ConsumeOptions<false>,
    ): Promise<object>;
    function decrypt(
        /** PASETO to decrypt and validate */
        token: string,
        /** The secret key to decrypt with. Alternatively any input that works for `crypto.createSecretKey` */
        key: KeyObject | Buffer,
        options?: ConsumeOptions<true>,
    ): Promise<CompleteResult>;
    function decrypt(
        /** PASETO to decrypt and validate */
        token: string,
        /** The secret key to decrypt with. Alternatively any input that works for `crypto.createSecretKey` */
        key: KeyObject | Buffer,
        options?: ConsumeOptionsBuffer<false>,
    ): Promise<Buffer>;
    function decrypt(
        /** PASETO to decrypt and validate */
        token: string,
        /** The secret key to decrypt with. Alternatively any input that works for `crypto.createSecretKey` */
        key: KeyObject | Buffer,
        options?: ConsumeOptionsBuffer<true>,
    ): Promise<CompleteResultBuffer>;

    /** Generates a new secret or private key for a given purpose */
    function generateKey(
        /** PASETO purpose */
        purpose: 'local' | 'public',
    ): Promise<KeyObject>;
}

export namespace V2 {
    /**
     * Serializes and signs the payload as a PASETO using the provided private key
     * @example
     * const { createPrivateKey } = require('crypto')
     * const { V2 } = require('paseto')
     *
     * const key = createPrivateKey(privateKey)
     *
     * const payload = {
     *   'urn:example:claim': 'foo'
     * }
     *
     * (async () => {
     *   const token = await V2.sign(payload, key, {
     *     audience: 'urn:example:client',
     *     issuer: 'https://op.example.com',
     *     expiresIn: '2 hours'
     *   })
     *   // v2.public.eyJ1cm46ZXhhbXBsZTpjbGFpbSI6ImZvbyIsImlhdCI6IjIwMTktMDctMDJUMTM6MzY6MTIuMzgwWiIsImV4cCI6IjIwMTktMDctMDJUMTU6MzY6MTIuMzgwWiIsImF1ZCI6InVybjpleGFtcGxlOmNsaWVudCIsImlzcyI6Imh0dHBzOi8vb3AuZXhhbXBsZS5jb20ifZfV2b1K3xbn8Az3aL24aPtqGRQ3dOf7DP3_GijBekGC2038REYwcyo1rv5o7OOjPuQ7-SqKhPKx0fn6hwm4nAw
     * })()
     */
    function sign(
        /** PASETO Payload claims or payload */
        payload: object | Buffer,
        /** The key to sign with. Alternatively any input that works for `crypto.createPrivateKey` */
        key: KeyObject | PrivateKeyInput,
        options?: ProduceOptions,
    ): Promise<string>;

    /**
     * Verifies the claims and signature of a PASETO
     * @example
     * const { createPublicKey } = require('crypto')
     * const { V2 } = require('paseto')
     *
     * const key = createPrivateKey(publicKey)
     *
     * const token = 'v2.public.eyJ1cm46ZXhhbXBsZTpjbGFpbSI6ImZvbyIsImlhdCI6IjIwMTktMDctMDJUMTM6MzY6MTIuMzgwWiIsImV4cCI6IjIwMTktMDctMDJUMTU6MzY6MTIuMzgwWiIsImF1ZCI6InVybjpleGFtcGxlOmNsaWVudCIsImlzcyI6Imh0dHBzOi8vb3AuZXhhbXBsZS5jb20ifZfV2b1K3xbn8Az3aL24aPtqGRQ3dOf7DP3_GijBekGC2038REYwcyo1rv5o7OOjPuQ7-SqKhPKx0fn6hwm4nAw'
     *
     * (async () => {
     *   await V2.verify(token, key, {
     *     audience: 'urn:example:client',
     *     issuer: 'https://op.example.com',
     *     clockTolerance: '1 min'
     *   })
     *   // {
     *   //   'urn:example:claim': 'foo',
     *   //   iat: '2019-07-02T13:36:12.380Z',
     *   //   exp: '2019-07-02T15:36:12.380Z',
     *   //   aud: 'urn:example:client',
     *   //   iss: 'https://op.example.com'
     *   // }
     * })()
     */
    function verify(
        /** PASETO to verify */
        token: string,
        /** The key to verify with. Alternatively any input that works for `crypto.createPublicKey` */
        key: KeyObject | PublicKeyInput,
        options?: ConsumeOptions<false>,
    ): Promise<object>;
    function verify(
        /** PASETO to verify */
        token: string,
            /** The key to verify with. Alternatively any input that works for `crypto.createPublicKey` */
        key: KeyObject | PublicKeyInput,
        options?: ConsumeOptions<true>,
    ): Promise<CompleteResult>;
    function verify(
        /** PASETO to verify */
        token: string,
        /** The key to verify with. Alternatively any input that works for `crypto.createPublicKey` */
        key: KeyObject | PublicKeyInput,
        options?: ConsumeOptionsBuffer<false>,
    ): Promise<Buffer>;
    function verify(
        /** PASETO to verify */
        token: string,
        /** The key to verify with. Alternatively any input that works for `crypto.createPublicKey` */
        key: KeyObject | PublicKeyInput,
        options?: ConsumeOptionsBuffer<true>,
    ): Promise<CompleteResultBuffer>;

    /** Generates a new secret or private key for a given purpose */
    function generateKey(
        /** PASETO purpose */
        purpose: 'public',
    ): Promise<KeyObject>;
}

export namespace errors {
    /** Base Error the others inherit from */
    class PasetoError extends Error {}

    /**
     * Thrown when PASETO Claim is either of incorrect type or fails to validate by the provided options
     * @example
     * if (err.code === 'ERR_PASETO_CLAIM_INVALID') {
     *   // ...
     * }
     */
    class PasetoClaimInvalid extends PasetoError {}
    /**
     * Thrown when a PASETO decrypt operations are started but fail to decrypt. Only generic error message is provided
     * @example
     * if (err.code === 'ERR_PASETO_DECRYPTION_FAILED') {
     *   // ...
     * }
     */
    class PasetoDecryptionFailed extends PasetoError {}
    /**
     * Thrown when PASETO is not in a valid format
     * @example
     * if (err.code === 'ERR_PASETO_INVALID') {
     *   // ...
     * }
     */
    class PasetoInvalid extends PasetoError {}
    /**
     * Thrown when a particular feature, e.g. version, purpose or anything else is not supported
     * @example
     * if (err.code === 'ERR_PASETO_NOT_SUPPORTED') {
     *   // ...
     * }
     */
    class PasetoNotSupported extends PasetoError {}
    /**
     * Thrown when a PASETO verify operations are started but fail to verify. Only generic error message is provided
     * @example
     * if (err.code === 'ERR_PASETO_VERIFICATION_FAILED') {
     *   // ...
     * }
     */
    class PasetoVerificationFailed extends PasetoError {}
}
