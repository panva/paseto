# paseto API Documentation

> [PASETO](https://paseto.io): <strong>P</strong>latform-<strong>A</strong>gnostic <strong>SE</strong>curity <strong>TO</strong>kens for Node.js with minimal dependencies

**Table of Contents**

- [V2 (PASETO Protocol Version v2)](#v2-paseto-protocol-version-v2)
- [V1 (PASETO Protocol Version v1)](#v1-paseto-protocol-version-v1)
- [decode](#decode)
- [errors](#errors)

## Support

If you or your business use paseto, please consider becoming a [sponsor][support-sponsor] so I can continue maintaining it and adding new features carefree.

<br>

---

## V2 (PASETO Protocol Version v2)

<!-- TOC V2 START -->
- [V2.sign(payload, key[, options])](#v2signpayload-key-options)
- [V2.verify(token, key[, options])](#v2verifytoken-key-options)
- [V2.encrypt(payload, key[, options])](#v2encryptpayload-key-options)
- [V2.decrypt(token, key[, options])](#v2decrypttoken-key-options)
- [V2.generateKey(purpose)](#v2generatekeypurpose)
<!-- TOC V2 END -->


```js
const { V2 } = require('paseto')
// {
//   sign: [AsyncFunction: v2Sign],
//   verify: [AsyncFunction: v2Verify],
//   encrypt: [AsyncFunction: v2Encrypt],
//   decrypt: [AsyncFunction: v2Decrypt],
//   generateKey: [AsyncFunction: generateKey]
// }
```

---
#### V2.sign(payload, key[, options])

Serializes and signs the payload as a PASETO using the provided private key.

- `payload`: `<Object>` PASETO Payload claims
- `key`: `<KeyObject>` The key to sign with. Alternatively any input that works for `crypto.createPrivateKey`
- `options`: `<Object>`
  - `audience`: `<string>` PASETO Audience, "aud" claim value, if provided it will replace
    "aud" found in the payload
  - `expiresIn`: `<string>` PASETO Expiration Time, "exp" claim value, specified as string which is
    added to the current unix epoch timestamp e.g. `24 hours`, `20 m`, `60s`, etc., if provided it
    will replace Expiration Time found in the payload
  - `footer`: `<Object>` &vert; `<string>` &vert; `<Buffer>` PASETO footer
  - `iat`: `<Boolean>` When true it pushes the "iat" to the PASETO payload. **Default:** 'true'
  - `issuer`: `<string>` PASETO Issuer, "iss" claim value, if provided it will replace "iss" found in
    the payload
  - `jti`: `<string>` Token ID, "jti" claim value, if provided it will replace "jti" found in the
    payload
  - `kid`: `<string>` Key ID, "kid" claim value, if provided it will replace "kid" found in the
    payload
  - `notBefore`: `<string>` PASETO Not Before, "nbf" claim value, specified as string which is added to
    the current unix epoch timestamp e.g. `24 hours`, `20 m`, `60s`, etc., if provided it will
    replace Not Before found in the payload
  - `now`: `<Date>` Date object to be used instead of the current unix epoch timestamp.
    **Default:** 'new Date()'
  - `subject`: `<string>` PASETO subject, "sub" claim value, if provided it will replace "sub" found in
    the payload
- Returns: `Promise<string>`

<details>
<summary><em><strong>Example</strong></em> (Click to expand)</summary>

```js
const { createPrivateKey } = require('crypto')
const { V2 } = require('paseto')

const key = createPrivateKey(privateKey)

const payload = {
  'urn:example:claim': 'foo'
}

(async () => {
  const token = await V2.sign(payload, key, {
    audience: 'urn:example:client',
    issuer: 'https://op.example.com',
    expiresIn: '2 hours'
  })
  // v2.public.eyJ1cm46ZXhhbXBsZTpjbGFpbSI6ImZvbyIsImlhdCI6IjIwMTktMDctMDJUMTM6MzY6MTIuMzgwWiIsImV4cCI6IjIwMTktMDctMDJUMTU6MzY6MTIuMzgwWiIsImF1ZCI6InVybjpleGFtcGxlOmNsaWVudCIsImlzcyI6Imh0dHBzOi8vb3AuZXhhbXBsZS5jb20ifZfV2b1K3xbn8Az3aL24aPtqGRQ3dOf7DP3_GijBekGC2038REYwcyo1rv5o7OOjPuQ7-SqKhPKx0fn6hwm4nAw
})()
```
</details>

---

#### V2.verify(token, key[, options])

Verifies the claims and signature of a PASETO

- `token`: `<String>` PASETO to verify
- `key`: `<KeyObject>` The key to verify with. Alternatively any input that works for `crypto.createPublicKey`.
- `options`: `<Object>`
  - `audience`: `<string>` Expected audience value. An exact match must be found in the payload.
  - `clockTolerance`: `<string>` Clock Tolerance for comparing timestamps, provided as timespan
    string e.g. `120s`, `2 minutes`, etc. **Default:** no clock tolerance
  - `complete`: `<Boolean>` When false only the parsed payload is returned, otherwise an object with
    a parsed payload and footer (as a Buffer) will be returned.
    **Default:** 'false'
  - `ignoreExp`: `<Boolean>` When true will not be validating the "exp" claim value to be in the
    future from now. **Default:** 'false'
  - `ignoreIat`: `<Boolean>` When true will not be validating the "iat" claim value to be in the
    past from now. **Default:** 'false'
  - `ignoreNbf`: `<Boolean>` When true will not be validating the "nbf" claim value to be in the
    past from now. **Default:** 'false'
  - `issuer`: `<string>` Expected issuer value. An exact match must be found in the payload.
  - `maxTokenAge`: `<string>` When provided the payload is checked to have the "iat" claim and its
    value is validated not to be older than the provided timespan string e.g. `30m`, `24 hours`.
    Do not confuse with maxAuthAge option.
  - `now`: `<Date>` Date object to be used instead of the current unix epoch timestamp.
    **Default:** 'new Date()'
  - `subject`: `<string>` Expected subject value. An exact match must be found in the payload.
- Returns: `Promise<Object>`

<details>
<summary><em><strong>Example</strong></em> (Click to expand)</summary>

```js
const { createPublicKey } = require('crypto')
const { V2 } = require('paseto')

const key = createPrivateKey(publicKey)

const token = 'v2.public.eyJ1cm46ZXhhbXBsZTpjbGFpbSI6ImZvbyIsImlhdCI6IjIwMTktMDctMDJUMTM6MzY6MTIuMzgwWiIsImV4cCI6IjIwMTktMDctMDJUMTU6MzY6MTIuMzgwWiIsImF1ZCI6InVybjpleGFtcGxlOmNsaWVudCIsImlzcyI6Imh0dHBzOi8vb3AuZXhhbXBsZS5jb20ifZfV2b1K3xbn8Az3aL24aPtqGRQ3dOf7DP3_GijBekGC2038REYwcyo1rv5o7OOjPuQ7-SqKhPKx0fn6hwm4nAw'

(async () => {
  await V2.verify(token, key, {
    audience: 'urn:example:client',
    issuer: 'https://op.example.com',
    clockTolerance: '1 min'
  })
  // {
  //   'urn:example:claim': 'foo',
  //   iat: '2019-07-02T13:36:12.380Z',
  //   exp: '2019-07-02T15:36:12.380Z',
  //   aud: 'urn:example:client',
  //   iss: 'https://op.example.com'
  // }
})()
```
</details>

---

#### V2.encrypt(payload, key[, options])

Serializes and encrypts the payload as a PASETO using the provided secret key.

- `payload`: `<Object>` PASETO Payload claims
- `key`: `<KeyObject>` The secret key to encrypt with. Alternatively any input that works for `crypto.createSecretKey`
- `options`: `<Object>`
  - `audience`: `<string>` PASETO Audience, "aud" claim value, if provided it will replace
    "aud" found in the payload
  - `expiresIn`: `<string>` PASETO Expiration Time, "exp" claim value, specified as string which is
    added to the current unix epoch timestamp e.g. `24 hours`, `20 m`, `60s`, etc., if provided it
    will replace Expiration Time found in the payload
  - `footer`: `<Object>` &vert; `<string>` &vert; `<Buffer>` PASETO footer
  - `iat`: `<Boolean>` When true it pushes the "iat" to the PASETO payload. **Default:** 'true'
  - `issuer`: `<string>` PASETO Issuer, "iss" claim value, if provided it will replace "iss" found in
    the payload
  - `jti`: `<string>` Token ID, "jti" claim value, if provided it will replace "jti" found in the
    payload
  - `kid`: `<string>` Key ID, "kid" claim value, if provided it will replace "kid" found in the
    payload
  - `notBefore`: `<string>` PASETO Not Before, "nbf" claim value, specified as string which is added to
    the current unix epoch timestamp e.g. `24 hours`, `20 m`, `60s`, etc., if provided it will
    replace Not Before found in the payload
  - `now`: `<Date>` Date object to be used instead of the current unix epoch timestamp.
    **Default:** 'new Date()'
  - `subject`: `<string>` PASETO subject, "sub" claim value, if provided it will replace "sub" found in
    the payload
- Returns: `Promise<string>`

<details>
<summary><em><strong>Example</strong></em> (Click to expand)</summary>

```js
const { createSecretKey } = require('crypto')
const { V2 } = require('paseto')

const key = createSecretKey(secret)

const payload = {
  'urn:example:claim': 'foo'
}

(async () => {
  const token = await V2.encrypt(payload, key, {
    audience: 'urn:example:client',
    issuer: 'https://op.example.com',
    expiresIn: '2 hours'
  })
  // v2.local.qPegA36ANA_Q4GnR6BCBQqW2O6N3UVE0X0cJEzPHguKv8YeUlhMz7mRqp-LqCJ0hMDwsvoJ1xYrx2sT5yf_T-WiBj_gVddUyL4HEUPyYxWVWQtl8CZ-YTDsw1adQetScDvg91P-IK-1FlRfp2lZE8BOYnGgUKTjbtnpy3XOsgnqc4K4K0KDTURXQgs2-FDcfRm3bjxTlRoOnetNEyabmnB1od3wOesyrqNv7migvgq-nvxZi-7rv1qVATgXFyFQ
})()
```
</details>

---

#### V2.decrypt(token, key[, options])

Decrypts and validates the claims of a PASETO

- `token`: `<String>` PASETO to decrypt and validate
- `key`: `<KeyObject>` The secret key to decrypt with. Alternatively any input that works for `crypto.createSecretKey`
- `options`: `<Object>`
  - `audience`: `<string>` Expected audience value. An exact match must be found in the payload.
  - `clockTolerance`: `<string>` Clock Tolerance for comparing timestamps, provided as timespan
    string e.g. `120s`, `2 minutes`, etc. **Default:** no clock tolerance
  - `complete`: `<Boolean>` When false only the parsed payload is returned, otherwise an object with
    a parsed payload and footer (as a Buffer) will be returned.
    **Default:** 'false'
  - `ignoreExp`: `<Boolean>` When true will not be validating the "exp" claim value to be in the
    future from now. **Default:** 'false'
  - `ignoreIat`: `<Boolean>` When true will not be validating the "iat" claim value to be in the
    past from now. **Default:** 'false'
  - `ignoreNbf`: `<Boolean>` When true will not be validating the "nbf" claim value to be in the
    past from now. **Default:** 'false'
  - `issuer`: `<string>` Expected issuer value. An exact match must be found in the payload.
  - `maxTokenAge`: `<string>` When provided the payload is checked to have the "iat" claim and its
    value is validated not to be older than the provided timespan string e.g. `30m`, `24 hours`.
    Do not confuse with maxAuthAge option.
  - `now`: `<Date>` Date object to be used instead of the current unix epoch timestamp.
    **Default:** 'new Date()'
  - `subject`: `<string>` Expected subject value. An exact match must be found in the payload.
- Returns: `Promise<Object>`

<details>
<summary><em><strong>Example</strong></em> (Click to expand)</summary>

```js
const { createSecretKey } = require('crypto')
const { V2 } = require('paseto')

const key = createSecretKey(secret)

const token = 'v2.local.qPegA36ANA_Q4GnR6BCBQqW2O6N3UVE0X0cJEzPHguKv8YeUlhMz7mRqp-LqCJ0hMDwsvoJ1xYrx2sT5yf_T-WiBj_gVddUyL4HEUPyYxWVWQtl8CZ-YTDsw1adQetScDvg91P-IK-1FlRfp2lZE8BOYnGgUKTjbtnpy3XOsgnqc4K4K0KDTURXQgs2-FDcfRm3bjxTlRoOnetNEyabmnB1od3wOesyrqNv7migvgq-nvxZi-7rv1qVATgXFyFQ'

(async () => {
  await V2.decrypt(token, key, {
    audience: 'urn:example:client',
    issuer: 'https://op.example.com',
    clockTolerance: '1 min'
  })
  // {
  //   'urn:example:claim': 'foo',
  //   iat: '2019-07-02T13:50:39.735Z',
  //   exp: '2019-07-02T15:50:39.735Z',
  //   aud: 'urn:example:client',
  //   iss: 'https://op.example.com'
  // }
})()
```
</details>

---

#### V2.generateKey(purpose)

Generates a new secret or private key for a given purpose.

- `purpose`: `<string>` PASETO purpose, either 'local' or 'public'
- Returns: `Promise<KeyObject>`

---

## V1 (PASETO Protocol Version v1)

<!-- TOC V1 START -->
- [V1.sign(payload, key[, options])](#v1signpayload-key-options)
- [V1.verify(token, key[, options])](#v1verifytoken-key-options)
- [V1.encrypt(payload, key[, options])](#v1encryptpayload-key-options)
- [V1.decrypt(token, key[, options])](#v1decrypttoken-key-options)
- [V1.generateKey(purpose)](#v1generatekeypurpose)
<!-- TOC V1 END -->


```js
const { V1 } = require('paseto')
// {
//   sign: [AsyncFunction: v1Sign],
//   verify: [AsyncFunction: v1Verify],
//   encrypt: [AsyncFunction: v1Encrypt],
//   decrypt: [AsyncFunction: v1Decrypt],
//   generateKey: [AsyncFunction: generateKey]
// }
```

---
#### V1.sign(payload, key[, options])

Serializes and signs the payload as a PASETO using the provided private key.

- `payload`: `<Object>` PASETO Payload claims
- `key`: `<KeyObject>` The key to sign with. Alternatively any input that works for `crypto.createPrivateKey`
- `options`: `<Object>`
  - `audience`: `<string>` PASETO Audience, "aud" claim value, if provided it will replace
    "aud" found in the payload
  - `expiresIn`: `<string>` PASETO Expiration Time, "exp" claim value, specified as string which is
    added to the current unix epoch timestamp e.g. `24 hours`, `20 m`, `60s`, etc., if provided it
    will replace Expiration Time found in the payload
  - `footer`: `<Object>` &vert; `<string>` &vert; `<Buffer>` PASETO footer
  - `iat`: `<Boolean>` When true it pushes the "iat" to the PASETO payload. **Default:** 'true'
  - `issuer`: `<string>` PASETO Issuer, "iss" claim value, if provided it will replace "iss" found in
    the payload
  - `jti`: `<string>` Token ID, "jti" claim value, if provided it will replace "jti" found in the
    payload
  - `kid`: `<string>` Key ID, "kid" claim value, if provided it will replace "kid" found in the
    payload
  - `notBefore`: `<string>` PASETO Not Before, "nbf" claim value, specified as string which is added to
    the current unix epoch timestamp e.g. `24 hours`, `20 m`, `60s`, etc., if provided it will
    replace Not Before found in the payload
  - `now`: `<Date>` Date object to be used instead of the current unix epoch timestamp.
    **Default:** 'new Date()'
  - `subject`: `<string>` PASETO subject, "sub" claim value, if provided it will replace "sub" found in
    the payload
- Returns: `Promise<string>`

<details>
<summary><em><strong>Example</strong></em> (Click to expand)</summary>

```js
const { createPrivateKey } = require('crypto')
const { V1 } = require('paseto')

const key = createPrivateKey(privateKey)

const payload = {
  'urn:example:claim': 'foo'
}

(async () => {
  const token = await V1.sign(payload, key, {
    audience: 'urn:example:client',
    issuer: 'https://op.example.com',
    expiresIn: '2 hours'
  })
  // v1.public.eyJ1cm46ZXhhbXBsZTpjbGFpbSI6ImZvbyIsImlhdCI6IjIwMTktMDctMDJUMTQ6MDI6MjIuNDg5WiIsImV4cCI6IjIwMTktMDctMDJUMTY6MDI6MjIuNDg5WiIsImF1ZCI6InVybjpleGFtcGxlOmNsaWVudCIsImlzcyI6Imh0dHBzOi8vb3AuZXhhbXBsZS5jb20ifbCaLu19MdLxjrexKh4WTyKr6UoeXzDly_Po1ZNv4wD5CglfY84QqQYTGXLlcLAqZagM3cWJn6xge-lBlT63km6OtOsiWTaKOnYg4MBtQTKmLsjpehpPtDSl_39h2BenB-r911qjYwNNuaRukjrtSVKQtfxdoAoFKEz_eulsDTclEBV7bJrL9Bo0epkJhFShZ6-K8qNd6rTg6Q3YOZCheW1FqNjqfoUYJ9nqPZl2OVbcPdAW3HBeLJefmlL_QGVSRClE2MXOVDrcyf7vGZ0SIj3ylnr6jmEJpzG8o0ap7FblQZI3xp91e-gmw30o6njhSq1ZVWpLqp7FYzq0pknJzGE
})()
```
</details>

---

#### V1.verify(token, key[, options])

Verifies the claims and signature of a PASETO

- `token`: `<String>` PASETO to verify
- `key`: `<KeyObject>` The key to verify with. Alternatively any input that works for `crypto.createPublicKey`.
- `options`: `<Object>`
  - `audience`: `<string>` Expected audience value. An exact match must be found in the payload.
  - `clockTolerance`: `<string>` Clock Tolerance for comparing timestamps, provided as timespan
    string e.g. `120s`, `2 minutes`, etc. **Default:** no clock tolerance
  - `complete`: `<Boolean>` When false only the parsed payload is returned, otherwise an object with
    a parsed payload and footer (as a Buffer) will be returned.
    **Default:** 'false'
  - `ignoreExp`: `<Boolean>` When true will not be validating the "exp" claim value to be in the
    future from now. **Default:** 'false'
  - `ignoreIat`: `<Boolean>` When true will not be validating the "iat" claim value to be in the
    past from now. **Default:** 'false'
  - `ignoreNbf`: `<Boolean>` When true will not be validating the "nbf" claim value to be in the
    past from now. **Default:** 'false'
  - `issuer`: `<string>` Expected issuer value. An exact match must be found in the payload.
  - `maxTokenAge`: `<string>` When provided the payload is checked to have the "iat" claim and its
    value is validated not to be older than the provided timespan string e.g. `30m`, `24 hours`.
    Do not confuse with maxAuthAge option.
  - `now`: `<Date>` Date object to be used instead of the current unix epoch timestamp.
    **Default:** 'new Date()'
  - `subject`: `<string>` Expected subject value. An exact match must be found in the payload.
- Returns: `Promise<Object>`

<details>
<summary><em><strong>Example</strong></em> (Click to expand)</summary>

```js
const { createPublicKey } = require('crypto')
const { V1 } = require('paseto')

const key = createPrivateKey(publicKey)

const token = 'v1.public.eyJ1cm46ZXhhbXBsZTpjbGFpbSI6ImZvbyIsImlhdCI6IjIwMTktMDctMDJUMTQ6MDI6MjIuNDg5WiIsImV4cCI6IjIwMTktMDctMDJUMTY6MDI6MjIuNDg5WiIsImF1ZCI6InVybjpleGFtcGxlOmNsaWVudCIsImlzcyI6Imh0dHBzOi8vb3AuZXhhbXBsZS5jb20ifbCaLu19MdLxjrexKh4WTyKr6UoeXzDly_Po1ZNv4wD5CglfY84QqQYTGXLlcLAqZagM3cWJn6xge-lBlT63km6OtOsiWTaKOnYg4MBtQTKmLsjpehpPtDSl_39h2BenB-r911qjYwNNuaRukjrtSVKQtfxdoAoFKEz_eulsDTclEBV7bJrL9Bo0epkJhFShZ6-K8qNd6rTg6Q3YOZCheW1FqNjqfoUYJ9nqPZl2OVbcPdAW3HBeLJefmlL_QGVSRClE2MXOVDrcyf7vGZ0SIj3ylnr6jmEJpzG8o0ap7FblQZI3xp91e-gmw30o6njhSq1ZVWpLqp7FYzq0pknJzGE'

(async () => {
  await V1.verify(token, key, {
    audience: 'urn:example:client',
    issuer: 'https://op.example.com',
    clockTolerance: '1 min'
  })
  // {
  //   'urn:example:claim': 'foo',
  //   iat: '2019-07-02T14:02:22.489Z',
  //   exp: '2019-07-02T16:02:22.489Z',
  //   aud: 'urn:example:client',
  //   iss: 'https://op.example.com'
  // }
})()
```
</details>

---

#### V1.encrypt(payload, key[, options])

Serializes and encrypts the payload as a PASETO using the provided secret key.

- `payload`: `<Object>` PASETO Payload claims
- `key`: `<KeyObject>` The secret key to encrypt with. Alternatively any input that works for `crypto.createSecretKey`
- `options`: `<Object>`
  - `audience`: `<string>` PASETO Audience, "aud" claim value, if provided it will replace
    "aud" found in the payload
  - `expiresIn`: `<string>` PASETO Expiration Time, "exp" claim value, specified as string which is
    added to the current unix epoch timestamp e.g. `24 hours`, `20 m`, `60s`, etc., if provided it
    will replace Expiration Time found in the payload
  - `footer`: `<Object>` &vert; `<string>` &vert; `<Buffer>` PASETO footer
  - `iat`: `<Boolean>` When true it pushes the "iat" to the PASETO payload. **Default:** 'true'
  - `issuer`: `<string>` PASETO Issuer, "iss" claim value, if provided it will replace "iss" found in
    the payload
  - `jti`: `<string>` Token ID, "jti" claim value, if provided it will replace "jti" found in the
    payload
  - `kid`: `<string>` Key ID, "kid" claim value, if provided it will replace "kid" found in the
    payload
  - `notBefore`: `<string>` PASETO Not Before, "nbf" claim value, specified as string which is added to
    the current unix epoch timestamp e.g. `24 hours`, `20 m`, `60s`, etc., if provided it will
    replace Not Before found in the payload
  - `now`: `<Date>` Date object to be used instead of the current unix epoch timestamp.
    **Default:** 'new Date()'
  - `subject`: `<string>` PASETO subject, "sub" claim value, if provided it will replace "sub" found in
    the payload
- Returns: `Promise<string>`

<details>
<summary><em><strong>Example</strong></em> (Click to expand)</summary>

```js
const { createSecretKey } = require('crypto')
const { V1 } = require('paseto')

const key = createSecretKey(secret)

const payload = {
  'urn:example:claim': 'foo'
}

(async () => {
  const token = await V1.encrypt(payload, key, {
    audience: 'urn:example:client',
    issuer: 'https://op.example.com',
    expiresIn: '2 hours'
  })
  // v1.local.1X8AshBYnBXTevpH6s21lTZzPL8k-pVaRBsfU5uFfpDWAoG8NZAB5LwQgUpcsgAbZj-wpDMix1Mzw_viBbntWjqEZAVOe-BTMhVKSe43u3fUM2EfRcNFHzPVY_2I_CqGjhW2qs6twNvgv5kEhOiUnTSgZMtCn9h6L_KlKz8YrWcGdGypBYcs5ooMClKvOhb2_M8wHqG_PCgAkgO5PBbHk1g6UnTgGgztuEMrcchLd7UJqNDU2I7TyQ9x7ofvndE35ODYaf-SefrJb72tuXaUqFbkAwKPs77EwvnWE5dgo6bbsp5KMdxq
})()
```
</details>

---

#### V1.decrypt(token, key[, options])

Decrypts and validates the claims of a PASETO

- `token`: `<String>` PASETO to decrypt and validate
- `key`: `<KeyObject>` The secret key to decrypt with. Alternatively any input that works for `crypto.createSecretKey`
- `options`: `<Object>`
  - `audience`: `<string>` Expected audience value. An exact match must be found in the payload.
  - `clockTolerance`: `<string>` Clock Tolerance for comparing timestamps, provided as timespan
    string e.g. `120s`, `2 minutes`, etc. **Default:** no clock tolerance
  - `complete`: `<Boolean>` When false only the parsed payload is returned, otherwise an object with
    a parsed payload and footer (as a Buffer) will be returned.
    **Default:** 'false'
  - `ignoreExp`: `<Boolean>` When true will not be validating the "exp" claim value to be in the
    future from now. **Default:** 'false'
  - `ignoreIat`: `<Boolean>` When true will not be validating the "iat" claim value to be in the
    past from now. **Default:** 'false'
  - `ignoreNbf`: `<Boolean>` When true will not be validating the "nbf" claim value to be in the
    past from now. **Default:** 'false'
  - `issuer`: `<string>` Expected issuer value. An exact match must be found in the payload.
  - `maxTokenAge`: `<string>` When provided the payload is checked to have the "iat" claim and its
    value is validated not to be older than the provided timespan string e.g. `30m`, `24 hours`.
    Do not confuse with maxAuthAge option.
  - `now`: `<Date>` Date object to be used instead of the current unix epoch timestamp.
    **Default:** 'new Date()'
  - `subject`: `<string>` Expected subject value. An exact match must be found in the payload.
- Returns: `Promise<Object>`

<details>
<summary><em><strong>Example</strong></em> (Click to expand)</summary>

```js
const { createSecretKey } = require('crypto')
const { V1 } = require('paseto')

const key = createSecretKey(secret)

const token = 'v2.local.qPegA36ANA_Q4GnR6BCBQqW2O6N3UVE0X0cJEzPHguKv8YeUlhMz7mRqp-LqCJ0hMDwsvoJ1xYrx2sT5yf_T-WiBj_gVddUyL4HEUPyYxWVWQtl8CZ-YTDsw1adQetScDvg91P-IK-1FlRfp2lZE8BOYnGgUKTjbtnpy3XOsgnqc4K4K0KDTURXQgs2-FDcfRm3bjxTlRoOnetNEyabmnB1od3wOesyrqNv7migvgq-nvxZi-7rv1qVATgXFyFQ'

(async () => {
  await V1.decrypt(token, key, {
    audience: 'urn:example:client',
    issuer: 'https://op.example.com',
    clockTolerance: '1 min'
  })
  // {
  //   'urn:example:claim': 'foo',
  //   iat: '2019-07-02T14:03:39.631Z',
  //   exp: '2019-07-02T16:03:39.631Z',
  //   aud: 'urn:example:client',
  //   iss: 'https://op.example.com'
  // }
})()
```
</details>

---

#### V1.generateKey(purpose)

Generates a new secret or private key for a given purpose.

- `purpose`: `<string>` PASETO purpose, either 'local' or 'public'
- Returns: `Promise<KeyObject>`

---

## Decode

#### decode(token)

Decodes a PASETO, does not perform any payload validations.

- `token`: `<String>` PASETO to decrypt and validate
- Returns: `<Object>`

<details>
<summary><em><strong>Example</strong></em> (Click to expand)</summary>

```js
const { decode } = require('paseto')

const token = 'v2.public.eyJ1cm46ZXhhbXBsZTpjbGFpbSI6ImZvbyIsImlhdCI6IjIwMTktMDctMDJUMTY6MzQ6NDMuMjA0WiIsImV4cCI6IjIwMTktMDctMDJUMTg6MzQ6NDMuMjA0WiIsImF1ZCI6InVybjpleGFtcGxlOmNsaWVudCIsImlzcyI6Imh0dHBzOi8vb3AuZXhhbXBsZS5jb20ifcEgHmn3JIHqfZgZC_jF-GT7QY-hoUnCbNPRP0Mnf_j_jjchA4OGkyv74sN1z7Yj6KQMe6sXly5jX6QHn0mD6As.eyJraWQiOiJmb28ifQ'

decode(token)
// {
//   footer: <Buffer 7b 22 6b 69 64 22 3a 22 66 6f 6f 22 7d>,
//   payload: {
//     'urn:example:claim': 'foo',
//     iat: '2019-07-02T16:34:43.204Z',
//     exp: '2019-07-02T18:34:43.204Z',
//     aud: 'urn:example:client',
//     iss: 'https://op.example.com'
//   },
//   version: 'v2',
//   purpose: 'public'
// }
```
</details>

---

## Errors

<!-- TOC Errors START -->
- [Class: &lt;TypeError&gt;](#class-typeerror)
- [Class: &lt;PasetoError&gt;](#class-pasetoerror)
- [Class: &lt;PasetoInvalid&gt;](#class-pasetoinvalid)
- [Class: &lt;PasetoNotSupported&gt;](#class-pasetonotsupported)
- [Class: &lt;PasetoDecryptionFailed&gt;](#class-pasetodecryptionfailed)
- [Class: &lt;PasetoVerificationFailed&gt;](#class-pasetoverificationfailed)
- [Class: &lt;PasetoClaimInvalid&gt;](#class-pasetoclaiminvalid)
<!-- TOC Errors END -->


The following errors are expected to be thrown by paseto runtime and have their prototypes
exported in `paseto.errors`. If you encounter an `Error` other then `TypeError` or one that's
`instanceof paseto.errors.PasetoError` please [report it][bug], it is not intended.

#### Class: `TypeError`

Thrown when unexpected argument types or their format is encountered. This is the standard built-in
[`TypeError`](https://nodejs.org/api/errors.html#errors_class_typeerror).

#### Class: `PasetoError`

Base Error the others inherit from.

#### Class: `PasetoInvalid`

Thrown when PASETO is not in a valid format

```js
if (err.code === 'ERR_PASETO_INVALID') {
  // ...
}
```

#### Class: `PasetoNotSupported`

Thrown when a particular feature, e.g. version, purpose or anything else is not supported.

```js
if (err.code === 'ERR_PASETO_NOT_SUPPORTED') {
  // ...
}
```

#### Class: `PasetoDecryptionFailed`

Thrown when a PASETO decrypt operations are started but fail to decrypt. Only generic error
message is  provided.

```js
if (err.code === 'ERR_PASETO_DECRYPTION_FAILED') {
  // ...
}
```

#### Class: `PasetoVerificationFailed`

Thrown when a PASETO verify operations are started but fail to verify. Only generic error
message is provided.

```js
if (err.code === 'ERR_PASETO_VERIFICATION_FAILED') {
  // ...
}
```

#### Class: `PasetoClaimInvalid`

Thrown when PASETO Claim is either of incorrect type or fails to validate by the provided
options.

```js
if (err.code === 'ERR_PASETO_CLAIM_INVALID') {
  // ...
}
```


[spec-thumbprint]: https://tools.ietf.org/html/rfc7638
[support-sponsor]: https://github.com/sponsors/panva
[bug]: https://github.com/panva/paseto/issues/new?labels=bug&template=bug-report.md&title=bug%3A+
