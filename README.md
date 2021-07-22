# paseto

> [PASETO](https://paseto.io): <strong>P</strong>latform-<strong>A</strong>gnostic <strong>SE</strong>curity <strong>TO</strong>kens for Node.js no dependencies.

## Implemented Protocol Versions

|  | v1 | v2 | v3 | v4 | 
| -- | -- | -- | -- | -- |
| local | ✓ | ✕ | ✓ | ✕ |
| public | ✓ | ✓ | ✓ | ✓ |

## Support

If you or your business use paseto, please consider becoming a [sponsor][support-sponsor] so I can continue maintaining it and adding new features carefree.

## Documentation

- [API Documentation][documentation]
  - [PASETO Protocol Version v4][documentation-v4]
  - [PASETO Protocol Version v3][documentation-v3]
  - [PASETO Protocol Version v2][documentation-v2]
  - [PASETO Protocol Version v1][documentation-v1]

## Usage

Installing paseto

```console
npm install paseto
```

Usage
```js
const paseto = require('paseto')

// Generic (all versions) APIs
const { decode } = paseto

// PASETO Protocol Version v1 specific API
const { V1 } = paseto // { sign, verify, encrypt, decrypt, generateKey }

// PASETO Protocol Version v2 specific API
const { V2 } = paseto // { sign, verify, generateKey }

// PASETO Protocol Version v3 specific API
const { V3 } = paseto // { sign, verify, encrypt, decrypt, generateKey }

// PASETO Protocol Version v4 specific API
const { V4 } = paseto // { sign, verify, generateKey }

// errors utilized by paseto
const { errors } = paseto
```

#### Producing tokens

```js
const { V2: { sign } } = paseto

(async () => {
  {
    const token = await sign({ sub: 'johndoe' }, privateKey)
    // v2.public.eyJzdWIiOiJqb2huZG9lIiwiaWF0IjoiMjAxOS0wNy0wMVQxNToyMTozMS40OTJaIn0tpEwuwb-loL652KAZhmCYdDUNW8YbF6UYCFCYLk-fexhzs2ofL4AyHTqIk0HzIxawufEibT1ZyJ7MPBJUVpsF
  }
})()
```

#### Consuming tokens

```js
const { V2: { verify } } = paseto

(async () => {
  {
    const payload = await verify(token, publicKey)
    // { sub: 'johndoe', iat: '2019-07-01T15:22:47.982Z' }
  }
})()
```

#### Keys

Node's [KeyObject](https://nodejs.org/api/crypto.html#crypto_class_keyobject) is ultimately what the
library works with, depending on the operation, if the key parameter is not already a KeyObject
instance the corresponding `create` function will be called with the input

- [`crypto.createSecretKey()`](https://nodejs.org/api/crypto.html#crypto_crypto_createsecretkey_key)
  for local encrypt/decrypt operations
- [`crypto.createPublicKey()`](https://nodejs.org/api/crypto.html#crypto_crypto_createpublickey_key)
  for public verify operations
- [`crypto.createPrivateKey()`](https://nodejs.org/api/crypto.html#crypto_crypto_createprivatekey_key)
  for public sign operations

You can also generate keys valid for the given operation directly through paseto

```js
const crypto = require('crypto')
const { V1, V2, V3, V4 } = paseto

(async () => {
  {
    const key = await V1.generateKey('local')
    console.log(key instanceof crypto.KeyObject)
    // true
    console.log(key.type === 'secret')
    // true
    console.log(key.symmetricKeySize === 32)
    // true
  }
  {
    const key = await V1.generateKey('public')
    console.log(key instanceof crypto.KeyObject)
    // true
    console.log(key.type === 'private')
    // true
    console.log(key.asymmetricKeyType === 'rsa')
    // true
  }
  {
    const key = await V2.generateKey('public')
    console.log(key instanceof crypto.KeyObject)
    // true
    console.log(key.type === 'private')
    // true
    console.log(key.asymmetricKeyType === 'ed25519')
    // true
  }
  {
    const key = await V3.generateKey('local')
    console.log(key instanceof crypto.KeyObject)
    // true
    console.log(key.type === 'secret')
    // true
    console.log(key.symmetricKeySize === 32)
    // true
  }
  {
    const key = await V3.generateKey('public')
    console.log(key instanceof crypto.KeyObject)
    // true
    console.log(key.type === 'private')
    // true
    console.log(key.asymmetricKeyType === 'ec')
    // true
    console.log(key.asymmetricKeyDetails.namedCurve === 'secp384r1')
    // true
  }
  {
    const key = await V4.generateKey('public')
    console.log(key instanceof crypto.KeyObject)
    // true
    console.log(key.type === 'private')
    // true
    console.log(key.asymmetricKeyType === 'ed25519')
    // true
  }
})()
```

## FAQ

#### Supported Versions

| Version | Security Fixes 🔑 | Other Bug Fixes 🐞 | New Features ⭐ |
| ------- | --------- | -------- | -------- |
| [3.x.x](https://github.com/panva/paseto) | ✅ | ✅ | ✅ |
| [2.x.x](https://github.com/panva/paseto/tree/v2.x) | ✅ | ✅ until 2022-04-30 | ❌ |
| [1.x.x](https://github.com/panva/paseto/tree/v1.x) | ✅ | ❌ | ❌ |

#### Semver?

**Yes.** Everything that's either exported in the TypeScript definitions file or
[documented][documentation] is subject to
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). The rest is to be considered
private API and is subject to change between any versions.

#### How do I use it outside of Node.js

It is **only built for Node.js** environment versions >=16.0.0


[documentation]: https://github.com/panva/paseto/blob/main/docs/README.md
[documentation-v4]: https://github.com/panva/paseto/blob/main/docs/README.md#v4-paseto-protocol-version-v4
[documentation-v3]: https://github.com/panva/paseto/blob/main/docs/README.md#v3-paseto-protocol-version-v3
[documentation-v2]: https://github.com/panva/paseto/blob/main/docs/README.md#v2-paseto-protocol-version-v2
[documentation-v1]: https://github.com/panva/paseto/blob/main/docs/README.md#v1-paseto-protocol-version-v1
[support-sponsor]: https://github.com/sponsors/panva
