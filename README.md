# paseto

![build][actions-image] [![codecov][codecov-image]][codecov-url]

> [PASETO](https://paseto.io): <strong>P</strong>latform-<strong>A</strong>gnostic <strong>SE</strong>curity <strong>TO</strong>kens for Node.js with minimal dependencies

## Implemented specs & features

All crypto operations are using their async node's crypto API, where such API is not available the
operation is pushed to a [Worker Thread](https://nodejs.org/api/worker_threads.html) so that your
main thread's I/O is not blocked.

<br>

|  | v1.local | v1.public | v2.local | v2.public |
| -- | -- | -- | -- | -- |
| supported? | ✓ | ✓ | ✓ | ✓ |

<br>

Have a question about using paseto? - [ask][ask].  
Found a bug? - [report it][bug].  
Missing a feature? - If it wasn't already discussed before, [ask for it][suggest-feature].  
Found a vulnerability? - Reach out to us via email first, see [security vulnerability disclosure][security-vulnerability].  

## Support

If you or your business use paseto, please consider becoming a [sponsor][support-sponsor] so I can continue maintaining it and adding new features carefree.

## Documentation

- [API Documentation][documentation]
  - [PASETO Protocol Version v2][documentation-v2]
  - [PASETO Protocol Version v1][documentation-v1]

## Usage

For its improvements in the crypto module ⚠️ the minimal Node.js version required is **v12.0.0** ⚠️

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
const { V2 } = paseto // { sign, verify, encrypt, decrypt, generateKey }

// errors utilized by paseto
const { errors } = paseto
```

#### Producing tokens

```js
const { V2: { encrypt, sign } } = paseto

(async () => {
  {
    const token = await encrypt({ sub: 'johndoe' }, secretKey)
    // v2.local.rRfHP25HDj5Pda40FwdTsGcsEMoQAKM6ElH6OhCon6YzG1Pzmj1ZPAHORhPaxKQo0XLM5LPYgaevWGrkEy2Os3N68Xee_Me9A0LmbMlV6MNVt-UZMos7ETha
  }
  {
    const token = await sign({ sub: 'johndoe' }, privateKey)
    // v2.public.eyJzdWIiOiJqb2huZG9lIiwiaWF0IjoiMjAxOS0wNy0wMVQxNToyMTozMS40OTJaIn0tpEwuwb-loL652KAZhmCYdDUNW8YbF6UYCFCYLk-fexhzs2ofL4AyHTqIk0HzIxawufEibT1ZyJ7MPBJUVpsF
  }
})()
```

#### Consuming tokens

```js
const { V2: { decrypt, verify } } = paseto

(async () => {
  {
    const payload = await decrypt(token, secretKey)
    // { sub: 'johndoe', iat: '2019-07-01T15:22:47.982Z' }
  }
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
const { V1, V2 } = paseto

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
    const key = await V2.generateKey('local')
    console.log(key instanceof crypto.KeyObject)
    // true
    console.log(key.type === 'secret')
    // true
    console.log(key.symmetricKeySize === 32)
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
})()
```

## FAQ

#### Semver?

**Yes.** Everything that's either exported in the TypeScript definitions file or
[documented][documentation] is subject to
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). The rest is to be considered
private API and is subject to change between any versions.

#### How do I use it outside of Node.js

It is **only built for Node.js** environment - it builds on top of the `crypto` module and requires
the KeyObject API that was added in Node.js v11.6.0 and one-shot sign/verify API added in v12.0.0

#### What is the ultimate goal?

- **No dependencies**, the moment `XChaCha20-Poly1305` is supported by OpenSSL and therefore node's
`crypto` the direct dependency count will go down from 1 to 0. 🚀


[ask]: https://github.com/panva/paseto/issues/new?labels=question&template=question.md&title=question%3A+
[bug]: https://github.com/panva/paseto/issues/new?labels=bug&template=bug-report.md&title=bug%3A+
[codecov-image]: https://img.shields.io/codecov/c/github/panva/paseto/master.svg
[codecov-url]: https://codecov.io/gh/panva/paseto
[documentation]: https://github.com/panva/paseto/blob/master/docs/README.md
[documentation-v2]: https://github.com/panva/paseto/blob/master/docs/README.md#v2-paseto-protocol-version-v2
[documentation-v1]: https://github.com/panva/paseto/blob/master/docs/README.md#v1-paseto-protocol-version-v1
[security-vulnerability]: https://github.com/panva/paseto/issues/new?template=security-vulnerability.md
[suggest-feature]: https://github.com/panva/paseto/issues/new?labels=enhancement&template=feature-request.md&title=proposal%3A+
[support-sponsor]: https://github.com/sponsors/panva
[actions-image]: https://github.com/panva/paseto/workflows/Continuous%20Integration/badge.svg
