# paseto

> [PASETO](https://paseto.io): <strong>P</strong>latform-<strong>A</strong>gnostic <strong>SE</strong>curity <strong>TO</strong>kens for Node.js with no dependencies.

## Implemented Protocol Versions

|  | v1 | v2 | v3 | v4 | 
| -- | -- | -- | -- | -- |
| local | ✅ | ❌ | ✅ | ❌ |
| public | ✅ | ✅ | ✅ | ✅ |

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
const { V4: { sign } } = paseto

(async () => {
  {
    const token = await sign({ sub: 'johndoe' }, privateKey)
    // v4.public.eyJzdWIiOiJqb2huZG9lIiwiaWF0IjoiMjAyMS0wOC0wM1QwNTozOTozNy42NzNaIn3AW3ri7P5HpdakJmZvhqssz7Wtzi2Rb3JafwKplLoCWuMkITYOo5KNNR5NMaeAR6ePZ3xWUcbO0R11YLb02awO
  }
})()
```

#### Consuming tokens

```js
const { V4: { verify } } = paseto

(async () => {
  {
    const payload = await verify(token, publicKey)
    // { sub: 'johndoe', iat: '2019-07-01T15:22:47.982Z' }
  }
})()
```

## FAQ

#### Supported Library Versions

| Version | Security Fixes 🔑 | Other Bug Fixes 🐞 | New Features ⭐ | Node.js version supported | 
| ------- | --------- | -------- | -------- | -------- |
| [3.x.x](https://github.com/panva/paseto) | ✅ | ✅ | ✅ | >= 16.0.0 |
| [2.x.x](https://github.com/panva/paseto/tree/v2.x) | ✅ | ❌ | ❌ | ^12.19.0 &vert;&vert; >=14.15.0 |
| [1.x.x](https://github.com/panva/paseto/tree/v1.x) | ✅ | ❌ | ❌ | >= 12.0.0 |

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
