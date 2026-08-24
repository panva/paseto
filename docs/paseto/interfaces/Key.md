# Interface: Key

Minimal key representation understood by protocol implementations.

It deliberately mirrors the structural-key convention used by `hpke`: implementations may return
Web Cryptography keys, HSM handles, native-addon keys, or their own opaque objects.

## Contents

- [Extended by](#extended-by)
- [Properties](#properties)
  - [algorithm](#algorithm)
  - [extractable](#extractable)
  - [type](#type)

## Extended by

- [`LocalKey`](../../v1/local/interfaces/LocalKey.md)
- [`WrappingKey`](../../v1/local/interfaces/WrappingKey.md)
- [`PublicKey`](../../v1/public/interfaces/PublicKey.md)
- [`SecretKey`](../../v1/public/interfaces/SecretKey.md)
- [`WrappingKey`](../../v1/public/interfaces/WrappingKey.md)
- [`LocalKey`](../../v2/local/interfaces/LocalKey.md)
- [`WrappingKey`](../../v2/local/interfaces/WrappingKey.md)
- [`PublicKey`](../../v2/public/interfaces/PublicKey.md)
- [`SecretKey`](../../v2/public/interfaces/SecretKey.md)
- [`WrappingKey`](../../v2/public/interfaces/WrappingKey.md)
- [`LocalKey`](../../v3/local/interfaces/LocalKey.md)
- [`WrappingKey`](../../v3/local/interfaces/WrappingKey.md)
- [`SealingPublicKey`](../../v3/local/interfaces/SealingPublicKey.md)
- [`SealingSecretKey`](../../v3/local/interfaces/SealingSecretKey.md)
- [`PublicKey`](../../v3/public/interfaces/PublicKey.md)
- [`SecretKey`](../../v3/public/interfaces/SecretKey.md)
- [`WrappingKey`](../../v3/public/interfaces/WrappingKey.md)
- [`LocalKey`](../../v4/local/interfaces/LocalKey.md)
- [`WrappingKey`](../../v4/local/interfaces/WrappingKey.md)
- [`PublicKey`](../../v4/public/interfaces/PublicKey.md)
- [`SecretKey`](../../v4/public/interfaces/SecretKey.md)
- [`WrappingKey`](../../v4/public/interfaces/WrappingKey.md)

## Properties

### algorithm

> `readonly` **algorithm**: `object`

Algorithm metadata used by an implementation to identify its keys.

#### name

> `readonly` **name**: `string`

Algorithm identifier for the key.

***

### extractable

> `readonly` **extractable**: `boolean`

Whether key material may be exported.

***

### type

> `readonly` **type**: `"public"` ∣ `"secret"`

Implementation-defined key role.
