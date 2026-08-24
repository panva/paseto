# Interface: TokenResult\<T>

A successfully authenticated PASETO.

`T` is for application wrappers that independently narrow `claims`. Capabilities created by
[LocalDecrypt](../functions/LocalDecrypt.md) and [PublicVerify](../functions/PublicVerify.md) return `TokenResult<Claims>`.

## Contents

- [Type Parameters](#type-parameters)
- [Properties](#properties)
  - [claims](#claims)
  - [footer](#footer)

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `T` *extends* `object` | Claims type supplied by an external narrowing wrapper |

## Properties

### claims

> **claims**: `T`

Authenticated claims.

***

### footer

> **footer**: `Uint8Array`

Authenticated token footer.
