# Class: InvalidTokenError

The token is malformed or failed authentication.

## Contents

- [Constructor](#constructor)
- [Properties](#properties)
  - [code](#code)

## Extends

- [`PasetoError`](PasetoError.md)<`"ERR_PASETO_INVALID_TOKEN"`>

## Constructor

> **new InvalidTokenError**(`message?`, `options?`): `InvalidTokenError`

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `message` | `string` | Human-readable error message |
| `options?` | `ErrorOptions` | Error construction options |

#### Returns

`InvalidTokenError`

#### Overrides

[`PasetoError`](PasetoError.md).[`constructor`](PasetoError.md#constructor)

## Properties

### code

> `readonly` **code**: `"ERR_PASETO_INVALID_TOKEN"`

Stable machine-readable error code.

#### Inherited from

[`PasetoError`](PasetoError.md).[`code`](PasetoError.md#code)
