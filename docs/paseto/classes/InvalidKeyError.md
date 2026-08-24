# Class: InvalidKeyError

The key is malformed, unavailable for an operation, or belongs to another protocol tuple.

## Contents

- [Constructor](#constructor)
- [Properties](#properties)
  - [code](#code)

## Extends

- [`PasetoError`](PasetoError.md)<`"ERR_PASETO_INVALID_KEY"`>

## Constructor

> **new InvalidKeyError**(`message?`, `options?`): `InvalidKeyError`

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `message` | `string` | Human-readable error message |
| `options?` | `ErrorOptions` | Error construction options |

#### Returns

`InvalidKeyError`

#### Overrides

[`PasetoError`](PasetoError.md).[`constructor`](PasetoError.md#constructor)

## Properties

### code

> `readonly` **code**: `"ERR_PASETO_INVALID_KEY"`

Stable machine-readable error code.

#### Inherited from

[`PasetoError`](PasetoError.md).[`code`](PasetoError.md#code)
