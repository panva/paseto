# Class: ClaimValidationError

An authenticated token contains claims that fail validation.

## Contents

- [Constructor](#constructor)
- [Properties](#properties)
  - [code](#code)
  - [claim?](#claim)

## Extends

- [`PasetoError`](PasetoError.md)<`"ERR_PASETO_CLAIM_VALIDATION"`>

## Constructor

> **new ClaimValidationError**(`message`, `claim?`, `options?`): `ClaimValidationError`

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `message` | `string` | Human-readable error message |
| `claim?` | `string` | Claim whose validation failed |
| `options?` | `ErrorOptions` | Error construction options |

#### Returns

`ClaimValidationError`

#### Overrides

[`PasetoError`](PasetoError.md).[`constructor`](PasetoError.md#constructor)

## Properties

### code

> `readonly` **code**: `"ERR_PASETO_CLAIM_VALIDATION"`

Stable machine-readable error code.

#### Inherited from

[`PasetoError`](PasetoError.md).[`code`](PasetoError.md#code)

***

### claim?

> `readonly` `optional` **claim?**: `string`

Claim whose validation failed, when applicable.
