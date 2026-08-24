# Class: UnsupportedAlgorithmError

The current runtime does not provide a required cryptographic primitive.

## Contents

- [Constructor](#constructor)
- [Properties](#properties)
  - [code](#code)

## Extends

- [`PasetoError`](PasetoError.md)<`"ERR_PASETO_UNSUPPORTED_ALGORITHM"`>

## Constructor

> **new UnsupportedAlgorithmError**(`message`, `options?`): `UnsupportedAlgorithmError`

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `message` | `string` | Human-readable error message |
| `options?` | `ErrorOptions` | Error construction options |

#### Returns

`UnsupportedAlgorithmError`

#### Overrides

[`PasetoError`](PasetoError.md).[`constructor`](PasetoError.md#constructor)

## Properties

### code

> `readonly` **code**: `"ERR_PASETO_UNSUPPORTED_ALGORITHM"`

Stable machine-readable error code.

#### Inherited from

[`PasetoError`](PasetoError.md).[`code`](PasetoError.md#code)
