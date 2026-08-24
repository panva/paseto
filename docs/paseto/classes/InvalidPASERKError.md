# Class: InvalidPASERKError

The PASERK is malformed or failed authentication.

## Contents

- [Constructor](#constructor)
- [Properties](#properties)
  - [code](#code)

## Extends

- [`PasetoError`](PasetoError.md)<`"ERR_PASERK_INVALID"`>

## Constructor

> **new InvalidPASERKError**(`message?`, `options?`): `InvalidPASERKError`

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `message` | `string` | Human-readable error message |
| `options?` | `ErrorOptions` | Error construction options |

#### Returns

`InvalidPASERKError`

#### Overrides

[`PasetoError`](PasetoError.md).[`constructor`](PasetoError.md#constructor)

## Properties

### code

> `readonly` **code**: `"ERR_PASERK_INVALID"`

Stable machine-readable error code.

#### Inherited from

[`PasetoError`](PasetoError.md).[`code`](PasetoError.md#code)
