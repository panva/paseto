# Class: PasetoError\<C>

Base class for errors produced by this module.

## Contents

- [Extended by](#extended-by)
- [Type Parameters](#type-parameters)
- [Constructor](#constructor)
- [Properties](#properties)
  - [code](#code)

## Extends

- `Error`

## Extended by

- [`InvalidTokenError`](InvalidTokenError.md)
- [`InvalidPASERKError`](InvalidPASERKError.md)
- [`InvalidKeyError`](InvalidKeyError.md)
- [`ClaimValidationError`](ClaimValidationError.md)
- [`UnsupportedAlgorithmError`](UnsupportedAlgorithmError.md)

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `C` *extends* [`PasetoErrorCode`](../type-aliases/PasetoErrorCode.md) | Stable machine-readable error code |

## Constructor

> **new PasetoError**<`C`>(`code`, `message`, `options?`): `PasetoError`<`C`>

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `code` | `C` | Stable machine-readable error code |
| `message` | `string` | Human-readable error message |
| `options?` | `ErrorOptions` | Error construction options |

#### Returns

`PasetoError`<`C`>

#### Overrides

`Error.constructor`

## Properties

### code

> `readonly` **code**: `C`

Stable machine-readable error code.
