# Interface: Argon2id

Replaceable Argon2id implementation contract.

## Contents

- [Properties](#properties)
  - [name](#name)
  - [type](#type)
- [Methods](#methods)
  - [Derive()](#derive)

## Properties

### name

> `readonly` **name**: `"Argon2id"`

Argon2id implementation name.

***

### type

> `readonly` **type**: `"KDF"`

Type discriminator, always `KDF`.

## Methods

### Derive()

> **Derive**(`password`, `salt`, `parameters`): `Promise`<`Uint8Array`>

Derives key material from a password using Argon2id.

#### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `password` | `Uint8Array` | Password bytes |
| `salt` | `Uint8Array` | Salt bytes |
| `parameters` | `Readonly`<[`Argon2idParameters`](Argon2idParameters.md)> | Argon2id parameters |

#### Returns

`Promise`<`Uint8Array`>
