# Interface: KeyPair\<P, S>

A public and secret key pair returned by a key-pair generation capability.

## Contents

- [Type Parameters](#type-parameters)
- [Properties](#properties)
  - [publicKey](#publickey)
  - [secretKey](#secretkey)

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `P` *extends* [`Key`](Key.md) | Public key representation contained in the pair |
| `S` *extends* [`Key`](Key.md) | Secret key representation contained in the pair |

## Properties

### publicKey

> `readonly` **publicKey**: `P`

Public key.

***

### secretKey

> `readonly` **secretKey**: `S`

Secret key.
