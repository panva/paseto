# Interface: LocalKey

Key used by the built-in v3.local implementations.

## Contents

- [Properties](#properties)
  - [algorithm](#algorithm)
  - [extractable](#extractable)
  - [kind](#kind)
  - [type](#type)
  - [version](#version)

## Extends

- [`Key`](../../../paseto/interfaces/Key.md)

## Properties

### algorithm

> `readonly` **algorithm**: `object`

Algorithm metadata used by an implementation to identify its keys.

#### name

> `readonly` **name**: `"PASETO v3.local"`

#### Overrides

[`Key`](../../../paseto/interfaces/Key.md).[`algorithm`](../../../paseto/interfaces/Key.md#algorithm)

***

### extractable

> `readonly` **extractable**: `boolean`

Whether key material may be exported.

#### Inherited from

[`Key`](../../../paseto/interfaces/Key.md).[`extractable`](../../../paseto/interfaces/Key.md#extractable)

***

### kind

> `readonly` **kind**: `"local"`

***

### type

> `readonly` **type**: `"secret"`

Implementation-defined key role.

#### Overrides

[`Key`](../../../paseto/interfaces/Key.md).[`type`](../../../paseto/interfaces/Key.md#type)

***

### version

> `readonly` **version**: `3`
