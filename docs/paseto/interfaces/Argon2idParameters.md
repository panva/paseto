# Interface: Argon2idParameters

Parameters for an Argon2id implementation. Memory is expressed in bytes.

## Contents

- [Properties](#properties)
  - [length](#length)
  - [memory](#memory)
  - [parallelism](#parallelism)
  - [passes](#passes)

## Properties

### length

> `readonly` **length**: `number`

Derived-key length in bytes.

***

### memory

> `readonly` **memory**: `number`

Memory cost in bytes.

***

### parallelism

> `readonly` **parallelism**: `number`

Degree of parallelism.

***

### passes

> `readonly` **passes**: `number`

Number of passes over memory.
