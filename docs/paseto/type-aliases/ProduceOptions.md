# Type Alias: ProduceOptions\<V>

> **ProduceOptions**<`V`> = `object` & \[`V`] *extends* \[`3` ∣ `4`] ? `object` : `object`

Options used when creating a token. All versions support `footer`, `now`, `addIssuedAt`,
`expiresIn`, and `nonExpiring`; only v3 and v4 support `implicitAssertion`.

`expiresIn` and `nonExpiring: true` are mutually exclusive.

## Type Declaration

### addIssuedAt?

> `optional` **addIssuedAt?**: `boolean`

Add an `iat` claim when one is not already present. Defaults to true.

### expiresIn?

> `optional` **expiresIn?**: `number`

Lifetime in seconds. Overrides an `exp` claim. Defaults to 3600 when `exp` is absent.

### footer?

> `optional` **footer?**: `Uint8Array`

Authenticated, unencrypted token footer.

### nonExpiring?

> `optional` **nonExpiring?**: `boolean`

Remove any `exp` claim when true; preserve normal expiration handling when false.

### now?

> `optional` **now?**: `Date`

Current time used for generated temporal claims.

## Version-specific Properties

### Versions 3 and 4

#### implicitAssertion?

> `optional` **implicitAssertion?**: `Uint8Array`

Authenticated data that is not stored in the token.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | PASETO version selecting whether implicit assertions are available |

## Remarks

`expiresIn` is a lifetime in seconds, overrides an existing `exp` claim, and defaults to 3,600
when `exp` is absent. `nonExpiring: true` removes `exp` instead. In v3 and v4,
`implicitAssertion` is a `Uint8Array` that authenticates data not stored in the token.
