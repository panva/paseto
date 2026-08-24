# Type Alias: ConsumeOptions\<V>

> **ConsumeOptions**<`V`> = `object` & \[`V`] *extends* \[`3` ∣ `4`] ? `object` : `object`

Options used when consuming a token. All versions support `footer`, `now`, `clockTolerance`,
`allowNonExpiring`, `maxTokenAge`, `audience`, `issuer`, `subject`, `tokenIdentifier`, and
`requiredClaims`; only v3 and v4 support `implicitAssertion`.

## Type Declaration

### allowNonExpiring?

> `optional` **allowNonExpiring?**: `boolean`

Accept a claims object without an `exp` claim. Defaults to false.

### audience?

> `optional` **audience?**: `string` ∣ readonly `string`\[]

Expected `aud` claim. Any listed value may match.

### clockTolerance?

> `optional` **clockTolerance?**: `number`

Permitted temporal skew in seconds. Defaults to zero.

### footer?

> `optional` **footer?**: `Uint8Array`

Require the token to contain this exact footer.

### issuer?

> `optional` **issuer?**: `string` ∣ readonly `string`\[]

Expected `iss` claim. Any listed value may match.

### maxTokenAge?

> `optional` **maxTokenAge?**: `number`

Maximum token age in seconds, measured from `iat`.

### now?

> `optional` **now?**: `Date`

Current time used for temporal claim validation.

### requiredClaims?

> `optional` **requiredClaims?**: readonly `string`\[]

Additional claims that must be present.

### subject?

> `optional` **subject?**: `string`

Expected `sub` claim.

### tokenIdentifier?

> `optional` **tokenIdentifier?**: `string`

Expected `jti` claim.

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

In v3 and v4, `implicitAssertion` is a `Uint8Array` that authenticates data not stored in the
token. V1 and v2 do not accept it.
