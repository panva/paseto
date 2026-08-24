# Type Alias: Claims

> **Claims** = `object` & `object`

A decoded PASETO claims object.

Registered claims are strings. `exp`, `iat`, and `nbf` use RFC 3339 date-time strings rather than
numeric dates. Additional string-keyed claims may contain any [JsonValue](JsonValue.md).

## Type Declaration

### aud?

> `optional` **aud?**: `string`

Intended audience.

### exp?

> `optional` **exp?**: `string`

Expiration time as an RFC 3339 date-time string.

### iat?

> `optional` **iat?**: `string`

Issued-at time as an RFC 3339 date-time string.

### iss?

> `optional` **iss?**: `string`

Issuer.

### jti?

> `optional` **jti?**: `string`

Token identifier.

### nbf?

> `optional` **nbf?**: `string`

Not-before time as an RFC 3339 date-time string.

### sub?

> `optional` **sub?**: `string`

Subject.
