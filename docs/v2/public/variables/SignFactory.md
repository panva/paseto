# Variable: SignFactory

> `const` **SignFactory**: `CapabilityFactory`<`"public"`, `2`, `"Sign"`, installed operation below>

Built-in v2.public token-signing capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
Sign<C extends object>(key: SecretKey, claims: C, options?: ProduceOptions<2>): Promise<string>
```

`C` must be a JSON-compatible claims object. Registered PASETO claims use string values.
