# Variable: SignFactory

> `const` **SignFactory**: `CapabilityFactory`<`"public"`, `4`, `"Sign"`, installed operation below>

Built-in v4.public token-signing capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
Sign<C extends object>(key: SecretKey, claims: C, options?: ProduceOptions<4>): Promise<string>
```

`C` must be a JSON-compatible claims object. Registered PASETO claims use string values.
