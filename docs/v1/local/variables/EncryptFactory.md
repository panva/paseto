# Variable: EncryptFactory

> `const` **EncryptFactory**: `CapabilityFactory`<`"local"`, `1`, `"Encrypt"`, installed operation below>

Built-in v1.local token-encryption capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
Encrypt<C extends object>(key: LocalKey, claims: C, options?: ProduceOptions<1>): Promise<string>
```

`C` must be a JSON-compatible claims object. Registered PASETO claims use string values.
