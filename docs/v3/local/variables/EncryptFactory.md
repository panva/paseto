# Variable: EncryptFactory

> `const` **EncryptFactory**: `CapabilityFactory`<`"local"`, `3`, `"Encrypt"`, installed operation below>

Built-in v3.local token-encryption capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
Encrypt<C extends object>(key: LocalKey, claims: C, options?: ProduceOptions<3>): Promise<string>
```

`C` must be a JSON-compatible claims object. Registered PASETO claims use string values.
