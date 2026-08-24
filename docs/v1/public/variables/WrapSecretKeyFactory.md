# Variable: WrapSecretKeyFactory

> `const` **WrapSecretKeyFactory**: `CapabilityFactory`<`"public"`, `1`, `"WrapSecretKey"`, installed operation below>

Built-in PASERK k1.secret-wrap.pie wrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
WrapSecretKey(key: SecretKey, wrappingKey: WrappingKey): Promise<WrappedSecretPASERK<1, 'pie'>>
```
