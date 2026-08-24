# Variable: UnwrapSecretKeyFactory

> `const` **UnwrapSecretKeyFactory**: `CapabilityFactory`<`"public"`, `1`, `"UnwrapSecretKey"`, installed operation below>

Built-in PASERK k1.secret-wrap.pie unwrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
UnwrapSecretKey(paserk: WrappedSecretPASERK<1, 'pie'>, wrappingKey: WrappingKey, options?: KeyOptions): Promise<SecretKey>
```
