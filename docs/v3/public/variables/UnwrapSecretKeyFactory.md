# Variable: UnwrapSecretKeyFactory

> `const` **UnwrapSecretKeyFactory**: `CapabilityFactory`<`"public"`, `3`, `"UnwrapSecretKey"`, installed operation below>

Built-in PASERK k3.secret-wrap.pie unwrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
UnwrapSecretKey(paserk: WrappedSecretPASERK<3, 'pie'>, wrappingKey: WrappingKey, options?: KeyOptions): Promise<SecretKey>
```
