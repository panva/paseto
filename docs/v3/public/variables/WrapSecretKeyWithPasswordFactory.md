# Variable: WrapSecretKeyWithPasswordFactory

> `const` **WrapSecretKeyWithPasswordFactory**: `CapabilityFactory`<`"public"`, `3`, `"WrapSecretKeyWithPassword"`, installed operation below>

Built-in PASERK k3.secret-pw wrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
WrapSecretKeyWithPassword(key: SecretKey, password: Uint8Array, options?: PasswordWrapOptions<3>): Promise<PasswordWrappedSecretPASERK<3>>
```
