# Variable: WrapSecretKeyWithPasswordFactory

> `const` **WrapSecretKeyWithPasswordFactory**: `CapabilityFactory`<`"public"`, `1`, `"WrapSecretKeyWithPassword"`, installed operation below>

Built-in PASERK k1.secret-pw wrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
WrapSecretKeyWithPassword(key: SecretKey, password: Uint8Array, options?: PasswordWrapOptions<1>): Promise<PasswordWrappedSecretPASERK<1>>
```
