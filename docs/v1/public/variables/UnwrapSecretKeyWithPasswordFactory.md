# Variable: UnwrapSecretKeyWithPasswordFactory

> `const` **UnwrapSecretKeyWithPasswordFactory**: `CapabilityFactory`<`"public"`, `1`, `"UnwrapSecretKeyWithPassword"`, installed operation below>

Built-in PASERK k1.secret-pw unwrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
UnwrapSecretKeyWithPassword(paserk: PasswordWrappedSecretPASERK<1>, password: Uint8Array, options?: PasswordUnwrapOptions<1>): Promise<SecretKey>
```
