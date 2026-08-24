# Variable: UnwrapSecretKeyWithPasswordFactory

> `const` **UnwrapSecretKeyWithPasswordFactory**: `CapabilityFactory`<`"public"`, `3`, `"UnwrapSecretKeyWithPassword"`, installed operation below>

Built-in PASERK k3.secret-pw unwrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
UnwrapSecretKeyWithPassword(paserk: PasswordWrappedSecretPASERK<3>, password: Uint8Array, options?: PasswordUnwrapOptions<3>): Promise<SecretKey>
```
