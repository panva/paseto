# Variable: UnwrapKeyWithPasswordFactory

> `const` **UnwrapKeyWithPasswordFactory**: `CapabilityFactory`<`"local"`, `3`, `"UnwrapKeyWithPassword"`, installed operation below>

Built-in PASERK k3.local-pw unwrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
UnwrapKeyWithPassword(paserk: PasswordWrappedLocalPASERK<3>, password: Uint8Array, options?: PasswordUnwrapOptions<3>): Promise<LocalKey>
```
