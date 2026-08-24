# Variable: UnwrapKeyWithPasswordFactory

> `const` **UnwrapKeyWithPasswordFactory**: `CapabilityFactory`<`"local"`, `1`, `"UnwrapKeyWithPassword"`, installed operation below>

Built-in PASERK k1.local-pw unwrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
UnwrapKeyWithPassword(paserk: PasswordWrappedLocalPASERK<1>, password: Uint8Array, options?: PasswordUnwrapOptions<1>): Promise<LocalKey>
```
