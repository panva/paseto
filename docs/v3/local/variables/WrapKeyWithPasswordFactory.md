# Variable: WrapKeyWithPasswordFactory

> `const` **WrapKeyWithPasswordFactory**: `CapabilityFactory`<`"local"`, `3`, `"WrapKeyWithPassword"`, installed operation below>

Built-in PASERK k3.local-pw wrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
WrapKeyWithPassword(key: LocalKey, password: Uint8Array, options?: PasswordWrapOptions<3>): Promise<PasswordWrappedLocalPASERK<3>>
```
