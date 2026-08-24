# Variable: WrapKeyWithPasswordFactory

> `const` **WrapKeyWithPasswordFactory**: `CapabilityFactory`<`"local"`, `1`, `"WrapKeyWithPassword"`, installed operation below>

Built-in PASERK k1.local-pw wrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
WrapKeyWithPassword(key: LocalKey, password: Uint8Array, options?: PasswordWrapOptions<1>): Promise<PasswordWrappedLocalPASERK<1>>
```
