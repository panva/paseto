# Variable: WrapKeyFactory

> `const` **WrapKeyFactory**: `CapabilityFactory`<`"local"`, `3`, `"WrapKey"`, installed operation below>

Built-in PASERK k3.local-wrap.pie wrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
WrapKey(key: LocalKey, wrappingKey: WrappingKey): Promise<WrappedLocalPASERK<3, 'pie'>>
```
