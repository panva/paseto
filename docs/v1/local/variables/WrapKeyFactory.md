# Variable: WrapKeyFactory

> `const` **WrapKeyFactory**: `CapabilityFactory`<`"local"`, `1`, `"WrapKey"`, installed operation below>

Built-in PASERK k1.local-wrap.pie wrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
WrapKey(key: LocalKey, wrappingKey: WrappingKey): Promise<WrappedLocalPASERK<1, 'pie'>>
```
