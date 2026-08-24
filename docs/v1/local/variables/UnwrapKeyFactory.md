# Variable: UnwrapKeyFactory

> `const` **UnwrapKeyFactory**: `CapabilityFactory`<`"local"`, `1`, `"UnwrapKey"`, installed operation below>

Built-in PASERK k1.local-wrap.pie unwrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
UnwrapKey(paserk: WrappedLocalPASERK<1, 'pie'>, wrappingKey: WrappingKey, options?: KeyOptions): Promise<LocalKey>
```
