# Variable: UnwrapKeyFactory

> `const` **UnwrapKeyFactory**: `CapabilityFactory`<`"local"`, `3`, `"UnwrapKey"`, installed operation below>

Built-in PASERK k3.local-wrap.pie unwrapping capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
UnwrapKey(paserk: WrappedLocalPASERK<3, 'pie'>, wrappingKey: WrappingKey, options?: KeyOptions): Promise<LocalKey>
```
