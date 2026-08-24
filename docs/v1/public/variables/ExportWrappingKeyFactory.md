# Variable: ExportWrappingKeyFactory

> `const` **ExportWrappingKeyFactory**: `CapabilityFactory`<`"public"`, `1`, `"ExportWrappingKey"`, installed operation below>

Built-in PASERK k1 wrapping-key export capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ExportWrappingKey(key: WrappingKey): Promise<Uint8Array>
```
