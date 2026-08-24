# Variable: ImportWrappingKeyFactory

> `const` **ImportWrappingKeyFactory**: `CapabilityFactory`<`"local"`, `2`, `"ImportWrappingKey"`, installed operation below>

Built-in PASERK k2 wrapping-key import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportWrappingKey(material: Uint8Array, options?: KeyOptions): Promise<WrappingKey>
```
