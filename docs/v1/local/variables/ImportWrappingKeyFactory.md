# Variable: ImportWrappingKeyFactory

> `const` **ImportWrappingKeyFactory**: `CapabilityFactory`<`"local"`, `1`, `"ImportWrappingKey"`, installed operation below>

Built-in PASERK k1 wrapping-key import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportWrappingKey(material: Uint8Array, options?: KeyOptions): Promise<WrappingKey>
```
