# Variable: ImportWrappingKeyFactory

> `const` **ImportWrappingKeyFactory**: `CapabilityFactory`<`"public"`, `4`, `"ImportWrappingKey"`, installed operation below>

Built-in PASERK k4 wrapping-key import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportWrappingKey(material: Uint8Array, options?: KeyOptions): Promise<WrappingKey>
```
