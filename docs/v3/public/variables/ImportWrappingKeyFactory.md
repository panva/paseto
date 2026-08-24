# Variable: ImportWrappingKeyFactory

> `const` **ImportWrappingKeyFactory**: `CapabilityFactory`<`"public"`, `3`, `"ImportWrappingKey"`, installed operation below>

Built-in PASERK k3 wrapping-key import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportWrappingKey(material: Uint8Array, options?: KeyOptions): Promise<WrappingKey>
```
