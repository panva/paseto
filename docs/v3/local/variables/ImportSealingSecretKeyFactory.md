# Variable: ImportSealingSecretKeyFactory

> `const` **ImportSealingSecretKeyFactory**: `CapabilityFactory`<`"local"`, `3`, `"ImportSealingSecretKey"`, installed operation below>

Built-in PASERK k3.seal secret-key import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportSealingSecretKey(material: Uint8Array, options?: KeyOptions): Promise<SealingSecretKey>
```
