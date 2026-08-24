# Variable: ExportSealingSecretKeyFactory

> `const` **ExportSealingSecretKeyFactory**: `CapabilityFactory`<`"local"`, `3`, `"ExportSealingSecretKey"`, installed operation below>

Built-in PASERK k3.seal secret-key export capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ExportSealingSecretKey(key: SealingSecretKey): Promise<Uint8Array>
```
