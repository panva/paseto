# Variable: ExportSealingPublicKeyFactory

> `const` **ExportSealingPublicKeyFactory**: `CapabilityFactory`<`"local"`, `3`, `"ExportSealingPublicKey"`, installed operation below>

Built-in PASERK k3.seal public-key export capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ExportSealingPublicKey(key: SealingPublicKey): Promise<Uint8Array>
```
