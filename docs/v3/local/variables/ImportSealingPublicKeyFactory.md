# Variable: ImportSealingPublicKeyFactory

> `const` **ImportSealingPublicKeyFactory**: `CapabilityFactory`<`"local"`, `3`, `"ImportSealingPublicKey"`, installed operation below>

Built-in PASERK k3.seal public-key import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportSealingPublicKey(material: Uint8Array): Promise<SealingPublicKey>
```
