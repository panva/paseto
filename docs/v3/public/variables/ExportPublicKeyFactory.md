# Variable: ExportPublicKeyFactory

> `const` **ExportPublicKeyFactory**: `CapabilityFactory`<`"public"`, `3`, `"ExportPublicKey"`, installed operation below>

Built-in PASERK k3.public key-export capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ExportPublicKey(key: PublicKey): Promise<PublicPASERK<3>>
```
