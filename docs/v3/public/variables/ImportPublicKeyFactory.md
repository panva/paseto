# Variable: ImportPublicKeyFactory

> `const` **ImportPublicKeyFactory**: `CapabilityFactory`<`"public"`, `3`, `"ImportPublicKey"`, installed operation below>

Built-in PASERK k3.public key-import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportPublicKey(paserk: PublicPASERK<3>): Promise<PublicKey>
```
