# Variable: ImportPublicKeyFactory

> `const` **ImportPublicKeyFactory**: `CapabilityFactory`<`"public"`, `2`, `"ImportPublicKey"`, installed operation below>

Built-in PASERK k2.public key-import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportPublicKey(paserk: PublicPASERK<2>): Promise<PublicKey>
```
