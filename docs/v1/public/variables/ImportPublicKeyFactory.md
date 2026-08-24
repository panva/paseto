# Variable: ImportPublicKeyFactory

> `const` **ImportPublicKeyFactory**: `CapabilityFactory`<`"public"`, `1`, `"ImportPublicKey"`, installed operation below>

Built-in PASERK k1.public key-import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportPublicKey(paserk: PublicPASERK<1>): Promise<PublicKey>
```
