# Variable: ImportPublicKeyFactory

> `const` **ImportPublicKeyFactory**: `CapabilityFactory`<`"public"`, `4`, `"ImportPublicKey"`, installed operation below>

Built-in PASERK k4.public key-import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportPublicKey(paserk: PublicPASERK<4>): Promise<PublicKey>
```
