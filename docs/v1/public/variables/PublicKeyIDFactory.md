# Variable: PublicKeyIDFactory

> `const` **PublicKeyIDFactory**: `CapabilityFactory`<`"public"`, `1`, `"PublicKeyID"`, installed operation below>

Built-in PASERK k1.pid identifier capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
PublicKeyID(paserk: PublicPASERK<1>): Promise<PublicIdPASERK<1>>
```
