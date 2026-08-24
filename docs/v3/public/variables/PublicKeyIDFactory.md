# Variable: PublicKeyIDFactory

> `const` **PublicKeyIDFactory**: `CapabilityFactory`<`"public"`, `3`, `"PublicKeyID"`, installed operation below>

Built-in PASERK k3.pid identifier capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
PublicKeyID(paserk: PublicPASERK<3>): Promise<PublicIdPASERK<3>>
```
