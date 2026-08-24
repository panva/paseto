# Variable: SecretKeyIDFactory

> `const` **SecretKeyIDFactory**: `CapabilityFactory`<`"public"`, `3`, `"SecretKeyID"`, installed operation below>

Built-in PASERK k3.sid identifier capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
SecretKeyID(paserk: SecretKeyIDInput<3>): Promise<SecretIdPASERK<3>>
```
