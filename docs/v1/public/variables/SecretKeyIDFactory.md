# Variable: SecretKeyIDFactory

> `const` **SecretKeyIDFactory**: `CapabilityFactory`<`"public"`, `1`, `"SecretKeyID"`, installed operation below>

Built-in PASERK k1.sid identifier capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
SecretKeyID(paserk: SecretKeyIDInput<1>): Promise<SecretIdPASERK<1>>
```
