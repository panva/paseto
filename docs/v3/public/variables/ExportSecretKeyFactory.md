# Variable: ExportSecretKeyFactory

> `const` **ExportSecretKeyFactory**: `CapabilityFactory`<`"public"`, `3`, `"ExportSecretKey"`, installed operation below>

Built-in PASERK k3.secret key-export capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ExportSecretKey(key: SecretKey): Promise<SecretPASERK<3>>
```
