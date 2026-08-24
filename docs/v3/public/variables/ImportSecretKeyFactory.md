# Variable: ImportSecretKeyFactory

> `const` **ImportSecretKeyFactory**: `CapabilityFactory`<`"public"`, `3`, `"ImportSecretKey"`, installed operation below>

Built-in PASERK k3.secret key-import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportSecretKey(paserk: SecretPASERK<3>, options?: KeyOptions): Promise<SecretKey>
```
