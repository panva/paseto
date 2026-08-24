# Variable: ImportSecretKeyFactory

> `const` **ImportSecretKeyFactory**: `CapabilityFactory`<`"public"`, `2`, `"ImportSecretKey"`, installed operation below>

Built-in PASERK k2.secret key-import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportSecretKey(paserk: SecretPASERK<2>, options?: KeyOptions): Promise<SecretKey>
```
