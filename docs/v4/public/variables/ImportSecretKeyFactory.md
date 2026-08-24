# Variable: ImportSecretKeyFactory

> `const` **ImportSecretKeyFactory**: `CapabilityFactory`<`"public"`, `4`, `"ImportSecretKey"`, installed operation below>

Built-in PASERK k4.secret key-import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportSecretKey(paserk: SecretPASERK<4>, options?: KeyOptions): Promise<SecretKey>
```
