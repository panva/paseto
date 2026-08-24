# Variable: ImportSecretKeyFactory

> `const` **ImportSecretKeyFactory**: `CapabilityFactory`<`"public"`, `1`, `"ImportSecretKey"`, installed operation below>

Built-in PASERK k1.secret key-import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportSecretKey(paserk: SecretPASERK<1>, options?: KeyOptions): Promise<SecretKey>
```
