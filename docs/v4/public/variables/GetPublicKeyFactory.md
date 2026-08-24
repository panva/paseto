# Variable: GetPublicKeyFactory

> `const` **GetPublicKeyFactory**: `CapabilityFactory`<`"public"`, `4`, `"GetPublicKey"`, installed operation below>

Built-in PASERK k4 public-key derivation capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
GetPublicKey(key: SecretKey): Promise<PublicKey>
```
