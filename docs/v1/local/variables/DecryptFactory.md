# Variable: DecryptFactory

> `const` **DecryptFactory**: `CapabilityFactory`<`"local"`, `1`, `"Decrypt"`, installed operation below>

Built-in v1.local token-decryption capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
Decrypt(key: LocalKey, token: string, options?: ConsumeOptions<1>): Promise<TokenResult>
```
