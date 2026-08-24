# Variable: VerifyFactory

> `const` **VerifyFactory**: `CapabilityFactory`<`"public"`, `2`, `"Verify"`, installed operation below>

Built-in v2.public token-verification capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
Verify(key: PublicKey, token: string, options?: ConsumeOptions<2>): Promise<TokenResult>
```
