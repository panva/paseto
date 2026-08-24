# Variable: VerifyFactory

> `const` **VerifyFactory**: `CapabilityFactory`<`"public"`, `4`, `"Verify"`, installed operation below>

Built-in v4.public token-verification capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
Verify(key: PublicKey, token: string, options?: ConsumeOptions<4>): Promise<TokenResult>
```
