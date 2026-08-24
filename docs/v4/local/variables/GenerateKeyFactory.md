# Variable: GenerateKeyFactory

> `const` **GenerateKeyFactory**: `CapabilityFactory`<`"local"`, `4`, `"GenerateKey"`, installed operation below>

Built-in v4.local symmetric-key generation capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
GenerateKey(options?: KeyOptions): Promise<LocalKey>
```
