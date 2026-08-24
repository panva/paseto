# Variable: GenerateWrappingKeyFactory

> `const` **GenerateWrappingKeyFactory**: `CapabilityFactory`<`"local"`, `2`, `"GenerateWrappingKey"`, installed operation below>

Built-in PASERK k2 wrapping-key generation capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
GenerateWrappingKey(options?: KeyOptions): Promise<WrappingKey>
```
