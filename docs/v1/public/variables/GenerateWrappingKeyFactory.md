# Variable: GenerateWrappingKeyFactory

> `const` **GenerateWrappingKeyFactory**: `CapabilityFactory`<`"public"`, `1`, `"GenerateWrappingKey"`, installed operation below>

Built-in PASERK k1 wrapping-key generation capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
GenerateWrappingKey(options?: KeyOptions): Promise<WrappingKey>
```
