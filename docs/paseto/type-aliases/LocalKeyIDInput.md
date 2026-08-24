# Type Alias: LocalKeyIDInput\<V>

> **LocalKeyIDInput**<`V`> = [`LocalPASERK`](LocalPASERK.md)<`V`> ∣ [`WrappedLocalPASERK`](WrappedLocalPASERK.md)<`V`> ∣ [`PasswordWrappedLocalPASERK`](PasswordWrappedLocalPASERK.md)<`V`> ∣ [`SealedLocalPASERK`](SealedLocalPASERK.md)<`V`>

A PASERK serialization accepted when deriving a local key identifier.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | PASERK protocol version encoded by the serialization |
