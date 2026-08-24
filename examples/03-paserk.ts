// Application code imports this from 'paseto'.
import { LocalProtocol } from '../index.ts'
// Application code imports these from 'paseto/v3/local'.
import {
  ExportKeyFactory,
  GenerateKeyFactory,
  ImportKeyFactory,
  KeyIDFactory,
} from '../v3/local.ts'

const v3 = new LocalProtocol(GenerateKeyFactory, ExportKeyFactory, ImportKeyFactory, KeyIDFactory)
const key = await v3.GenerateKey({ extractable: true })
const serialized = await v3.ExportKey(key)
const identifier = await v3.KeyID(serialized)
const imported = await v3.ImportKey(serialized, { extractable: true })

console.log(serialized)
console.log(identifier)
console.log(await v3.ExportKey(imported))
