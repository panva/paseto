import * as Noble from '../examples/noble-suite/index.js'
import * as PASETO from '../index.js'
import * as V1Local from '../v1/local.js'
import * as V1Public from '../v1/public.js'
import * as V2Local from '../v2/local.js'
import * as V2Public from '../v2/public.js'
import * as V3Local from '../v3/local.js'
import * as V3Public from '../v3/public.js'
import * as V4Local from '../v4/local.js'
import * as V4Public from '../v4/public.js'
import vectorsV1 from './vectors/v1.json' with { type: 'json' }
import vectorsV2 from './vectors/v2.json' with { type: 'json' }
import vectorsV3 from './vectors/v3.json' with { type: 'json' }
import vectorsV4 from './vectors/v4.json' with { type: 'json' }
import { runRuntimeTests } from './run.js'

const Native = {
  V1_LOCAL: V1Local,
  V1_PUBLIC: V1Public,
  V2_LOCAL: V2Local,
  V2_PUBLIC: V2Public,
  V3_LOCAL: V3Local,
  V3_PUBLIC: V3Public,
  V4_LOCAL: V4Local,
  V4_PUBLIC: V4Public,
}

export default {
  async test() {
    const results = await runRuntimeTests({
      PASETO,
      Native,
      Noble,
      vectors: { 1: vectorsV1, 2: vectorsV2, 3: vectorsV3, 4: vectorsV4 },
    })

    console.log(`Runtime tests: ${results.passed}/${results.total} passed`)
    for (const test of results.tests) {
      if (test.status === 'failed') console.log(`FAIL ${test.name}\n${test.error}`)
    }
    if (results.failed !== 0) throw new Error(`${results.failed} runtime test(s) failed`)
  },
}
