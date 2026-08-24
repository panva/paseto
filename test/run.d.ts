export interface RuntimeTest {
  name: string
  status: 'running' | 'passed' | 'failed'
  error: string | null
}

export interface RuntimeTestResults {
  total: number
  passed: number
  failed: number
  tests: RuntimeTest[]
}

export interface RuntimeTestMode {
  onlyNative?: boolean
  onlyReference?: boolean
}

export function runRuntimeTests(options: {
  PASETO: typeof import('../index.ts')
  Native: {
    V1_LOCAL: typeof import('../v1/local.ts')
    V1_PUBLIC: typeof import('../v1/public.ts')
    V2_LOCAL: typeof import('../v2/local.ts')
    V2_PUBLIC: typeof import('../v2/public.ts')
    V3_LOCAL: typeof import('../v3/local.ts')
    V3_PUBLIC: typeof import('../v3/public.ts')
    V4_LOCAL: typeof import('../v4/local.ts')
    V4_PUBLIC: typeof import('../v4/public.ts')
  }
  Noble: typeof import('../examples/noble-suite/index.ts')
  vectors: Record<number, { tests: unknown[] }>
  mode?: RuntimeTestMode
  onTestComplete?: (test: RuntimeTest, tests: RuntimeTest[]) => void
}): Promise<RuntimeTestResults>
