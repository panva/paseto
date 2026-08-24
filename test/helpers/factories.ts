type UnionToIntersection<U> = (U extends unknown ? (value: U) => void : never) extends (
  value: infer I,
) => void
  ? I
  : never

type LastOf<U> =
  UnionToIntersection<U extends unknown ? () => U : never> extends () => infer L ? L : never

type UnionToTuple<U, L = LastOf<U>> = [U] extends [never] ? [] : [...UnionToTuple<Exclude<U, L>>, L]

type FactoryValue<M extends object> = M[keyof M] extends infer V
  ? V extends () => Readonly<{
      readonly purpose: 'local' | 'public'
      readonly version: number
      readonly operation: string
      readonly run: (...args: never[]) => unknown
    }>
    ? V
    : never
  : never

export type FactoryTuple<M extends object> = Readonly<UnionToTuple<FactoryValue<M>>>

export function factoryTuple<const M extends object>(module: M): FactoryTuple<M> {
  const marker = Symbol.for('panva.paseto.capabilityFactory')
  const factories = Object.values(module).filter(
    (value) =>
      typeof value === 'function' &&
      (value as unknown as Record<PropertyKey, unknown>)[marker] === true,
  )
  if (factories.length === 0) throw new TypeError('Expected at least one factory')
  return factories as unknown as FactoryTuple<M>
}
