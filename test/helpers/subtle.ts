/**
 * Replaces `crypto.subtle` methods until the returned callback is invoked.
 *
 * Restoring by assignment would leave an own property behind whenever the replaced method was
 * inherited, permanently shadowing the prototype for every test that runs afterwards. The original
 * property descriptors are restored instead, leaving `crypto.subtle` exactly as it was found.
 */
export function mockSubtle(mocks: Record<string, unknown>): () => void {
  const subtle = crypto.subtle as unknown as Record<string, unknown>
  const descriptors = Object.entries(mocks).map(([name, value]) => {
    const descriptor = Object.getOwnPropertyDescriptor(subtle, name)
    Object.defineProperty(subtle, name, { configurable: true, writable: true, value })
    return [name, descriptor] as const
  })
  return () => {
    for (const [name, descriptor] of descriptors) {
      if (descriptor) Object.defineProperty(subtle, name, descriptor)
      else Reflect.deleteProperty(subtle, name)
    }
  }
}
