/** A minimal Cordis-shaped context: records listeners so tests can fire them. */
export function fakeContext() {
  const listeners = new Map()
  const warnings = []
  return {
    warnings,
    logger: { warn: (message) => warnings.push(message) },
    on(event, listener) { listeners.set(event, listener) },
    fire(event, ...args) {
      const listener = listeners.get(event)
      if (!listener) throw new Error(`no listener for ${event}`)
      return listener(...args)
    },
  }
}

/** A fake agent rooted at `cwd` that records steering. */
export function fakeAgent(cwd) {
  const steered = []
  return { steered, session: { header: { cwd, id: `session-${Math.random().toString(36).slice(2)}` } }, steer: (message) => steered.push(message) }
}

/** A pending tool execution as dsh hands it to `tools/*` listeners. */
export function execution(name, args, agent) {
  return { callId: 'call-1', name, arguments: args, agent, signal: new AbortController().signal }
}

export const allow = async () => ({ kind: 'allow' })
export const accept = async () => ({ kind: 'accept' })
