/**
 * Pocket 代理与 dsh-pocket-auth 的最小调度契约。
 * 局域网（0.0.0.0 直连）与公网（cloudflared 回连同一代理）共用这一入口：
 * allow → 跳过原生 PIN，进入原转发；handled/deny → 停止；其它 → fail-closed。
 */

export function resolvePocketAuthProvider(ctx) {
  if (!ctx || typeof ctx.get !== 'function') return null
  const provider = ctx.get('pocketAuth')
  if (provider && typeof provider.authorizeHttp === 'function') return provider
  return null
}

export function pocketDispatchAction(decision) {
  if (decision?.kind === 'allow') return 'upstream-skip-pin'
  if (decision?.kind === 'handled' || decision?.kind === 'deny') return 'stop'
  return 'fail-closed'
}
