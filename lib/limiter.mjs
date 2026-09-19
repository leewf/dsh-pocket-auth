// 滑动窗口阶梯限速器与实例级限流
export function createLimiter({
  clock = () => Date.now(),
  globalLimit = 60, // 全局每分钟最大请求
  maxEntries = 10_000,
} = {}) {
  const sources = new Map()
  let globalCount = 0
  let globalResetAt = clock() + 60_000

  function cleanupExpired(now) {
    if (sources.size > maxEntries) {
      for (const [key, state] of sources.entries()) {
        if (state.lockUntil && now > state.lockUntil && now - state.windowStart > 300_000) {
          sources.delete(key)
        }
      }
    }
  }

  function check(sourceKey) {
    const now = clock()
    cleanupExpired(now)

    // 全局预算检查
    if (now > globalResetAt) {
      globalCount = 0
      globalResetAt = now + 60_000
    }
    if (globalCount >= globalLimit) {
      return { allowed: false, retryAfter: Math.ceil((globalResetAt - now) / 1000), reason: 'global_rate_limit' }
    }
    globalCount += 1

    // 单来源状态检查
    const state = sources.get(sourceKey)
    if (!state) return { allowed: true }

    if (state.lockUntil && now < state.lockUntil) {
      return { allowed: false, retryAfter: Math.ceil((state.lockUntil - now) / 1000), reason: 'source_locked' }
    }

    return { allowed: true }
  }

  function failure(sourceKey) {
    const now = clock()
    let state = sources.get(sourceKey)
    if (!state) {
      state = { failures: 0, windowStart: now, lockUntil: 0 }
      sources.set(sourceKey, state)
    }

    // 重置 15 分钟窗口
    if (now - state.windowStart > 15 * 60 * 1000) {
      state.failures = 0
      state.windowStart = now
    }

    state.failures += 1

    // 阶梯封禁
    if (state.failures >= 15) {
      state.lockUntil = now + 15 * 60 * 1000 // 15 次封 15 分钟
    } else if (state.failures >= 10) {
      state.lockUntil = now + 3 * 60 * 1000 // 10 次封 3 分钟
    } else if (state.failures >= 5) {
      state.lockUntil = now + 30 * 1000 // 5 次封 30 秒（强制跳过一个步长）
    }
  }

  function success(sourceKey) {
    // 成功只清除该来源的失败计数，不重置全局预算
    sources.delete(sourceKey)
  }

  return { check, failure, success }
}
