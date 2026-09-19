import test from 'node:test'
import assert from 'node:assert/strict'
import { createLimiter } from '../lib/limiter.mjs'

test('失败达到阈值后按阶梯锁定，成功清除来源失败计数', () => {
  let now = 0
  const limiter = createLimiter({ clock: () => now })
  for (let i = 0; i < 5; i += 1) limiter.failure('source-1')
  assert.equal(limiter.check('source-1').allowed, false)
  now = 31_000
  assert.equal(limiter.check('source-1').allowed, true)
  limiter.failure('source-1')
  limiter.success('source-1')
  assert.equal(limiter.check('source-1').allowed, true)
})

test('实例级请求预算超限时拒绝新请求', () => {
  let now = 0
  const limiter = createLimiter({ clock: () => now, globalLimit: 2 })
  assert.equal(limiter.check('a').allowed, true)
  assert.equal(limiter.check('b').allowed, true)
  assert.equal(limiter.check('c').allowed, false)
  now = 60_001
  assert.equal(limiter.check('c').allowed, true)
})
