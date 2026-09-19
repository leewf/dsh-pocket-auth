import test from 'node:test'
import assert from 'node:assert/strict'
import { pocketDispatchAction, resolvePocketAuthProvider } from '../lib/pocket-hook.mjs'

test('Pocket hook：ctx.get(pocketAuth) 解析 Provider', () => {
  const provider = { authorizeHttp() {}, authorizeUpgrade() {} }
  const ctx = { get(name) { return name === 'pocketAuth' ? provider : undefined } }
  assert.equal(resolvePocketAuthProvider(ctx), provider)
  assert.equal(resolvePocketAuthProvider({ get() { return undefined } }), null)
  assert.equal(resolvePocketAuthProvider(null), null)
})

test('Pocket hook：局域网与公网共用 allow/stop/fail-closed 调度', () => {
  assert.equal(pocketDispatchAction({ kind: 'allow' }), 'upstream-skip-pin')
  assert.equal(pocketDispatchAction({ kind: 'handled' }), 'stop')
  assert.equal(pocketDispatchAction({ kind: 'deny', status: 401 }), 'stop')
  assert.equal(pocketDispatchAction(null), 'fail-closed')
  assert.equal(pocketDispatchAction({ kind: 'unknown' }), 'fail-closed')
})
