import test from 'node:test'
import assert from 'node:assert/strict'
import { createSessions } from '../lib/sessions.mjs'

test('HTTPS会话固定30天，HTTP会话固定24小时且不滑动续期', () => {
  let now = 0
  let seed = 0
  const sessions = createSessions({ clock: () => now, randomBytes: () => Buffer.alloc(32, ++seed) })
  const https = sessions.issue(1, 'https')
  const http = sessions.issue(1, 'http')
  assert.equal(https.expiresAt, 2_592_000_000)
  assert.equal(http.expiresAt, 86_400_000)
  now = 86_400_000
  assert.equal(sessions.verify(http.token, 1, 'http'), null)
  assert.ok(sessions.verify(https.token, 1, 'https'))
})

test('DSH重启通过新会话容器使旧Cookie全部失效', () => {
  const first = createSessions({ clock: () => 0, randomBytes: () => Buffer.alloc(32, 2) })
  const issued = first.issue(1, 'http')
  const restarted = createSessions({ clock: () => 0, randomBytes: () => Buffer.alloc(32, 2) })
  assert.equal(restarted.verify(issued.token, 1, 'http'), null)
})
