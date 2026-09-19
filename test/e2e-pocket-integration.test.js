import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createCredentials } from '../lib/credentials.mjs'
import { createSessions } from '../lib/sessions.mjs'
import { createLimiter } from '../lib/limiter.mjs'
import { createAdminHandler } from '../lib/admin.mjs'
import { createAuthProvider } from '../lib/provider.mjs'
import { base32Decode, totp } from '../lib/totp.mjs'

async function decideAuth({ required, provider, kind, req, res, onAllow }) {
  if (!required) {
    onAllow?.()
    return { kind: 'allow' }
  }
  if (!provider) return { kind: 'deny', status: 503 }
  const decision = kind === 'http'
    ? await provider.authorizeHttp(req, res)
    : await provider.authorizeUpgrade(req, res)
  if (decision?.kind === 'allow') {
    onAllow?.()
    return decision
  }
  return decision || { kind: 'deny', status: 503 }
}

async function withTempStore(run) {
  const directory = await mkdtemp(join(tmpdir(), 'dsh-e2e-test-'))
  try {
    await run(directory)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

test('E2E: Pocket 调度器 与 dsh-pocket-auth Provider 完整协同', async () => {
  await withTempStore(async (directory) => {
    let now = 10_000
    const credentials = await createCredentials({ directory, clock: () => now })
    const sessions = createSessions({ clock: () => now })
    const limiter = createLimiter({ clock: () => now })
    const admin = createAdminHandler({ credentials })
    const provider = createAuthProvider({ credentials, sessions, limiter, admin, clock: () => now })

    let upstreamReached = 0
    const onAllow = () => { upstreamReached += 1 }

    // 1. 未配置状态下外部请求 -> decideAuth 得到 deny 503，upstreamReached 依然为 0
    const req1 = { url: '/', headers: {}, socket: { remoteAddress: '203.0.113.1' } }
    const res1 = { writeHead() {}, end() {} }
    const d1 = await decideAuth({
      required: true,
      provider,
      kind: 'http',
      req: req1,
      res: res1,
      onAllow,
    })
    assert.equal(d1.kind, 'deny')
    assert.equal(d1.status, 503)
    assert.equal(upstreamReached, 0)

    // 2. 本地管理员在设置页完成绑定
    const pending = credentials.begin('admin-local')
    now = 30_000
    const confirmCode = totp(base32Decode(pending.secret), now).code
    await credentials.confirm('admin-local', pending.bindingId, confirmCode)

    // 3. 手机端通过 /pocket-auth/verify 提交动态码登录
    now = 60_000
    const loginCode = totp(base32Decode(pending.secret), now).code
    let cookieHeader = ''
    const reqLogin = {
      method: 'POST',
      url: '/pocket-auth/verify',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      socket: { remoteAddress: '203.0.113.1' },
      on(event, cb) {
        if (event === 'data') cb(Buffer.from(`code=${loginCode}`))
        if (event === 'end') cb()
      },
    }
    const resLogin = {
      writeHead(status, hdrs) {
        if (hdrs['set-cookie']) cookieHeader = hdrs['set-cookie']
      },
      end() {},
    }
    const dLogin = await decideAuth({
      required: true,
      provider,
      kind: 'http',
      req: reqLogin,
      res: resLogin,
      onAllow,
    })
    assert.equal(dLogin.kind, 'handled')
    assert.ok(cookieHeader)
    assert.equal(upstreamReached, 0)

    // 4. 手机端携带提取的 Cookie 访问业务 API -> 放行，进入上游
    const token = cookieHeader.match(/dsh-pocket-auth-token=([a-zA-Z0-9_-]+);/)[1]
    const reqApi = {
      method: 'GET',
      url: '/api/sessions',
      headers: { cookie: `dsh-pocket-auth-token=${token}` },
      socket: { remoteAddress: '203.0.113.1' },
    }
    const resApi = { writeHead() {}, end() {} }
    const dApi = await decideAuth({
      required: true,
      provider,
      kind: 'http',
      req: reqApi,
      res: resApi,
      onAllow,
    })
    assert.equal(dApi.kind, 'allow')
    assert.equal(upstreamReached, 1)

    // 5. WebSocket Upgrade 请求携带同一 Cookie -> 放行
    const reqWs = {
      url: '/api/events.host',
      headers: { cookie: `dsh-pocket-auth-token=${token}` },
      socket: { remoteAddress: '203.0.113.1' },
    }
    const fakeSocket = { write() {}, destroy() {} }
    let wsUpstreamReached = 0
    const dWs = await decideAuth({
      required: true,
      provider,
      kind: 'upgrade',
      req: reqWs,
      res: fakeSocket,
      onAllow: () => { wsUpstreamReached += 1 },
    })
    assert.equal(dWs.kind, 'allow')
    assert.equal(wsUpstreamReached, 1)

    // 6. 重放攻击测试：攻击者尝试重复提交刚刚用过的验证码 loginCode
    let replayLocked = false
    const reqReplay = {
      method: 'POST',
      url: '/pocket-auth/verify',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      socket: { remoteAddress: '203.0.113.2' },
      on(event, cb) {
        if (event === 'data') cb(Buffer.from(`code=${loginCode}`))
        if (event === 'end') cb()
      },
    }
    const resReplay = {
      writeHead(status) {
        if (status === 401) replayLocked = true
      },
      end() {},
    }
    await decideAuth({
      required: true,
      provider,
      kind: 'http',
      req: reqReplay,
      res: resReplay,
      onAllow,
    })
    assert.equal(replayLocked, true) // 拒绝重放
  })
})
