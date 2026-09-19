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

async function withTempStore(run) {
  const directory = await mkdtemp(join(tmpdir(), 'dsh-provider-test-'))
  try {
    await run(directory)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

function createMockReqRes({
  method = 'GET',
  url = '/',
  headers = {},
  body = '',
  remoteAddress = '192.168.1.100',
} = {}) {
  let responseData = {
    statusCode: 200,
    headers: {},
    body: '',
    ended: false,
  }

  const req = {
    method,
    url,
    headers: {
      host: 'pocket.example.com',
      ...headers,
    },
    socket: { remoteAddress, encrypted: false },
    on(event, handler) {
      if (event === 'data' && body) {
        handler(Buffer.from(body))
      }
      if (event === 'end') {
        handler()
      }
      return req
    },
  }

  const res = {
    writeHead(status, hdrs = {}) {
      responseData.statusCode = status
      Object.assign(responseData.headers, hdrs)
      return res
    },
    end(data = '') {
      responseData.body += data
      responseData.ended = true
      return res
    },
    getHeader(name) {
      return responseData.headers[name.toLowerCase()]
    },
  }

  return { req, res, responseData }
}

test('Provider: 未绑定任何密钥时，请求 fail-closed 返回 503', async () => {
  await withTempStore(async (directory) => {
    const credentials = await createCredentials({ directory })
    const sessions = createSessions()
    const limiter = createLimiter()
    const admin = createAdminHandler({ credentials })
    const provider = createAuthProvider({ credentials, sessions, limiter, admin })

    const { req, res, responseData } = createMockReqRes({ url: '/' })
    const decision = await provider.authorizeHttp(req, res)

    assert.equal(decision.kind, 'deny')
    assert.equal(decision.status, 503)
  })
})

test('Provider: 绑定后未登录访问主页，HTML 请求拦截并重定向/展示登录页', async () => {
  await withTempStore(async (directory) => {
    let now = 10_000
    const credentials = await createCredentials({ directory, clock: () => now })
    const sessions = createSessions({ clock: () => now })
    const limiter = createLimiter({ clock: () => now })
    const admin = createAdminHandler({ credentials })
    const provider = createAuthProvider({ credentials, sessions, limiter, admin, clock: () => now })

    // 绑定密钥
    const pending = credentials.begin('admin-local')
    await credentials.confirm('admin-local', pending.bindingId, totp(base32Decode(pending.secret), now).code)

    // 访问登录页
    const { req, res, responseData } = createMockReqRes({
      url: '/pocket-auth/login',
      headers: { accept: 'text/html' },
    })
    const decision = await provider.authorizeHttp(req, res)
    assert.equal(decision.kind, 'handled')
    assert.equal(responseData.statusCode, 200)
    assert.match(responseData.body, /安全口令验证/)
  })
})

test('Provider: 提交 6 位动态验证码登录成功，种植 HttpOnly Cookie 并 302 重定向', async () => {
  await withTempStore(async (directory) => {
    let now = 10_000
    const credentials = await createCredentials({ directory, clock: () => now })
    const sessions = createSessions({ clock: () => now })
    const limiter = createLimiter({ clock: () => now })
    const admin = createAdminHandler({ credentials })
    const provider = createAuthProvider({ credentials, sessions, limiter, admin, clock: () => now })

    // 绑定密钥
    const pending = credentials.begin('admin-local')
    await credentials.confirm('admin-local', pending.bindingId, totp(base32Decode(pending.secret), now).code)

    // 进入下一个步长提交登录验证
    now = 31_000
    const code = totp(base32Decode(pending.secret), now).code
    const { req, res, responseData } = createMockReqRes({
      method: 'POST',
      url: '/pocket-auth/verify',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'x-forwarded-proto': 'https',
        host: 'pocket.example.com',
      },
      body: `code=${code}`,
      remoteAddress: '127.0.0.1',
    })

    const decision = await provider.authorizeHttp(req, res)
    assert.equal(decision.kind, 'handled')
    assert.equal(responseData.statusCode, 302)
    assert.equal(responseData.headers['location'], '/')
    const setCookie = responseData.headers['set-cookie']
    assert.ok(setCookie)
    assert.match(setCookie, /dsh-pocket-auth-token=[a-zA-Z0-9_-]+/)
    assert.match(setCookie, /HttpOnly/)
    assert.match(setCookie, /Secure/)
    assert.match(setCookie, /SameSite=Lax/)
    assert.match(setCookie, /Max-Age=2592000/)

    // 提取 cookie 再次发起常规业务请求 -> 应直接放行 allow
    const tokenMatch = setCookie.match(/dsh-pocket-auth-token=([a-zA-Z0-9_-]+);/)
    const token = tokenMatch[1]

    const authed = createMockReqRes({
      method: 'GET',
      url: '/api/conversations',
      headers: {
        cookie: `dsh-pocket-auth-token=${token}`,
        'x-forwarded-proto': 'https',
        host: 'pocket.example.com',
      },
      remoteAddress: '127.0.0.1',
    })
    const allowDecision = await provider.authorizeHttp(authed.req, authed.res)
    assert.equal(allowDecision.kind, 'allow')
    assert.ok(allowDecision.sessionId)
  })
})

test('Provider: WebSocket Upgrade 鉴权：未认证关闭 socket，认证通过放行', async () => {
  await withTempStore(async (directory) => {
    let now = 10_000
    const credentials = await createCredentials({ directory, clock: () => now })
    const sessions = createSessions({ clock: () => now })
    const limiter = createLimiter({ clock: () => now })
    const admin = createAdminHandler({ credentials })
    const provider = createAuthProvider({ credentials, sessions, limiter, admin, clock: () => now })

    const pending = credentials.begin('admin-local')
    await credentials.confirm('admin-local', pending.bindingId, totp(base32Decode(pending.secret), now).code)

    // 1. 无 Cookie 的 Upgrade 请求
    let socketDestroyed = false
    let socketWritten = ''
    const fakeSocket = {
      write(d) { socketWritten += d },
      destroy() { socketDestroyed = true },
    }
    const unauthUpgrade = {
      headers: { host: 'pocket.example.com' },
      socket: { encrypted: true },
    }
    const denyDecision = await provider.authorizeUpgrade(unauthUpgrade, fakeSocket, Buffer.alloc(0))
    assert.equal(denyDecision.kind, 'deny')
    assert.equal(socketDestroyed, true)
    assert.match(socketWritten, /401 Unauthorized/)

    // 2. 签发会话后携带 Cookie 进行 Upgrade
    const session = sessions.issue(1, 'https')
    const authedUpgrade = {
      headers: {
        host: 'pocket.example.com',
        cookie: `dsh-pocket-auth-token=${session.token}`,
      },
      socket: { encrypted: true },
    }
    const allowDecision = await provider.authorizeUpgrade(authedUpgrade, fakeSocket, Buffer.alloc(0))
    assert.equal(allowDecision.kind, 'allow')
  })
})

test('Provider: 远程访问 admin 路由强制拒绝 403', async () => {
  await withTempStore(async (directory) => {
    const credentials = await createCredentials({ directory })
    const sessions = createSessions()
    const limiter = createLimiter()
    const admin = createAdminHandler({ credentials })
    const provider = createAuthProvider({ credentials, sessions, limiter, admin })

    const { req, res } = createMockReqRes({
      url: '/pocket-auth-admin/status',
      remoteAddress: '198.51.100.23', // 公网远程地址
      headers: { host: 'pocket.example.com' },
    })

    const decision = await provider.authorizeHttp(req, res)
    assert.equal(decision.kind, 'deny')
    assert.equal(decision.status, 403)
  })
})

test('Provider: 局域网 HTTP 与公网 HTTPS 共用同一 TOTP，会话按协议隔离', async () => {
  await withTempStore(async (directory) => {
    let now = 10_000
    const credentials = await createCredentials({ directory, clock: () => now })
    const sessions = createSessions({ clock: () => now })
    const limiter = createLimiter({ clock: () => now })
    const admin = createAdminHandler({ credentials })
    const provider = createAuthProvider({ credentials, sessions, limiter, admin, clock: () => now })

    const pending = credentials.begin('admin-local')
    await credentials.confirm('admin-local', pending.bindingId, totp(base32Decode(pending.secret), now).code)

    now = 40_000
    const lanCode = totp(base32Decode(pending.secret), now).code
    const lanLogin = createMockReqRes({
      method: 'POST',
      url: '/pocket-auth/verify',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        host: '192.168.1.8:3081',
        accept: 'text/html',
      },
      body: `code=${lanCode}`,
      remoteAddress: '192.168.1.23',
    })
    const lanDecision = await provider.authorizeHttp(lanLogin.req, lanLogin.res)
    assert.equal(lanDecision.kind, 'handled')
    assert.equal(lanLogin.responseData.statusCode, 302)
    const lanCookie = lanLogin.responseData.headers['set-cookie']
    assert.match(lanCookie, /Max-Age=86400/)
    assert.doesNotMatch(lanCookie, /Secure/)
    const lanToken = lanCookie.match(/dsh-pocket-auth-token=([a-zA-Z0-9_-]+);/)[1]

    now = 80_000
    const wanCode = totp(base32Decode(pending.secret), now).code
    const wanLogin = createMockReqRes({
      method: 'POST',
      url: '/pocket-auth/verify',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'x-forwarded-proto': 'https',
        'cf-connecting-ip': '203.0.113.50',
        host: 'chat.example.com',
      },
      body: `code=${wanCode}`,
      remoteAddress: '127.0.0.1',
    })
    const wanDecision = await provider.authorizeHttp(wanLogin.req, wanLogin.res)
    assert.equal(wanDecision.kind, 'handled')
    const wanCookie = wanLogin.responseData.headers['set-cookie']
    assert.match(wanCookie, /Max-Age=2592000/)
    assert.match(wanCookie, /Secure/)
    const wanToken = wanCookie.match(/dsh-pocket-auth-token=([a-zA-Z0-9_-]+);/)[1]

    const lanAllow = createMockReqRes({
      url: '/api/sessions',
      headers: { cookie: `dsh-pocket-auth-token=${lanToken}`, host: '192.168.1.8:3081' },
      remoteAddress: '192.168.1.23',
    })
    assert.equal((await provider.authorizeHttp(lanAllow.req, lanAllow.res)).kind, 'allow')

    const wanAllow = createMockReqRes({
      url: '/api/sessions',
      headers: {
        cookie: `dsh-pocket-auth-token=${wanToken}`,
        'x-forwarded-proto': 'https',
        host: 'chat.example.com',
      },
      remoteAddress: '127.0.0.1',
    })
    assert.equal((await provider.authorizeHttp(wanAllow.req, wanAllow.res)).kind, 'allow')

    const cross = createMockReqRes({
      url: '/api/sessions',
      headers: {
        cookie: `dsh-pocket-auth-token=${lanToken}`,
        'x-forwarded-proto': 'https',
        host: 'chat.example.com',
      },
      remoteAddress: '127.0.0.1',
    })
    const crossDecision = await provider.authorizeHttp(cross.req, cross.res)
    assert.notEqual(crossDecision.kind, 'allow')
  })
})

test('Provider: 局域网伪造 X-Forwarded-Proto 不能升级为 HTTPS 会话', async () => {
  await withTempStore(async (directory) => {
    let now = 10_000
    const credentials = await createCredentials({ directory, clock: () => now })
    const sessions = createSessions({ clock: () => now })
    const limiter = createLimiter({ clock: () => now })
    const admin = createAdminHandler({ credentials })
    const provider = createAuthProvider({ credentials, sessions, limiter, admin, clock: () => now })

    const pending = credentials.begin('admin-local')
    await credentials.confirm('admin-local', pending.bindingId, totp(base32Decode(pending.secret), now).code)

    now = 40_000
    const code = totp(base32Decode(pending.secret), now).code
    const spoof = createMockReqRes({
      method: 'POST',
      url: '/pocket-auth/verify',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'x-forwarded-proto': 'https',
        host: '192.168.1.8:3081',
      },
      body: `code=${code}`,
      remoteAddress: '192.168.1.23',
    })
    await provider.authorizeHttp(spoof.req, spoof.res)
    assert.match(spoof.responseData.headers['set-cookie'], /Max-Age=86400/)
    assert.doesNotMatch(spoof.responseData.headers['set-cookie'], /Secure/)
  })
})

test('Provider: cloudflared 回连不能打开本机管理接口', async () => {
  await withTempStore(async (directory) => {
    const credentials = await createCredentials({ directory })
    const sessions = createSessions()
    const limiter = createLimiter()
    const admin = createAdminHandler({ credentials })
    const provider = createAuthProvider({ credentials, sessions, limiter, admin })

    const tunneled = createMockReqRes({
      url: '/pocket-auth-admin/status',
      remoteAddress: '127.0.0.1',
      headers: {
        host: 'chat.example.com',
        'cf-connecting-ip': '203.0.113.9',
        'x-forwarded-proto': 'https',
      },
    })
    const decision = await provider.authorizeHttp(tunneled.req, tunneled.res)
    assert.equal(decision.kind, 'deny')
    assert.equal(decision.status, 403)
  })
})
