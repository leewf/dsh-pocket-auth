import { renderLoginPage } from '../client/login.mjs'

function isLoopback(ip) {
  if (!ip) return false
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1' || ip === 'localhost'
}

function detectProtocol(req) {
  if (req.socket?.encrypted) return 'https'
  // 只信 loopback 上游写入的转发头（cloudflared 回连）。局域网客户端伪造 X-Forwarded-Proto 无效。
  const forwarded = req.headers?.['x-forwarded-proto']
  if (typeof forwarded === 'string' && isLoopback(req.socket?.remoteAddress)) {
    const proto = forwarded.split(',')[0].trim().toLowerCase()
    if (proto === 'https' || proto === 'http') return proto
  }
  return 'http'
}

function hasForwardedClient(req) {
  const headers = req.headers || {}
  return Boolean(headers['cf-connecting-ip'] || headers['x-forwarded-for'])
}

function hostNameOnly(host) {
  const raw = String(host ?? '').trim().toLowerCase()
  if (!raw) return ''
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']')
    return end > 0 ? raw.slice(1, end) : raw
  }
  return raw.split(':')[0]
}

/** 本机设置页：loopback 源 + loopback Host，且无隧道/代理转发头。 */
function isLocalAdminContext(req) {
  if (!isLoopback(req.socket?.remoteAddress)) return false
  if (hasForwardedClient(req)) return false
  const host = hostNameOnly(req.headers?.host)
  return host === '' || host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '0.0.0.0'
}

function getSourceKey(req) {
  // 仅信 loopback 反向代理（cloudflared）写入的客户端标识；LAN 客户端可伪造
  // X-Forwarded-For，不能借此规避 TOTP 尝试次数与阶梯锁定。
  if (isLoopback(req.socket?.remoteAddress)) {
    const cloudflare = req.headers?.['cf-connecting-ip']
    if (typeof cloudflare === 'string' && cloudflare.trim()) return cloudflare.trim()
    const forwarded = req.headers?.['x-forwarded-for']
    if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim()
  }
  return req.socket?.remoteAddress || 'unknown'
}

function parseCookie(cookieHeader, name) {
  if (typeof cookieHeader !== 'string') return null
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`))
  return match ? match[1] : null
}

function readBody(req, maxBytes = 4096) {
  return new Promise((resolve, reject) => {
    let body = ''
    let size = 0
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > maxBytes) {
        reject(new Error('payload_too_large'))
      } else {
        body += chunk.toString('utf8')
      }
    })
    req.on('end', () => resolve(body))
    req.on('error', reject)
  })
}

export function createAuthProvider({
  credentials,
  sessions,
  limiter,
  admin,
  clock = () => Date.now(),
} = {}) {
  async function authorizeHttp(req, res) {
    const url = new URL(req.url || '/', 'http://127.0.0.1')
    const pathname = url.pathname
    const protocol = detectProtocol(req)
    const sourceKey = getSourceKey(req)

    // 1. 管理端路由：仅本机设置页。局域网手机与公网隧道（cloudflared 回连也是 loopback）一律拒绝。
    if (pathname.startsWith('/pocket-auth-admin/')) {
      if (!isLocalAdminContext(req)) {
        res.writeHead(403, { 'content-type': 'application/json', 'cache-control': 'no-store' })
        res.end('{"error":"admin_forbidden_remote"}')
        return { kind: 'deny', status: 403 }
      }
      if (admin) {
        const adminRes = await admin.handle(req)
        res.writeHead(adminRes.status, { 'content-type': 'application/json', 'cache-control': 'no-store' })
        res.end(JSON.stringify(adminRes.body))
        return { kind: 'handled' }
      }
    }

    // 2. 检查凭据配置状态：未配置任何 Aegis 密钥时，远程请求全部 fail-closed 503
    const credStatus = credentials.status()
    if (credStatus.state !== 'active') {
      res.writeHead(503, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
      res.end('<h1>503 Service Unavailable</h1><p>Pocket Auth is enabled but unconfigured. Please complete Aegis binding from local PC first.</p>')
      return { kind: 'deny', status: 503 }
    }

    // 3. 访问登录页面
    if (pathname === '/pocket-auth/login') {
      const html = renderLoginPage({ protocol })
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
      res.end(html)
      return { kind: 'handled' }
    }

    // 4. 提交 6 位动态验证码
    if (pathname === '/pocket-auth/verify' && req.method === 'POST') {
      const limit = limiter.check(sourceKey)
      if (!limit.allowed) {
        const html = renderLoginPage({ protocol, error: 'locked', retryAfter: limit.retryAfter })
        res.writeHead(429, {
          'content-type': 'text/html; charset=utf-8',
          'retry-after': String(limit.retryAfter),
          'cache-control': 'no-store',
        })
        res.end(html)
        return { kind: 'handled' }
      }

      let body = ''
      try {
        body = await readBody(req)
      } catch {
        res.writeHead(400, { 'content-type': 'text/plain' })
        res.end('Bad Request')
        return { kind: 'handled' }
      }

      const params = new URLSearchParams(body)
      const code = params.get('code')?.trim() || ''

      const consumed = await credentials.consume(code)
      if (consumed) {
        limiter.success(sourceKey)
        const session = sessions.issue(consumed.credentialVersion, protocol)
        const isHttps = protocol === 'https'
        const maxAge = isHttps ? 2592000 : 86400
        const secureFlag = isHttps ? '; Secure' : ''
        const cookieStr = `dsh-pocket-auth-token=${session.token}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${secureFlag}`

        res.writeHead(302, {
          location: '/',
          'set-cookie': cookieStr,
          'cache-control': 'no-store',
        })
        res.end()
        return { kind: 'handled' }
      } else {
        limiter.failure(sourceKey)
        const html = renderLoginPage({ protocol, error: 'invalid_code' })
        res.writeHead(401, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
        res.end(html)
        return { kind: 'handled' }
      }
    }

    // 5. 常规请求 Cookie 会话验证
    const token = parseCookie(req.headers?.cookie, 'dsh-pocket-auth-token')
    if (token) {
      const verified = sessions.verify(token, credStatus.credentialVersion, protocol)
      if (verified) {
        return { kind: 'allow', sessionId: verified.id }
      }
    }

    // 6. 会话无效或缺失
    const acceptsHtml = req.headers?.accept?.includes('text/html')
    if (acceptsHtml) {
      res.writeHead(302, { location: '/pocket-auth/login', 'cache-control': 'no-store' })
      res.end()
      return { kind: 'handled' }
    }

    res.writeHead(401, { 'content-type': 'application/json', 'cache-control': 'no-store' })
    res.end('{"error":"unauthorized"}')
    return { kind: 'deny', status: 401 }
  }

  async function authorizeUpgrade(req, socket, head) {
    const credStatus = credentials.status()
    if (credStatus.state !== 'active') {
      socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n')
      socket.destroy()
      return { kind: 'deny', status: 503 }
    }

    const protocol = detectProtocol(req)
    const token = parseCookie(req.headers?.cookie, 'dsh-pocket-auth-token')
    if (token) {
      const verified = sessions.verify(token, credStatus.credentialVersion, protocol)
      if (verified) {
        return { kind: 'allow', sessionId: verified.id }
      }
    }

    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
    socket.destroy()
    return { kind: 'deny', status: 401 }
  }

  return {
    authorizeHttp,
    authorizeUpgrade,
  }
}
