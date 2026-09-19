const JSON_BODY_LIMIT = 4096

function readRawBody(req, maxBytes = JSON_BODY_LIMIT) {
  if (typeof req?.on !== 'function') return Promise.resolve('')
  return new Promise((resolve, reject) => {
    let body = ''
    let size = 0
    req.on('data', (chunk) => {
      size += Buffer.byteLength(chunk)
      if (size > maxBytes) reject(new Error('payload_too_large'))
      else body += chunk.toString('utf8')
    })
    req.on('end', () => resolve(body))
    req.on('error', reject)
  })
}

/**
 * 解析 Admin JSON 请求体。
 * DSH webServer 传入的是 Node IncomingMessage（无 req.json）；单测 mock 可能提供 req.json()。
 * @param {object} req
 * @returns {Promise<object>}
 */
export async function parseJsonBody(req) {
  if (typeof req?.json === 'function') {
    try {
      const parsed = await req.json()
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {}
    } catch {
      return {}
    }
  }
  if (req?.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body) && !Array.isArray(req.body)) {
    return req.body
  }
  try {
    const raw = await readRawBody(req)
    if (!raw) return {}
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {}
  } catch {
    return {}
  }
}

/**
 * 将 otpauth URI 渲染为 PNG Data URL，供 Aegis 扫码绑定。
 * 依赖缺失或渲染失败时返回 null，前端回退到手动密钥录入。
 * @param {string} uri otpauth://totp/...
 * @returns {Promise<string|null>}
 */
export async function renderOtpauthQrDataUrl(uri) {
  try {
    const mod = await import('qrcode')
    const QRCode = mod.default || mod
    if (typeof QRCode?.toDataURL !== 'function') return null
    return await QRCode.toDataURL(uri, { margin: 1, width: 240 })
  } catch {
    return null
  }
}

export function createAdminHandler({
  credentials,
  allowedOrigins = ['http://127.0.0.1:3080', 'http://localhost:3080'],
  clock = () => Date.now(),
} = {}) {
  function verifyOrigin(req) {
    const origin = req.headers?.origin || req.headers?.Origin
    if (!origin) return true // 同源无 origin 或内部调用放行
    return allowedOrigins.includes(origin)
  }

  async function handle(req) {
    if (!verifyOrigin(req)) {
      return { status: 403, body: { error: 'forbidden_origin' } }
    }

    const url = new URL(req.url, 'http://127.0.0.1')
    const path = url.pathname

    if (req.method === 'GET' && path === '/pocket-auth-admin/status') {
      const status = credentials.status()
      return { status: 200, body: status }
    }

    if (req.method === 'POST' && path === '/pocket-auth-admin/binding/start') {
      const body = await parseJsonBody(req)
      const owner = body.owner || 'admin-local'
      try {
        const pending = credentials.begin(owner)
        // qrcode 为本包显式依赖；插件经 junction 解析到真实路径后，
        // 无法借用 profiles/web/node_modules 的传递依赖，必须自带。
        const qrDataUrl = await renderOtpauthQrDataUrl(pending.uri)

        return {
          status: 200,
          body: {
            bindingId: pending.bindingId,
            secret: pending.secret,
            uri: pending.uri,
            expiresAt: pending.expiresAt,
            qrDataUrl,
          },
        }
      } catch (err) {
        return { status: 400, body: { error: err.message } }
      }
    }

    if (req.method === 'POST' && path === '/pocket-auth-admin/binding/confirm') {
      const body = await parseJsonBody(req)
      const { owner = 'admin-local', bindingId, code } = body
      if (!bindingId || !code) {
        return { status: 400, body: { error: 'bindingId and code required' } }
      }
      try {
        const res = await credentials.confirm(owner, bindingId, code)
        return { status: 200, body: res }
      } catch (err) {
        return { status: 400, body: { error: err.message } }
      }
    }

    return { status: 404, body: { error: 'not_found' } }
  }

  return { handle }
}
