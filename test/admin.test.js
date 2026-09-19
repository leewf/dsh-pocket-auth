import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createCredentials } from '../lib/credentials.mjs'
import { createAdminHandler } from '../lib/admin.mjs'
import { base32Decode, totp } from '../lib/totp.mjs'

async function withTempStore(run) {
  const directory = await mkdtemp(join(tmpdir(), 'dsh-admin-test-'))
  try {
    await run(directory)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

function mockRequest(method, url, headers = {}, body = null) {
  return {
    method,
    url,
    headers: {
      host: '127.0.0.1:3080',
      origin: 'http://127.0.0.1:3080',
      ...headers,
    },
    async json() {
      return body || {}
    },
  }
}

/** DSH webServer 传入的是 Node IncomingMessage：没有 req.json()，JSON 在请求流里。 */
function nodeHttpRequest(method, url, bodyObj, headers = {}) {
  const payload = bodyObj == null ? '' : JSON.stringify(bodyObj)
  return {
    method,
    url,
    headers: {
      host: '127.0.0.1:3080',
      origin: 'http://127.0.0.1:3080',
      'content-type': 'application/json',
      ...headers,
    },
    on(event, cb) {
      if (event === 'data' && payload) cb(Buffer.from(payload))
      if (event === 'end') cb()
      return this
    },
  }
}

test('Admin API：状态查询不返回 secret', async () => {
  await withTempStore(async (directory) => {
    const credentials = await createCredentials({ directory })
    const admin = createAdminHandler({ credentials, allowedOrigins: ['http://127.0.0.1:3080'] })
    const res = await admin.handle(mockRequest('GET', '/pocket-auth-admin/status'))
    assert.equal(res.status, 200)
    assert.deepEqual(res.body, { state: 'unconfigured', credentialVersion: 0 })
    assert.equal('secret' in res.body, false)
  })
})

test('Admin API：非允许 Origin 直接拒绝 403', async () => {
  await withTempStore(async (directory) => {
    const credentials = await createCredentials({ directory })
    const admin = createAdminHandler({ credentials, allowedOrigins: ['http://127.0.0.1:3080'] })
    const res = await admin.handle(mockRequest('POST', '/pocket-auth-admin/binding/start', { origin: 'http://malicious.com' }))
    assert.equal(res.status, 403)
  })
})

test('Admin API：二阶段绑定流程', async () => {
  await withTempStore(async (directory) => {
    let now = 10_000
    const credentials = await createCredentials({ directory, clock: () => now })
    const admin = createAdminHandler({ credentials, allowedOrigins: ['http://127.0.0.1:3080'], clock: () => now })

    // 1. 开始绑定
    const startRes = await admin.handle(mockRequest('POST', '/pocket-auth-admin/binding/start', {}, { owner: 'admin-local' }))
    assert.equal(startRes.status, 200)
    const { bindingId, secret, uri, qrDataUrl } = startRes.body
    assert.ok(bindingId)
    assert.ok(secret)
    assert.ok(uri.startsWith('otpauth://'))
    assert.equal('confirmCode' in startRes.body, false)
    assert.ok(typeof qrDataUrl === 'string' && qrDataUrl.startsWith('data:image/png;base64,'), '应生成本地 PNG 二维码 Data URL')

    // 2. 确认绑定
    const code = totp(base32Decode(secret), now).code
    const confirmRes = await admin.handle(mockRequest('POST', '/pocket-auth-admin/binding/confirm', {}, {
      owner: 'admin-local',
      bindingId,
      code,
    }))
    assert.equal(confirmRes.status, 200)
    assert.equal(confirmRes.body.credentialVersion, 1)

    // 3. 再次查状态
    const statusRes = await admin.handle(mockRequest('GET', '/pocket-auth-admin/status'))
    assert.deepEqual(statusRes.body, { state: 'active', credentialVersion: 1 })
  })
})

test('Admin API：Node HTTP 流式 JSON 体可完成确认绑定（无 req.json）', async () => {
  await withTempStore(async (directory) => {
    let now = 10_000
    const credentials = await createCredentials({ directory, clock: () => now })
    const admin = createAdminHandler({ credentials, allowedOrigins: ['http://127.0.0.1:3080'], clock: () => now })

    const startRes = await admin.handle(nodeHttpRequest('POST', '/pocket-auth-admin/binding/start', { owner: 'admin-local' }))
    assert.equal(startRes.status, 200)
    assert.ok(startRes.body.bindingId)

    const code = totp(base32Decode(startRes.body.secret), now).code
    const confirmRes = await admin.handle(nodeHttpRequest('POST', '/pocket-auth-admin/binding/confirm', {
      owner: 'admin-local',
      bindingId: startRes.body.bindingId,
      code,
    }))
    assert.equal(confirmRes.status, 200, confirmRes.body?.error)
    assert.equal(confirmRes.body.credentialVersion, 1)
  })
})

test('Admin API：流式请求缺少 bindingId 或 code 仍返回明确错误', async () => {
  await withTempStore(async (directory) => {
    const credentials = await createCredentials({ directory })
    const admin = createAdminHandler({ credentials, allowedOrigins: ['http://127.0.0.1:3080'] })
    const res = await admin.handle(nodeHttpRequest('POST', '/pocket-auth-admin/binding/confirm', { code: '123456' }))
    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'bindingId and code required')
  })
})
