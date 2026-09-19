/**
 * dsh-pocket-auth
 * DeepSeek Harness Pocket Aegis TOTP 动态安全认证插件
 */

import os from 'node:os'
import path from 'node:path'
import { createCredentials } from './credentials.mjs'
import { createSessions } from './sessions.mjs'
import { createLimiter } from './limiter.mjs'
import { createAdminHandler } from './admin.mjs'
import { createAuthProvider } from './provider.mjs'

export const name = 'dsh-pocket-auth'
export const inject = ['webServer']

export async function apply(ctx, config = {}) {
  const dshDir = process.env.DSH_HOME || path.join(os.homedir(), '.dsh')
  const storageDir = config.directory || path.join(dshDir, 'dsh-pocket-auth')

  const log = (msg) => {
    if (ctx.logger) ctx.logger(name).info(msg)
    else console.log(`[${name}] ${msg}`)
  }

  log(`初始化 Pocket Auth 插件，存储路径: ${storageDir}`)

  // 1. 初始化持久化与状态机
  const credentials = await createCredentials({ directory: storageDir })
  const sessions = createSessions()
  const limiter = createLimiter()
  const admin = createAdminHandler({ credentials })

  // 2. 创建核心认证 Provider
  const provider = createAuthProvider({ credentials, sessions, limiter, admin })

  // 3. 注册到 Cordis 上下文，供 Pocket 或其它网关注入使用
  ctx.provide('pocketAuth', provider)

  // 4. 挂载本地 WebServer 管理路由：/pocket-auth-admin/*
  if (ctx.webServer?.register) {
    ctx.webServer.register({
      kind: 'prefix',
      path: '/pocket-auth-admin',
      handler: async (req, res) => {
        // 确保必须为 Localhost / Loopback
        const remote = req.socket?.remoteAddress
        const isLocal = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1' || remote === 'localhost'
        if (!isLocal) {
          res.writeHead(403, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'forbidden_remote' }))
          return
        }

        const adminRes = await admin.handle(req)
        res.writeHead(adminRes.status, {
          'content-type': 'application/json',
          'cache-control': 'no-store',
        })
        res.end(JSON.stringify(adminRes.body))
      },
    })
    log('已注册本地管理路由 /pocket-auth-admin')
  }

  // 5. 挂到 Pocket 网关（局域网 0.0.0.0:3081 与公网 cloudflared 共用同一代理）。
  // Cordis：未列入 inject 的服务不能用 ctx.pocket 访问。ctx.get('pocket') 软探测；
  // 另用 ctx.inject 等待后加载的 pocket。已安装 dsh-pocket 若尚未提供 registerAuthProvider，
  // 本插件仍 provide('pocketAuth')，供 Pocket 按请求 ctx.get('pocketAuth') 拉取。
  let unregisterPocketAuth = null
  const attachPocket = (pocket) => {
    if (unregisterPocketAuth || !pocket?.registerAuthProvider) return Boolean(unregisterPocketAuth)
    try {
      unregisterPocketAuth = pocket.registerAuthProvider(provider)
      if (typeof unregisterPocketAuth !== 'function') unregisterPocketAuth = null
      log('已成功挂载至 dsh-pocket 认证网关（局域网与公网入口共用 TOTP）')
      return true
    } catch (err) {
      log(`Pocket 认证 Provider 挂载失败: ${err?.message || err}`)
      return false
    }
  }
  const pocketNow = typeof ctx.get === 'function' ? ctx.get('pocket') : null
  if (!attachPocket(pocketNow) && typeof ctx.inject === 'function') {
    try {
      ctx.inject(['pocket'], (scoped) => {
        attachPocket(scoped.pocket || (typeof scoped.get === 'function' ? scoped.get('pocket') : null))
      })
    } catch (err) {
      log(`Pocket 延迟注入不可用: ${err?.message || err}`)
    }
  }

  // 6. 销毁逻辑
  ctx.on?.('dispose', () => {
    try { unregisterPocketAuth?.() } catch { /* 网关已销毁时忽略 */ }
    unregisterPocketAuth = null
    sessions.revokeAll()
    log('Pocket Auth 插件已卸载，所有活跃会话已销毁。')
  })
}
