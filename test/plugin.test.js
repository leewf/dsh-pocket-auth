import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, name, inject } from '../lib/index.js'

test('插件元数据与依赖声明', async () => {
  assert.equal(name, 'dsh-pocket-auth')
  assert.deepEqual(inject, ['webServer'])
  const pkg = JSON.parse(await import('node:fs/promises').then((fs) => fs.readFile(new URL('../package.json', import.meta.url), 'utf8')))
  assert.ok(pkg.dependencies?.qrcode, 'qrcode 须为本包显式依赖，禁止借用宿主传递依赖')
})

test('插件 apply：无 pocket 时不抛错（Cordis 软探测）', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-plugin-apply-nopocket-'))
  try {
    let providedService = null

    // 模拟 Cordis：访问未 inject 的 ctx.pocket 会抛错
    const mockCtx = {
      webServer: {
        register() {},
      },
      provide(key, service) {
        if (key === 'pocketAuth') providedService = service
      },
      get(key) {
        if (key === 'pocket') return undefined
        return undefined
      },
      on() {},
      get pocket() {
        throw new Error('cannot get property "pocket" without inject')
      },
    }

    await assert.doesNotReject(() => apply(mockCtx, { directory: dir }))
    assert.ok(providedService)
    assert.equal(typeof providedService.authorizeHttp, 'function')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('插件 apply：pocket 后加载时经 ctx.inject 挂载', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-plugin-apply-inject-'))
  try {
    let injectFn = null
    const mockCtx = {
      webServer: { register() {} },
      provide() {},
      get() { return undefined },
      on() {},
      inject(deps, fn) {
        injectFn = fn
      },
      get pocket() {
        throw new Error('cannot get property "pocket" without inject')
      },
    }
    await apply(mockCtx, { directory: dir })
    assert.equal(typeof injectFn, 'function')
    const pocketService = { registered: null, registerAuthProvider(p) { this.registered = p } }
    injectFn({ pocket: pocketService })
    assert.ok(pocketService.registered)
    assert.equal(typeof pocketService.registered.authorizeHttp, 'function')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('插件 apply 流程：注册 webServer 路由与 provide 服务', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-plugin-apply-'))
  try {
    let registeredRoute = null
    let providedService = null
    let disposed = false

    const pocketService = {
      registeredProvider: null,
      registerAuthProvider(p) {
        this.registeredProvider = p
      },
    }

    const mockCtx = {
      webServer: {
        register(route) {
          registeredRoute = route
        },
      },
      provide(key, service) {
        if (key === 'pocketAuth') providedService = service
      },
      get(key) {
        if (key === 'pocket') return pocketService
        return undefined
      },
      on(event, handler) {
        if (event === 'dispose') {
          this._disposeHandler = handler
        }
      },
      get pocket() {
        throw new Error('cannot get property "pocket" without inject')
      },
    }

    await apply(mockCtx, { directory: dir })

    assert.ok(registeredRoute)
    assert.equal(registeredRoute.kind, 'prefix')
    assert.equal(registeredRoute.path, '/pocket-auth-admin')

    assert.ok(providedService)
    assert.equal(typeof providedService.authorizeHttp, 'function')
    assert.equal(typeof providedService.authorizeUpgrade, 'function')

    assert.equal(pocketService.registeredProvider, providedService)

    // 模拟 dispose
    mockCtx._disposeHandler?.()
    disposed = true
    assert.equal(disposed, true)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
