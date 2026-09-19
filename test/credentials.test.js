import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createCredentials } from '../lib/credentials.mjs'
import { base32Decode, totp } from '../lib/totp.mjs'

async function withTempStore(run) {
  const directory = await mkdtemp(join(tmpdir(), 'dsh-pocket-auth-'))
  try {
    await run(directory)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

test('初始状态未配置，绑定确认后变为 active', async () => {
  await withTempStore(async (directory) => {
    let now = 1_000
    const credentials = await createCredentials({ directory, clock: () => now })
    assert.deepEqual(credentials.status(), { state: 'unconfigured', credentialVersion: 0 })
    const pending = credentials.begin('admin-1')
    assert.equal(pending.bindingId.length > 0, true)
    const confirmCode = totp(base32Decode(pending.secret), now).code
    const result = await credentials.confirm('admin-1', pending.bindingId, confirmCode)
    assert.deepEqual(result, { credentialVersion: 1 })
    assert.deepEqual(credentials.status(), { state: 'active', credentialVersion: 1 })
  })
})

test('绑定接口不会返回可直接使用的验证码', async () => {
  await withTempStore(async (directory) => {
    const credentials = await createCredentials({ directory, clock: () => 1_000 })
    const pending = credentials.begin('admin-1')
    assert.equal('confirmCode' in pending, false)
    assert.equal('nextCode' in pending, false)
  })
})

test('绑定会话不匹配时不能激活', async () => {
  await withTempStore(async (directory) => {
    const credentials = await createCredentials({ directory, clock: () => 1_000 })
    const pending = credentials.begin('admin-1')
    await assert.rejects(
      credentials.confirm('admin-2', pending.bindingId, totp(base32Decode(pending.secret), 1_000).code),
      /binding owner/i,
    )
  })
})

test('同一时间步验证码只能消费一次且持久化', async () => {
  await withTempStore(async (directory) => {
    let now = 1_000
    const credentials = await createCredentials({ directory, clock: () => now })
    const pending = credentials.begin('admin-1')
    await credentials.confirm('admin-1', pending.bindingId, totp(base32Decode(pending.secret), now).code)
    now = 31_000
    const nextCode = totp(base32Decode(pending.secret), now).code
    const first = await credentials.consume(nextCode)
    const second = await credentials.consume(nextCode)
    assert.equal(first.step, 1n)
    assert.equal(second, null)
    const raw = JSON.parse(await readFile(join(directory, 'totp-secret.json'), 'utf8'))
    assert.equal(raw.lastAcceptedStep, '1')
  })
})

test('重启加载后仍拒绝已消费时间步', async () => {
  await withTempStore(async (directory) => {
    let now = 1_000
    let credentials = await createCredentials({ directory, clock: () => now })
    const pending = credentials.begin('admin-1')
    await credentials.confirm('admin-1', pending.bindingId, totp(base32Decode(pending.secret), now).code)
    now = 31_000
    await credentials.consume(totp(base32Decode(pending.secret), now).code)
    credentials = await createCredentials({ directory, clock: () => now })
    assert.equal(await credentials.consume(totp(base32Decode(pending.secret), now).code), null)
  })
})
