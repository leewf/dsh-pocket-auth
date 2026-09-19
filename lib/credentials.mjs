import { randomBytes } from 'node:crypto'
import { openStore } from './store.mjs'
import { buildOtpAuthUri, base32Decode, createSecret, matchTotp, totp } from './totp.mjs'

const PENDING_TTL_MS = 10 * 60 * 1000

export async function createCredentials({ directory, clock = () => Date.now() }) {
  const store = await openStore(directory)
  let pending = null
  let busy = Promise.resolve()
  const current = () => store.read()

  function status() {
    const record = current()
    if (!record) return { state: 'unconfigured', credentialVersion: 0 }
    return { state: 'active', credentialVersion: record.credentialVersion }
  }

  function begin(owner) {
    if (typeof owner !== 'string' || owner.trim() === '') throw new TypeError('binding owner is required')
    const secret = createSecret()
    const bindingId = randomBytes(16).toString('hex')
    const startedAt = clock()
    pending = { owner, bindingId, secret, startedAt, expiresAt: startedAt + PENDING_TTL_MS }
    return {
      bindingId,
      secret,
      uri: buildOtpAuthUri(base32Decode(secret), 'workstation'),
      expiresAt: pending.expiresAt,
    }
  }

  async function confirm(owner, bindingId, code) {
    return enqueue(async () => {
      if (!pending || pending.bindingId !== bindingId) throw new Error('binding not found')
      if (pending.owner !== owner) throw new Error('binding owner mismatch')
      const now = clock()
      if (!Number.isFinite(now) || now < 0 || now > pending.expiresAt) throw new Error('binding expired')
      const pendingSecret = pending.secret
      const step = matchTotp(base32Decode(pendingSecret), code, now, 1)
      if (step === null) throw new Error('invalid binding code')
      const version = (current()?.credentialVersion ?? 0) + 1
      await store.commit({ schemaVersion: 1, credentialVersion: version, secret: pendingSecret, lastAcceptedStep: String(step) })
      pending = null
      return { credentialVersion: version }
    })
  }

  async function consume(code) {
    return enqueue(async () => {
      const record = current()
      if (!record) return null
      const step = matchTotp(base32Decode(record.secret), code, clock(), 1)
      if (step === null || step <= BigInt(record.lastAcceptedStep)) return null
      await store.commit({ ...record, lastAcceptedStep: String(step) })
      return { credentialVersion: record.credentialVersion, step }
    })
  }

  async function enqueue(task) {
    const result = busy.then(task, task)
    busy = result.catch(() => {})
    return result
  }

  return { status, begin, confirm, consume }
}
