import { createHash, randomBytes as secureRandomBytes } from 'node:crypto'

const HTTPS_TTL_MS = 30 * 24 * 60 * 60 * 1000
const HTTP_TTL_MS = 24 * 60 * 60 * 1000

export function createSessions({ clock = () => Date.now(), randomBytes = secureRandomBytes, maxSessions = 100 } = {}) {
  const records = new Map()
  const revoked = new Set()
  const hash = (token) => createHash('sha256').update(token).digest('hex')

  function issue(credentialVersion, protocol = 'https') {
    if (protocol !== 'http' && protocol !== 'https') throw new TypeError('protocol must be http or https')
    if (records.size >= maxSessions) throw new Error('session capacity reached')
    const token = randomBytes(32).toString('base64url')
    const id = hash(token)
    const createdAt = clock()
    const expiresAt = createdAt + (protocol === 'http' ? HTTP_TTL_MS : HTTPS_TTL_MS)
    records.set(id, { id, createdAt, expiresAt, credentialVersion, protocol })
    return { token, createdAt, expiresAt, protocol }
  }

  function verify(token, credentialVersion, protocol) {
    if (typeof token !== 'string' || !protocol) return null
    const id = hash(token)
    const record = records.get(id)
    if (!record || revoked.has(id) || record.credentialVersion !== credentialVersion || record.protocol !== protocol) return null
    if (clock() >= record.expiresAt) {
      records.delete(id)
      return null
    }
    return { id: record.id, expiresAt: record.expiresAt, protocol: record.protocol }
  }

  function revoke(token) {
    if (typeof token === 'string') revoked.add(hash(token))
  }

  function revokeAll() {
    for (const id of records.keys()) revoked.add(id)
    records.clear()
  }

  return { issue, verify, revoke, revokeAll, size: () => records.size }
}
