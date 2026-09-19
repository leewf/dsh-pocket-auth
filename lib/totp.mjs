import { createHmac, randomBytes } from 'node:crypto'

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const CODE_PATTERN = /^\d{6}$/

export function hotp(secret, counter, digits = 6) {
  if (!Buffer.isBuffer(secret) || secret.length === 0) throw new TypeError('secret must be a non-empty Buffer')
  if (typeof counter !== 'bigint' || counter < 0n) throw new TypeError('counter must be a non-negative bigint')
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) throw new RangeError('digits must be 6-8')
  const input = Buffer.alloc(8)
  input.writeBigUInt64BE(counter)
  const digest = createHmac('sha1', secret).update(input).digest()
  const offset = digest[digest.length - 1] & 0x0f
  const value = (digest.readUInt32BE(offset) & 0x7fffffff) % (10 ** digits)
  return String(value).padStart(digits, '0')
}

export function base32Encode(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) throw new TypeError('bytes must be a non-empty Buffer')
  let output = ''
  let buffer = 0
  let bits = 0
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      output += BASE32_ALPHABET[(buffer >> bits) & 31]
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(buffer << (5 - bits)) & 31]
  return output
}

export function base32Decode(value) {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Z2-7]+$/i.test(value)) throw new TypeError('invalid Base32 secret')
  let buffer = 0
  let bits = 0
  const output = []
  for (const char of value.toUpperCase()) {
    buffer = (buffer << 5) | BASE32_ALPHABET.indexOf(char)
    bits += 5
    if (bits >= 8) {
      bits -= 8
      output.push((buffer >> bits) & 0xff)
    }
  }
  return Buffer.from(output)
}

export function createSecret() {
  return base32Encode(randomBytes(20))
}

export function totp(secret, nowMs = Date.now()) {
  const step = BigInt(Math.floor(nowMs / 1000 / 30))
  return { code: hotp(secret, step), step }
}

export function matchTotp(secret, code, nowMs = Date.now(), window = 1) {
  if (!CODE_PATTERN.test(code) || !Number.isInteger(window) || window < 0 || window > 2) return null
  const current = BigInt(Math.floor(nowMs / 1000 / 30))
  for (let offset = -window; offset <= window; offset += 1) {
    const step = current + BigInt(offset)
    if (step >= 0n && hotp(secret, step) === code) return step
  }
  return null
}

export function buildOtpAuthUri(secret, instanceLabel = 'DSH') {
  const label = `DSH Pocket:${instanceLabel}`
  const params = new URLSearchParams({
    secret: base32Encode(secret),
    issuer: 'DSH Pocket',
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  })
  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`
}
