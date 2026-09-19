import test from 'node:test'
import assert from 'node:assert/strict'
import { hotp, base32Encode, base32Decode, matchTotp, buildOtpAuthUri } from '../lib/totp.mjs'

test('RFC 4226 counter 0 produces 755224', () => {
  const secret = Buffer.from('12345678901234567890')
  assert.equal(hotp(secret, 0n), '755224')
})

test('RFC 4226 counter 1 produces 287082', () => {
  const secret = Buffer.from('12345678901234567890')
  assert.equal(hotp(secret, 1n), '287082')
})

test('Base32 encodes and decodes the secret without losing bytes', () => {
  const secret = Buffer.from('12345678901234567890')
  assert.deepEqual(base32Decode(base32Encode(secret)), secret)
})

test('TOTP accepts current step and one adjacent step only', () => {
  const secret = Buffer.from('12345678901234567890')
  assert.equal(matchTotp(secret, '287082', 30_000), 1n)
  assert.equal(matchTotp(secret, '287082', 60_000), 1n)
  assert.equal(matchTotp(secret, '287082', 90_000), null)
})

test('OTPAuth URI uses matching issuer and six digit settings', () => {
  const uri = buildOtpAuthUri(Buffer.from('12345678901234567890'), 'workstation')
  const parsed = new URL(uri)
  assert.equal(parsed.protocol, 'otpauth:')
  assert.equal(parsed.hostname, 'totp')
  assert.equal(parsed.searchParams.get('issuer'), 'DSH Pocket')
  assert.equal(parsed.searchParams.get('algorithm'), 'SHA1')
  assert.equal(parsed.searchParams.get('digits'), '6')
  assert.equal(parsed.searchParams.get('period'), '30')
})
