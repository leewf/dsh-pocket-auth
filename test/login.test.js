import test from 'node:test'
import assert from 'node:assert/strict'
import { renderLoginPage } from '../client/login.mjs'

test('登录页渲染：包含 6 位输入框、OTP 属性与表单动作', () => {
  const html = renderLoginPage({ protocol: 'https', error: null })
  assert.match(html, /<form[^>]+action="\/pocket-auth\/verify"/)
  assert.match(html, /inputmode="numeric"/)
  assert.match(html, /maxlength="6"/)
  assert.match(html, /autocomplete="one-time-code"/)
  assert.match(html, /Aegis/)
  // https 下不应出现明文警告
  assert.doesNotMatch(html, /未加密连接/)
})

test('登录页渲染：HTTP 协议下明确提示未加密与 24 小时限制', () => {
  const html = renderLoginPage({ protocol: 'http', error: null })
  assert.match(html, /未加密连接/)
  assert.match(html, /24 小时/)
})

test('登录页渲染：错误与锁定提示', () => {
  const errHtml = renderLoginPage({ protocol: 'https', error: 'invalid_code' })
  assert.match(errHtml, /验证码错误/)

  const lockHtml = renderLoginPage({ protocol: 'https', error: 'locked', retryAfter: 30 })
  assert.match(lockHtml, /30/)
})
