export function renderLoginPage({
  protocol = 'https',
  error = null,
  retryAfter = 0,
} = {}) {
  const isHttp = protocol === 'http'
  let errMsg = ''
  if (error === 'locked') {
    errMsg = `尝试次数过多，请在 ${retryAfter} 秒后再试 | Too many attempts, retry after ${retryAfter}s`
  } else if (error === 'invalid_code') {
    errMsg = '验证码错误或已过期，请核对手机 Aegis 时间后重试 | Invalid or expired code'
  } else if (error) {
    errMsg = String(error)
  }

  const notice = isHttp
    ? `<div class="warn">⚠️ 当前连接为未加密连接（HTTP），会话有效期固定为 24 小时（重启立即失效）。建议使用 HTTPS 获得最佳安全防护。</div>`
    : `<div class="info">🛡️ 当前连接为安全连接（HTTPS），会话有效期 30 天（重启立即失效）。</div>`

  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
  <title>DSH Pocket · 动态安全验证</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0f172a;
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      padding: 16px;
    }
    .card {
      width: 100%;
      max-width: 380px;
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 16px;
      padding: 32px 24px;
      text-align: center;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      background: #3b82f6;
      color: #fff;
      font-size: 12px;
      font-weight: 600;
      border-radius: 9999px;
      margin-bottom: 12px;
    }
    h1 { font-size: 20px; font-weight: 700; margin-bottom: 8px; }
    p { font-size: 13px; color: #94a3b8; line-height: 1.5; margin-bottom: 20px; }
    .err {
      color: #ef4444;
      font-size: 13px;
      min-height: 20px;
      margin-bottom: 16px;
      font-weight: 500;
    }
    .warn {
      background: rgba(245, 158, 11, 0.15);
      border: 1px solid #f59e0b;
      color: #fcd34d;
      font-size: 12px;
      padding: 10px;
      border-radius: 8px;
      margin-bottom: 18px;
      text-align: left;
      line-height: 1.4;
    }
    .info {
      background: rgba(59, 130, 246, 0.15);
      border: 1px solid #3b82f6;
      color: #93c5fd;
      font-size: 12px;
      padding: 8px;
      border-radius: 8px;
      margin-bottom: 18px;
      text-align: left;
    }
    input[type="text"] {
      width: 100%;
      height: 52px;
      background: #0f172a;
      border: 2px solid #475569;
      border-radius: 10px;
      color: #fff;
      font-size: 26px;
      font-weight: bold;
      letter-spacing: 12px;
      text-align: center;
      padding-left: 12px;
      outline: none;
      transition: border-color 0.2s;
      margin-bottom: 20px;
    }
    input[type="text"]:focus { border-color: #3b82f6; }
    button {
      width: 100%;
      height: 48px;
      background: #3b82f6;
      color: #fff;
      border: none;
      border-radius: 10px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
    }
    button:active { background: #2563eb; }
    .footer { margin-top: 20px; font-size: 12px; color: #64748b; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">Aegis 2FA</div>
    <h1>安全口令验证</h1>
    <p>请输入手机 Aegis 验证器中显示的 6 位动态验证码进入系统</p>
    ${notice}
    <div class="err">${errMsg}</div>
    <form method="POST" action="/pocket-auth/verify">
      <input
        name="code"
        type="text"
        inputmode="numeric"
        pattern="[0-9]*"
        maxlength="6"
        autocomplete="one-time-code"
        placeholder="••••••"
        autofocus
        required
      >
      <button type="submit">立即验证</button>
    </form>
    <div class="footer">DeepSeek Harness · Pocket Auth</div>
  </div>
</body>
</html>`
}
