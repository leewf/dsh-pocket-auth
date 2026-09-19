# dsh-pocket-auth

DeepSeek Harness (DSH) 手机端动态口令认证扩展插件 (Aegis / Google Authenticator TOTP)。

## 🌟 核心功能

1. **RFC 6238 / RFC 4226 兼容**：完全兼容 Aegis Authenticator 及 Google Authenticator，基于时间步长（30 秒）计算 6 位动态验证码。
2. **纯动态码替代方案**：登录远程 DSH Pocket 时以 6 位动态码作为访问通行证，彻底避免固定 PIN 泄露与暴力破解风险。
3. **二阶段绑定与本地管理隔离**：
   - 必须通过电脑本机（`127.0.0.1` 环回接口）在 DSH 设置页查看绑定二维码及密钥。
   - 远程请求禁止访问管理员绑定路由（`/pocket-auth-admin/*` 返回 403 Forbidden），含 cloudflared 回连。
   - 扫码后必须在网页输入手机显示的当前有效验证码完成二次确认，才正式激活存储。
   - 确认接口解析 Node HTTP 原始 JSON 流（不依赖 `req.json()`）。
4. **单步防重放与持久化**：已消费的有效时间步原子记录到磁盘，同一 30 秒周期内的验证码不可重复使用；重启 DSH 服务后依然保持防重放保护。
5. **双轨会话安全策略（局域网 + 外网共用同一 TOTP）**：
   - **HTTPS（公网隧道）**：签发 30 天 Cookie（`HttpOnly; Secure; SameSite=Lax`）；只信 loopback 上游的 `X-Forwarded-Proto`。
   - **HTTP（局域网直连）**：签发固定 24 小时 Cookie（`HttpOnly; SameSite=Lax`），不滑动续期，登录页显式警示安全风险。
   - **重启即失效**：DSH 进程重启后内存会话表重置，所有旧 Cookie 统一失效。
6. **阶梯限速防暴破**：
   - 5 次连续失败锁定 30 秒（跳过一个 TOTP 周期）；
   - 10 次失败锁定 3 分钟；
   - 15 次失败锁定 15 分钟；
   - 全局请求速率预算限制。
7. **Fail-Closed 故障闭环**：未绑定密钥或插件异常时，远程入口一律返回 503 拒绝访问，绝不静默降级或穿透至上游。

## 📁 项目目录结构

```text
plugin/dsh-pocket-auth/
├── client.js               # DSH 设置页前端面板（展示二维码与绑定交互）
├── client/
│   └── login.mjs           # 移动端沉浸式 6 位验证码输入登录页面
├── lib/
│   ├── index.js            # Cordis 插件入口（注册路由与 pocketAuth 服务）
│   ├── admin.mjs           # 本地管理员管理接口（Origin 校验与二阶段绑定）
│   ├── credentials.mjs     # 凭证状态机与防重放原子消费队列
│   ├── limiter.mjs         # 阶梯限速器与全局限流
│   ├── provider.mjs        # 核心 AuthProvider（统一 HTTP 与 WebSocket 门禁）
│   ├── sessions.mjs        # 内存双轨会话管理器
│   ├── store.mjs           # 密钥原子文件持久化（临时文件 + rename）
│   └── totp.mjs            # RFC 4226 HOTP / RFC 6238 TOTP / Base32 / OTPAuth URI
├── test/                   # 完整单元测试、集成测试与 E2E 验证套件（28 项测试）
├── cordis.patch.yml        # Cordis 插件配置
└── package.json            # 含显式依赖 qrcode（绑定二维码本地生成）
```

## 依赖说明

- `qrcode`：本包**显式依赖**，用于本机生成 Aegis 扫码 PNG Data URL。插件经 junction 解析到工作区真实路径后，**不能**借用 `profiles/web/node_modules` 的传递依赖；安装后需在插件目录执行 `npm install`。

## 🧪 自动化测试验证

运行完整测试套件：
```bash
npm test
```
包含：
- RFC 4226 官方向量测试（Counter 0, 1）
- RFC 6238 时间窗口与漂移容错（±1 step）
- Base32 编解码往返无损测试
- OTPAuth URI 生成与参数校验
- 密钥安全存储与损坏容错
- 二阶段绑定与防重放持久化
- 内存会话管理、双轨 TTL 与重启失效
- 滑动窗口阶梯限速与请求预算
- 登录页渲染与 HTTP/HTTPS 差异化警示
- Admin 本地隔离与非同源 403 拦截
- AuthProvider HTTP/WS 门禁拦截与 Cookie 签发放行
- Pocket 调度器与 AuthProvider 协同 E2E 测试
