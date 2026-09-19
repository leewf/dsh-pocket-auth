/**
 * dsh-pocket-auth 浏览器前端：Aegis TOTP 动态口令设置与二维码绑定面板
 */
window.__ModuleLoader__.load({
  id: "dsh-pocket-auth",
  factory: (require) => {
    const module = { exports: {} };
    const exports = module.exports;
    const React = require("react");
    const { useState, useEffect, useCallback } = React;
    const h = React.createElement;

    const API_BASE = "/pocket-auth-admin";

    function PocketAuthSettingsView() {
      const [loading, setLoading] = useState(true);
      const [status, setStatus] = useState(null);
      const [binding, setBinding] = useState(null);
      const [code, setCode] = useState("");
      const [msg, setMsg] = useState(null);
      const [error, setError] = useState(null);
      const [remoteBlockInfo, setRemoteBlockInfo] = useState(null); // 'remote' | 'origin' | null
      const [submitting, setSubmitting] = useState(false);

      const fetchStatus = useCallback(async () => {
        try {
          setLoading(true);
          setError(null);
          setRemoteBlockInfo(null);
          const res = await fetch(`${API_BASE}/status`);
          if (res.ok) {
            const data = await res.json();
            setStatus(data);
          } else {
            let errorData = null;
            try {
              errorData = await res.json();
            } catch {}
            const errorCode = errorData?.error;
            if (res.status === 403 && (errorCode === "admin_forbidden_remote" || errorCode === "forbidden_remote")) {
              setRemoteBlockInfo("remote");
            } else if (res.status === 403 && errorCode === "forbidden_origin") {
              setRemoteBlockInfo("origin");
            } else {
              setError(errorCode ? `获取认证状态失败: ${errorCode}` : `获取认证状态失败 (HTTP ${res.status})`);
            }
          }
        } catch (e) {
          setError(e.message || "请求状态异常");
        } finally {
          setLoading(false);
        }
      }, []);

      useEffect(() => {
        fetchStatus();
      }, [fetchStatus]);

      const handleStartBinding = async () => {
        try {
          setError(null);
          setMsg(null);
          setSubmitting(true);
          const res = await fetch(`${API_BASE}/binding/start`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ owner: "admin-local" }),
          });
          const data = await res.json().catch(() => ({}));
          if (res.ok) {
            setBinding(data);
            setCode("");
          } else {
            if (res.status === 403 && (data.error === "admin_forbidden_remote" || data.error === "forbidden_remote")) {
              setError("操作被拒绝：动态口令绑定与二维码查看仅限在电脑本机（127.0.0.1）进行。");
            } else {
              setError(data.error || `生成绑定失败 (HTTP ${res.status})`);
            }
          }
        } catch (e) {
          setError(e.message || "网络请求异常");
        } finally {
          setSubmitting(false);
        }
      };

      const handleConfirmBinding = async () => {
        if (!binding?.bindingId) {
          setError("绑定会话已失效，请重新点击扫码绑定");
          return;
        }
        if (!code || code.length !== 6) {
          setError("请输入 6 位动态验证码");
          return;
        }
        try {
          setError(null);
          setMsg(null);
          setSubmitting(true);
          const res = await fetch(`${API_BASE}/binding/confirm`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              owner: "admin-local",
              bindingId: binding.bindingId,
              code: code.trim(),
            }),
          });
          const data = await res.json();
          if (res.ok) {
            setMsg("🎉 Aegis 绑定成功并已激活！后续远程访问请使用动态口令登录。");
            setBinding(null);
            setCode("");
            await fetchStatus();
          } else {
            setError(data.error || "验证码错误或绑定超时");
          }
        } catch (e) {
          setError(e.message || "确认绑定异常");
        } finally {
          setSubmitting(false);
        }
      };

      if (loading && !status && !remoteBlockInfo) {
        return h("div", { style: { padding: 24, color: "#64748b" } }, "正在加载安全认证状态...");
      }

      const isRemote = remoteBlockInfo === "remote";
      const isOriginBlocked = remoteBlockInfo === "origin";
      const isActive = status?.state === "active";

      return h(
        "div",
        { style: { padding: "24px 32px", maxWidth: 760, margin: "0 auto", fontFamily: "sans-serif" } },
        // 标题区
        h(
          "div",
          { style: { marginBottom: 24, paddingBottom: 16, borderBottom: "1px solid var(--dsw-alias-border-l2, #334155)" } },
          h(
            "h2",
            { style: { fontSize: 20, fontWeight: 700, margin: "0 0 8px 0", display: "flex", alignItems: "center", gap: 8 } },
            "🛡️ 手机动态口令认证 (Aegis TOTP)"
          ),
          h(
            "p",
            { style: { margin: 0, fontSize: 13, color: "#94a3b8", lineHeight: 1.5 } },
            "基于 RFC 6238 标准的手机端动态口令认证插件。兼容 Aegis Authenticator 及 Google Authenticator，每 30 秒轮转 6 位动态码，全面替代默认简易密码，保障远程访问绝对安全。"
          )
        ),

        // 安全隔离指引卡片 (移动端/远程访问)
        isRemote &&
          h(
            "div",
            {
              style: {
                background: "rgba(59, 130, 246, 0.12)",
                border: "1px solid rgba(59, 130, 246, 0.35)",
                borderRadius: 10,
                padding: "16px 20px",
                marginBottom: 20,
                fontSize: 13,
                lineHeight: 1.6,
              },
            },
            h(
              "div",
              {
                style: {
                  fontWeight: 600,
                  fontSize: 14,
                  color: "#60a5fa",
                  marginBottom: 6,
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                },
              },
              "🛡️ 安全隔离机制生效中（当前为移动端 / 远程访问）"
            ),
            h(
              "div",
              { style: { color: "#cbd5e1" } },
              "为了防止动态口令密钥与绑定二维码通过局域网或公网传输泄露，管理面板已开启 Fail-Closed 本地隔离守护，仅限在电脑本机通过环回接口访问。"
            ),
            h(
              "div",
              { style: { marginTop: 6, color: "#34d399", fontWeight: 500 } },
              "✅ 当前手机端动态口令防护依然处于正常生效状态，登录时正常校验 6 位动态码。"
            ),
            h(
              "div",
              { style: { marginTop: 6, color: "#94a3b8" } },
              "如需重新绑定新验证器或查看二维码，请在电脑本机浏览器打开 http://127.0.0.1:3080 进入此设置页。"
            )
          ),

        // 来源域名拦截指引卡片
        isOriginBlocked &&
          h(
            "div",
            {
              style: {
                background: "rgba(245, 158, 11, 0.12)",
                border: "1px solid rgba(245, 158, 11, 0.35)",
                borderRadius: 10,
                padding: "14px 18px",
                marginBottom: 20,
                fontSize: 13,
                lineHeight: 1.6,
              },
            },
            h(
              "div",
              {
                style: {
                  fontWeight: 600,
                  fontSize: 14,
                  color: "#fbbf24",
                  marginBottom: 6,
                },
              },
              "⚠️ 访问来源域名被安全拦截"
            ),
            h(
              "div",
              { style: { color: "#cbd5e1" } },
              "动态口令管理面板仅允许从电脑本机 http://127.0.0.1:3080 或 http://localhost:3080 访问。如果您当前使用了局域网 IP 或自定义域名，请改用 127.0.0.1 访问。"
            )
          ),

        // 普通提示信息与错误卡片
        msg &&
          h(
            "div",
            {
              style: {
                background: "rgba(16, 185, 129, 0.15)",
                border: "1px solid #10b981",
                color: "#34d399",
                padding: "10px 14px",
                borderRadius: 8,
                marginBottom: 16,
                fontSize: 13,
              },
            },
            msg
          ),
        error &&
          h(
            "div",
            {
              style: {
                background: "rgba(239, 68, 68, 0.15)",
                border: "1px solid #ef4444",
                color: "#f87171",
                padding: "10px 14px",
                borderRadius: 8,
                marginBottom: 16,
                fontSize: 13,
              },
            },
            error
          ),

        // 状态卡片
        h(
          "div",
          {
            style: {
              background: "var(--dsw-alias-bg-layer-2, #1e293b)",
              border: "1px solid var(--dsw-alias-border-l2, #334155)",
              borderRadius: 12,
              padding: 20,
              marginBottom: 24,
            },
          },
          h(
            "div",
            { style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
            h(
              "div",
              null,
              h("div", { style: { fontSize: 14, fontWeight: 600, marginBottom: 4 } }, "当前防护状态"),
              h(
                "div",
                { style: { fontSize: 13, color: "#94a3b8" } },
                isRemote
                  ? "已启用动态口令保护（移动端安全隔离模式，敏感配置已在本地锁定）"
                  : isActive
                  ? `已启用动态口令保护（凭据版本: v${status.credentialVersion}）`
                  : "尚未完成手机绑定（未配置时远程请求将被安全拒绝）"
              )
            ),
            h(
              "span",
              {
                style: {
                  padding: "4px 12px",
                  borderRadius: 9999,
                  fontSize: 12,
                  fontWeight: 600,
                  background: isRemote ? "#10b981" : isActive ? "#10b981" : "#f59e0b",
                  color: "#fff",
                },
              },
              isRemote ? "运行中 · 远程受保护" : isActive ? "运行中 · 安全" : "未绑定"
            )
          )
        ),

        // 绑定动作区
        isRemote
          ? h(
              "div",
              { style: { display: "flex", alignItems: "center", gap: 12 } },
              h(
                "button",
                {
                  disabled: true,
                  style: {
                    padding: "10px 18px",
                    background: "#334155",
                    color: "#94a3b8",
                    border: "1px solid #475569",
                    borderRadius: 8,
                    fontSize: 14,
                    fontWeight: 600,
                    cursor: "not-allowed",
                  },
                },
                "🔒 绑定与密钥重置仅限电脑本机操作"
              ),
              h("span", { style: { fontSize: 13, color: "#94a3b8" } }, "如需更换手机验证器，请在电脑本机打开 http://127.0.0.1:3080")
            )
          : !binding
          ? h(
              "div",
              null,
              h(
                "button",
                {
                  onClick: handleStartBinding,
                  disabled: submitting,
                  style: {
                    padding: "10px 20px",
                    background: "#3b82f6",
                    color: "#fff",
                    border: "none",
                    borderRadius: 8,
                    fontSize: 14,
                    fontWeight: 600,
                    cursor: submitting ? "not-allowed" : "pointer",
                  },
                },
                isActive ? "重新绑定新验证器" : "扫码绑定 Aegis"
              )
            )
          : h(
              "div",
              {
                style: {
                  background: "var(--dsw-alias-bg-layer-2, #1e293b)",
                  border: "1px solid var(--dsw-alias-border-l2, #334155)",
                  borderRadius: 12,
                  padding: 24,
                },
              },
              h("h3", { style: { fontSize: 16, fontWeight: 600, margin: "0 0 12px 0" } }, "步骤 1: 使用手机扫码或手动添加"),
              h("p", { style: { fontSize: 13, color: "#94a3b8", marginBottom: 16 } }, "打开手机 Aegis Authenticator，点击右下角加号选择「扫描二维码」："),

              // 二维码展示
              binding.qrDataUrl
                ? h(
                    "div",
                    { style: { textAlign: "center", marginBottom: 16 } },
                    h("img", {
                      src: binding.qrDataUrl,
                      alt: "Aegis OTPAuth QR",
                      style: { width: 200, height: 200, borderRadius: 8, background: "#fff", padding: 8 },
                    })
                  )
                : h("div", { style: { color: "#f59e0b", fontSize: 13, marginBottom: 12 } }, "未检测到图片库，请使用下方密钥手动添加"),

              // 备用手动密钥
              h(
                "div",
                { style: { background: "#0f172a", padding: 12, borderRadius: 8, marginBottom: 20, fontSize: 13 } },
                h("div", { style: { color: "#64748b", marginBottom: 4 } }, "手动输入密钥 (Base32 Secret)："),
                h("code", { style: { color: "#38bdf8", fontWeight: "bold", letterSpacing: 2, wordBreak: "break-all" } }, binding.secret)
              ),

              h("h3", { style: { fontSize: 16, fontWeight: 600, margin: "0 0 12px 0" } }, "步骤 2: 输入手机上显示的 6 位验证码以激活"),
              h(
                "div",
                { style: { display: "flex", gap: 12, alignItems: "center", marginBottom: 16 } },
                h("input", {
                  type: "text",
                  value: code,
                  onChange: (e) => setCode(e.target.value),
                  maxLength: 6,
                  placeholder: "000000",
                  style: {
                    width: 160,
                    height: 40,
                    background: "#0f172a",
                    border: "1px solid #475569",
                    borderRadius: 8,
                    color: "#fff",
                    fontSize: 20,
                    fontWeight: "bold",
                    textAlign: "center",
                    letterSpacing: 4,
                  },
                }),
                h(
                  "button",
                  {
                    onClick: handleConfirmBinding,
                    disabled: submitting || code.length !== 6,
                    style: {
                      height: 40,
                      padding: "0 18px",
                      background: "#10b981",
                      color: "#fff",
                      border: "none",
                      borderRadius: 8,
                      fontWeight: 600,
                      cursor: submitting || code.length !== 6 ? "not-allowed" : "pointer",
                    },
                  },
                  submitting ? "正在验证..." : "确认绑定并激活"
                ),
                h(
                  "button",
                  {
                    onClick: () => { setBinding(null); setCode(""); },
                    style: {
                      height: 40,
                      padding: "0 14px",
                      background: "transparent",
                      color: "#94a3b8",
                      border: "1px solid #475569",
                      borderRadius: 8,
                      cursor: "pointer",
                    },
                  },
                  "取消"
                )
              )
            )
      );
    }

    function apply(ctx) {
      console.log("[dsh-pocket-auth] 正在加载手机动态口令认证前端插件...");

      if (ctx.slots && typeof ctx.slots.inject === "function") {
        // 1. 注册为主设置项 (一级导航设置页)
        ctx.slots.inject("settings.section", function () {
          try {
            return ctx.slots.register(
              {
                name: "settings.section",
                id: "pocket-auth",
                order: 38,
                label: function () { return "动态口令认证"; },
              },
              PocketAuthSettingsView
            );
          } catch (e) {
            console.warn("[dsh-pocket-auth] 注册 settings.section 异常:", e);
            return function () {};
          }
        });

        // 2. 备用：同时注册进插件设置 Tab 槽位 (双重保障)
        ctx.slots.inject("settings.plugins.tab", function () {
          try {
            return ctx.slots.register(
              {
                name: "settings.plugins.tab",
                id: "pocket-auth-tab",
                order: 38,
                label: function () { return "动态口令认证"; },
              },
              PocketAuthSettingsView
            );
          } catch (e) {
            return function () {};
          }
        });
      }

      console.log("[dsh-pocket-auth] 动态口令认证前端配置界面挂载就绪。");
    }

    exports.name = "dsh-pocket-auth";
    exports.apply = apply;
    exports.inject = ["slots"];
    return module.exports;
  },
});
