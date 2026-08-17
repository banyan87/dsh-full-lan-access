# dsh-full-lan-access

为 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（DSH）提供安全局域网访问。这是一个即插即用的 Cordis 插件：在局域网开放一个**受保护的网关**，反向代理到 DSH Web 界面 —— 支持 CIDR 白名单、密码认证（scrypt）、会话令牌、暴力破解限流、可选 TLS、WebSocket 隧道与 JSON 行审计日志。

> ⚠️ **安全第一。** DSH 自身的 Web 服务器始终只绑定 `127.0.0.1`。本插件绝不裸暴露它：所有局域网请求必须先通过网关的 IP 策略，非本机客户端还必须完成密码登录，才会被流转到 DSH。

## 功能一览

| 能力 | 说明 |
| --- | --- |
| 🛡️ IP 白名单 / 黑名单 | IPv4 + IPv6 CIDR 匹配；拒绝规则永远优先；自动归一化 IPv4-mapped 地址 |
| 🔑 密码认证 | scrypt 哈希（`scrypt$N$r$p$salt$hash`，遵循 OWASP 交互登录建议），常量时间比较，登录表单带 CSRF 防护 |
| 🎟️ 会话令牌 | 256 位随机令牌，只持久化 SHA-256 摘要（令牌本身永不落盘），TTL + 最大会话数淘汰，网关重启后会话仍有效 |
| 🚦 限流 | 按 IP 的登录尝试限流与锁定，另可选全局限流 |
| 🔒 本机免密 | localhost 客户端直接放行（可配置）—— 本机 `http://127.0.0.1:3081` 零摩擦 |
| 🚫 代理头拒绝 | 永不信任 `X-Forwarded-For` / `X-Real-IP` / `Forwarded` / `Via` 等，默认直接拒绝携带此类头的请求 |
| 🔐 TLS | 可选 HTTPS：使用自有证书，或零依赖自动生成自签名 ECDSA 证书（持久化在状态目录） |
| 🔌 WebSocket 代理 | DSH 客户端 RPC 的 WebSocket 同样经过鉴权检查后被隧道转发 |
| 📜 审计日志 | JSON 行格式记录放行/拒绝/认证/限流/代理事件，输出到 DSH 日志器和/或文件 |
| 🧰 运维 CLI | `dsh-lan-gate hash-password`、`verify`、`cidr`、`check-config` |
| 🩺 状态 API | `GET /__lan_gate/status`（同时注册在 DSH 自身 Web 服务器上） |
| 🧩 DSH 原生 | Cordis `Service`（`lanAccess`），完整生命周期、Config schema、失败即关闭的启动校验、兼容 Loader 组合加载 |

## 快速开始

```bash
# 1. 安装到 web profile（转发给 pnpm）
dsh plugin --profile web add dsh-full-lan-access

# 2. 生成密码哈希
npx dsh-lan-gate hash-password            # 交互式输入；也可把密码作为参数传入

# 3. 在 $DSH_HOME/profiles/web/cordis.patch.yml 中加入配置行
#    （参见 examples/cordis.patch.example.yml）

# 4. 重启 dsh web，然后在其他设备打开 http://<你的局域网IP>:3081
```

局域网内未登录的浏览器会被重定向到网关登录页；认证通过的客户端被代理到 DSH Web 界面（含 WebSocket 连接）。在 DSH 宿主机上访问 `http://127.0.0.1:3081` 无需登录（本机免密）。

## 文档

- [安装指南](docs/installation.md) — dsh plugin 集成、cordis.yml 配置行、验证步骤
- [配置参考](docs/configuration.md) — 全部选项与默认值
- [架构说明](docs/architecture.md) — 组件、请求流程、威胁模型
- [安全模型](docs/security.md) — 安全设计、加固建议、已知限制
- [API 说明](docs/api.md) — 网关端点、Cookie 语义、状态报文
- [故障排查](docs/troubleshooting.md) — 常见问题
- [SECURITY.md](SECURITY.md) — 漏洞报告流程

## 开发

```bash
npm install          # 开发依赖（@deepseek-ai/cordis、schemastery、loader）
npm test             # 60+ 项单元与集成测试（node:test，零额外运行时依赖）
npm run smoke        # 针对运行中的 DSH 做实机冒烟测试（默认 127.0.0.1:3080）
```

测试覆盖：CIDR 匹配器、scrypt 哈希、会话持久化、限流器、请求策略、X.509 证书生成（以完整 TLS 握手验证）、完整网关管线（代理、认证、CSRF、锁定、WebSocket 隧道、TLS），以及 Cordis 插件契约（Service 生命周期、失败关闭校验、Loader 组合加载）。

## License

MIT
