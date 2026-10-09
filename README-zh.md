# opentunnel-aio-relay

[English](README.md) | 中文

[OpenTunnel](https://github.com/anomalyco/opentunnel) 协议（"盲 TLS 隧道"，注重隐私的 ngrok 替代品）的单二进制自托管中转服务器。

它用**一台 VPS 上的一个静态二进制**，替代官方的 Cloudflare 部署（Worker + Durable Objects + 证书 Workflow + 外部 TCP 中转）。现有客户端——Rust CLI（`opentunnel`）和 TypeScript SDK——无需改动：把它们指向你的服务器即可。

## 工作原理

单个进程监听一个 TCP 端口（默认 443），只看 ClientHello 按 TLS SNI 分流：

```
:443 ──看 SNI──┬─ SNI == tunnel.example.com ──▶ 本地终止 TLS ──▶ HTTP API + bridge WebSocket
               └─ SNI == *.tunnel.example.com ──▶ 盲转发 ──▶ bridge WS ──▶ 客户端 ──▶ 本地应用
```

- **API 分支**：用自动签发的 API 域名证书在本地终止 TLS；提供开通 API 和 bridge WebSocket。
- **隧道分支**：字节*加密*转发。TLS 由客户端在自己的机器上终止，和官方服务完全一样——这台服务器永远看不到明文（"盲"）。

Cloudflare 概念一一对应：

| 官方托管版 | 本服务器 |
|---|---|
| Worker HTTP API | axum 路由，路径和结构相同 |
| 每个隧道的 Durable Object | 进程内 session + SQLite 行 |
| DO alarm（续签定时器） | 后台每小时任务 |
| Certificate Workflow | 异步 ACME 任务（RFC 8555，DNS-01） |
| AWS TCP 中转 | 没了——二进制直接监听 443 |

## 快速开始

### 1. DNS

把下面这些指向你的 VPS（全部 **DNS only**，不要开代理）：

```
tunnel.example.com      A    203.0.113.10
*.tunnel.example.com    A    203.0.113.10
```

### 2. 凭证

- **Cloudflare API token**，对该 zone 有 DNS 编辑权限（用于 ACME DNS-01）。
  证书默认来自 **Let's Encrypt**——不需要额外注册账号。

### 3. 运行

```bash
export OT_DOMAIN=tunnel.example.com
export OT_CF_TOKEN=your-cloudflare-token
export OT_CF_ZONE_ID=your-zone-id
# 可选：先用 Let's Encrypt staging 测试
# export OT_ACME_URL=https://acme-staging-v02.api.letsencrypt.org/directory

./opentunnel-relay
# 或者：./opentunnel-relay --domain tunnel.example.com --cf-token ...（完整列表看 --help）
```

首次启动会通过 ACME DNS-01 为 `tunnel.example.com` 签发 TLS 证书，存到 `./data/`（和 `relay.db` 在一起）。不用手动处理证书。

### 4. 使用

```bash
export OPENTUNNEL_API=https://tunnel.example.com
opentunnel route add 3000
# → https://<random>.<tunnel-id>.tunnel.example.com
```

建议：用单独的客户端 profile（`--profile home` / `OPENTUNNEL_PROFILE`），别覆盖掉你在官方服务上用的隧道身份。

## 配置

所有选项都是 flag 或 `OT_*` 环境变量（完整列表看 `--help`）：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `OT_DOMAIN` | —（必填） | 公网域名，如 `tunnel.example.com` |
| `OT_LISTEN` | `0.0.0.0:443` | TCP 监听地址 |
| `OT_DATA_DIR` | `./data` | SQLite 数据库 + API 证书存放目录 |
| `OT_CF_TOKEN` / `OT_CF_ZONE_ID` | —（必填） | Cloudflare DNS，用于 ACME 验证 |
| `OT_ACME_EAB_KID` / `OT_ACME_EAB_HMAC` | —（空） | 只给需要 EAB 的 CA 用（如 ZeroSSL） |
| `OT_ACME_URL` | Let's Encrypt 生产环境 | ACME 目录；测试用 `https://acme-staging-v02.api.letsencrypt.org/directory` |
| `OT_ACME_EMAIL` | `acme@localhost` | ACME 账号联系邮箱 |
| `OT_MAX_CONNECTIONS` | `1024` | 监听器上同时打开的连接数（API、bridge、访客 socket 都算）。超出的在 accept 时直接拒绝。`0` 表示不限制 |
| `OT_RESERVED_CONNECTIONS` | `64` | 在 `OT_MAX_CONNECTIONS` 里给访客 socket 禁止占用的预留位，保证访客满了 API 和 bridge 还能连进来。必须小于 `OT_MAX_CONNECTIONS`（除非后者为 `0`） |
| `OT_MAX_CONNECTIONS_PER_IP` | `64` | 单个源地址同时可保持的 socket 数。IPv6 按 /64 统计。超出的在 accept 时拒绝。`0` 表示不限制 |
| `OT_STREAM_BUFFER_BYTES` | `2097152`（2 MiB） | 为还没读数据的访客暂存的数据量。落后超过这个量的访客会被以 `backpressure` 重置。最小 `65536` |
| `OT_STREAM_IDLE_SECS` | `3600`（1 小时） | 转发连接双向无字节多少秒后关闭，并以 `connection_terminated` 通知 bridge。`0` 关闭该限制；长时间静默的 SSH/WebSocket 会话可以调大 |
| `OT_MAX_TUNNELS` | `1000` | 存活隧道数（未删除的）。超限创建返回 `503`。`0` 表示不限制 |
| `OT_MAX_CERTS_PER_DAY` | `7` | 所有隧道 24 小时滚动窗口内的新证书订单数。续签永远不受限。`0` 表示不限制 |
| `OT_RATE_LIMIT_PER_HOUR` | `30` | 单个源地址每小时可调用隧道创建和证书绑定的次数。IPv6 按 /64 统计。`0` 表示不限制 |
| `OT_CREATE_ALLOW_CIDRS` | —（空：允许所有来源） | 允许创建隧道和绑定证书的 IPv4/IPv6 地址或 CIDR 段，逗号分隔 |

不可配置的固定限制：ClientHello 和 TLS 握手必须在 10 秒内完成，每个请求的 header 必须在 10 秒内到达。访客 ClientHello 发出后 15 秒内 bridge 还没发来第一个字节，该转发连接会被以 `connection_terminated` 重置；第一个字节到达后这个检查停止，静默流改由 `OT_STREAM_IDLE_SECS` 管。访客 10 秒内一个字节都不读、且有中转数据在等它，会被单独重置并标记 `backpressure`。除 bridge 的 WebSocket 升级外，每个 API 响应都带 `Connection: close`。单个 ACME 订单最多跑 10 分钟。ACME 和 Cloudflare 的调用 10 秒建连超时、30 秒总超时。

### 给慢访客的缓冲

每个转发连接有自己独立的 buffer，暂存访客还没读走的数据。bridge 的读循环从不等访客，所以一个停读的访客拖不慢其他连接，也拖不慢 bridge 的心跳。buffer 溢出的连接会被立即以 `backpressure` 重置，同时通知客户端。

协议本身没有按流的流量控制，所以中转没法只暂停一条连接而不影响其他。访客读得比 bridge 发得慢、且慢过 buffer 能撑的时间，就会被重置。给慢客户端做大文件传输可以调大 `OT_STREAM_BUFFER_BYTES`。最坏情况的 buffer 内存是 `OT_MAX_CONNECTIONS` 乘以 `OT_STREAM_BUFFER_BYTES`，默认值下是 2 GiB——按主机的内存把这两个一起配好。

### 连接数限制

每个 accept 到的 socket 都计入全局上限（`OT_MAX_CONNECTIONS`）和来源地址的份额（`OT_MAX_CONNECTIONS_PER_IP`）。SNI 指向隧道的 socket（访客）还额外占用访客名额，访客名额 = 全局上限减 `OT_RESERVED_CONNECTIONS`，这样访客满了预留位还留给 API 和 bridge。

需要注意的 trade-off：

- socket 按 TCP 对端地址统计。同一 NAT/代理后的客户端共用一个份额，中转前面架负载均衡会让所有客户端看起来像一个地址。这种部署把 `OT_MAX_CONNECTIONS_PER_IP` 调大或设为 `0`。
- 还没发 ClientHello 的 socket 只计入全局和按地址的上限。大批来自不同地址的这种 socket 能把全局池占满，直到 10 秒 ClientHello 超时把它们关掉。如果这对你的部署重要，在网络边缘做过滤或限流。

## 防滥用

`POST /api/tunnel` 不需要凭证，而每个建出来的隧道都能去订证书。所以开放的中转可能被批量建隧道、批量订证书。下面这些检查按顺序执行，每一项都可选。

1. **来源白名单**（`OT_CREATE_ALLOW_CIDRS`）：不在名单里的地址拿 `403`。
2. **限流**（`OT_RATE_LIMIT_PER_HOUR`）：按来源地址的固定一小时窗口。超限返回 `429` 并带 `Retry-After`。
3. **隧道上限**（`OT_MAX_TUNNELS`）：只有 `DELETE /api/tunnel/{id}` 能释放名额，闲置隧道不会自动回收。
4. **证书预算**（`OT_MAX_CERTS_PER_DAY`）：所有隧道 24 小时滚动窗口内的新订单数。续签永远放行。默认每天 7 张，保证不超 Let's Encrypt 每注册域名每周 50 张的限制。

需要注意的 trade-off：

- 白名单和限流都用 TCP 对端地址。中转不读 `X-Forwarded-For` 之类的 header。NAT 或负载均衡后面，所有客户端共用一个地址、也就是共用一份配额。
- 限流计数器在内存里，重启清零。表最多跟踪 65,536 个来源，满了之后新来源拿 `429`，直到旧窗口过期。

## systemd 示例

```ini
[Unit]
Description=opentunnel-relay
After=network-online.target

[Service]
Type=simple
User=opentunnel
WorkingDirectory=/opt/opentunnel-relay
EnvironmentFile=/opt/opentunnel-relay/secrets.env
ExecStart=/opt/opentunnel-relay/opentunnel-relay
Restart=on-failure
# 新建的数据库、WAL 和密钥文件保持私有。
UMask=0077
# 每个打开的连接占一个文件描述符。限制要大于
# OT_MAX_CONNECTIONS（默认 1024）并留余量；systemd 默认软限制
# 可能只有 1024。
LimitNOFILE=65536
# 443 是特权端口：
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

`secrets.env` 放 `OT_*` 变量（mode 600，属主为服务用户）。服务数据目录属主应为 `opentunnel` 且 mode 700；中转也会把 SQLite 数据库和 API 私钥限制为 mode 600。

## 证书

- **隧道证书**（`<id>.tunnel.example.com` + 通配符）：客户端提交 CSR 时按需签发。客户端私钥永远不出客户端的机器——服务器只见得到 CSR。
- **续签**：后台任务给 30 天内到期、且 90 天内活跃过的隧道续签，复用存着的 CSR（密钥不变）。拿着快到期证书来 attach 也会触发续签。
- **续签失败不会替换正在用的证书。** 隧道继续用当前证书服务到它过期。失败的尝试按指数退避重试：1 小时、2 小时、4 小时、8 小时，之后每 12 小时一次。
- **单个订单有时限**：ACME 订单必须在 10 分钟内完成（含 DNS 生效时间），失败时删掉它放的 DNS TXT 记录。重启时被打断的订单会在启动时重新排队。
- **API 证书**：首次启动时签发，之后只要还有效且覆盖 `OT_DOMAIN` 就复用。到期前在后台续签，新握手用新证书。续签失败的话，还有效的旧证书继续服务并记一条 warning 日志。

## 构建

```bash
cargo build --release
```

约 10 MB 的静态二进制（glibc）。完全静态的 musl 构建：

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

（全程用 ring 做 TLS crypto provider，所以 musl 能编过。）

## 测试

```bash
cargo test
```

- `tests/vectors.rs` —— 用从 `anomalyco/opentunnel` 拷来的 spec 向量（`spec/vectors`）校验路由合法性、SNI 路由、数据帧编码和控制消息往返。通过只说明这些向量对得上，不是完整的一致性测试。
- `tests/e2e.rs` —— 真 socket 全链路：TCP 接入 → SNI 路由 → API TLS → REST 开通 → bridge WebSocket attach → 代理 `open`，含半关闭响应投递、多 bridge 隔离、删隧道后立即断开。还覆盖开通管控、隧道和连接上限（全局、按地址、访客份额）、header 和空闲超时、bridge 停滞和溢出处理。
- 单元测试：ClientHello 解析、CSR 校验（含篡改签名）、CIDR 解析和限流、数据库和 bridge 状态机。
- `.github/scripts/test-fetch-official-client.sh` —— CI 下载脚本的离线检查：digest 对得上才成功，digest 对不上或缺失就 fail-closed，什么都不解压。
- `memory_probe_reports_rss_per_stage`（`#[ignore]`）—— 运行时内存探针：在进程内启动中转，分阶段加压（隧道、连接、stream buffer）并打印每阶段的 RSS。
  `cargo test --test e2e memory_probe -- --ignored --nocapture`

### 用官方客户端做端到端（CI）

`integration` 任务从 GitHub release 下载官方 `opentunnel` CLI。`OFFICIAL_CLIENT_RELEASE` 选版本：`latest`（默认）或 `v0.4.0` 这样的 tag 来 pin。`.github/scripts/fetch-official-client.sh` 通过 GitHub API 解析该 release，读取 GitHub 给 `opentunnel-linux-x64.tar.gz` 报告的 sha256 digest，下载文件对不上就拒绝运行。解析到的 tag 会打到日志里。上游不发布 checksum 文件，所以这个 API digest 就是完整性依据。它防传输损坏和中途替换，防不了上游 release 本身被黑——因为 asset 和 digest 都是 GitHub 给的。

任务接着启动本中转跑一条真隧道：HTTP API 开通 → bridge WebSocket attach → 走客户端终止的 SNI 路由 TLS 连接抓一个页面。需要真 Let's Encrypt 证书（官方客户端只认内置的 Mozilla 根），所以这里会做真实的 ACME DNS-01 签发——每次跑 2 张证书。

每次跑用自己的 hostname：`run-<run id>-<attempt>.<CI_DOMAIN>`，证书名永不重复。Let's Encrypt 限制完全相同的名字集合每周只能签 5 张，固定 hostname 跑几次重跑就超了。脚本退出时删掉该 hostname 下的 DNS-01 TXT 记录，启动前也会删掉被打断的 run 留下的 `_acme-challenge.run-*` 记录。删失败只记日志，不让任务失败。

一次性配置（仓库 Settings → Secrets → Actions）：

| Secret | 用途 |
|---|---|
| `CI_DOMAIN` | 如 `ci-relay.example.com` —— DNS 托管在 Cloudflare；不需要 A 记录 |
| `CI_CF_TOKEN` | Cloudflare API token，对该 zone 有 DNS 编辑权限 |
| `CI_CF_ZONE_ID` | 该域名的 Cloudflare zone ID |

没配这些 secret 的话任务自动跳过（fork 保持绿色）。为了尊重 Let's Encrypt 的限流（每注册域名每周 50 张），它只在 tag 推送、每周定时（周一）和手动触发时跑——不在每次 push 跑。每周定时也顺带跑单元测试和 release 构建。中转的数据目录不在 run 之间缓存，所以签发的密钥和账号密钥不会进 Actions 缓存。

## 安全模型

和官方服务一样：中转永远只看得到密文。它能看到的元数据有 SNI 主机名、客户端 IP、字节数。自托管之后连第三方运营商都不用信了。隧道创建默认开放，公开暴露中转之前先读[防滥用](#防滥用)。

## License

MIT。协议类型和 spec 向量改编自
[anomalyco/opentunnel](https://github.com/anomalyco/opentunnel)（MIT）。
