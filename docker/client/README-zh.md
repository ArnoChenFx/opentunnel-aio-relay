# OpenTunnel Client Docker 镜像

带 Web 管理页的官方 [OpenTunnel](https://github.com/anomalyco/opentunnel) 客户端容器，适合配合 [opentunnel-aio-relay](../../README-zh.md) 或官方 API 使用。

容器内运行 `opentunnel serve`（前台服务模式，专为容器设计），管理页通过调用同一 profile 的 CLI 实现 route 的查看、添加、修改和删除。

## 从 GHCR 拉取（推荐）

仓库在 `master` 更新 `docker/client/` 或打 `v*` 标签时会自动构建并推送到 GitHub Container Registry：

```bash
docker pull ghcr.io/arnochenfx/opentunnel-aio-relay/opentunnel-client:latest
```

（包名与 GitHub 用户名/仓库名均为小写。若包为私有，需先 `docker login ghcr.io` 并使用有 `read:packages` 的 token。）

也可在 Actions 里手动运行 **Client Docker (GHCR)** workflow，指定嵌入的 `opentunnel` 版本或仅构建不推送。

## 快速开始

在仓库根目录构建：

```bash
docker build -f docker/client/Dockerfile -t opentunnel-client .
```

运行（将 API 地址换成你的 relay）：

```bash
docker run --rm \
  -e OPENTUNNEL_API=https://tunnel.example.com \
  -p 9080:9080 \
  -v opentunnel-client-data:/data \
  --add-host=host.docker.internal:host-gateway \
  ghcr.io/arnochenfx/opentunnel-aio-relay/opentunnel-client:latest
```

浏览器打开 `http://localhost:9080`。

或使用 Compose（先改 `docker-compose.yml` 里的 `OPENTUNNEL_API`）：

```bash
docker compose -f docker/client/docker-compose.yml up -d --build
```

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `OPENTUNNEL_API` | —（必填） | Relay HTTP API 根 URL，如 `https://tunnel.example.com` |
| `OPENTUNNEL_PROFILE` | `default` | 客户端 profile，每个 profile 对应一条隧道身份 |
| `OPENTUNNEL_CA_CERT` | — | 额外信任的 CA PEM（自签/staging relay 时使用） |
| `OT_CLIENT_ADMIN_PORT` | `9080` | 管理页监听端口 |
| `OT_CLIENT_ADMIN_TOKEN` | — | 设置后，API 与页面请求需 `Authorization: Bearer <token>` |
| `XDG_*` / `/data` | 见 Dockerfile | 隧道密钥、route 配置等持久化在 `/data` 卷 |

## 转发到本机服务

容器内的 route **目标**填容器能访问的地址：

- 同一 Compose 网络里的服务：`服务名:端口`
- 宿主机上的进程：`host.docker.internal:端口`（Linux 需 `--add-host=host.docker.internal:host-gateway` 或 Compose 的 `extra_hosts`）
- 需要访问整台宿主机网络时，可使用 `network_mode: host`（此时管理页端口直接开在主机上）

## 管理页能力

- **状态**：profile、Tunnel ID、hostname、bridge 连接情况
- **Routes 列表**：名称、本地目标、公网 URL（有 hostname 时自动拼接）
- **添加 / 修改**：与 CLI 相同，`route add <目标> --name <名称>`（如 `gateway-api` → `https://gateway-api.<Hostname>`）；留空名称则随机；同名 route 会更新目标
- **删除**：`route remove`

首次添加 route 时会自动创建隧道并申请证书，可能需要数分钟；页面会显示 CLI 输出中的公网 URL。

## 安全说明

- 管理页默认**无认证**，请勿把端口直接暴露到公网。生产环境请设置 `OT_CLIENT_ADMIN_TOKEN`，并仅在内网或反向代理后访问。
- `/data` 含隧道私钥与证书，请妥善备份并限制卷权限。

## 构建参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `OPENTUNNEL_VERSION` | `0.6.1` | 官方 release 版本号（可填 `latest`） |
