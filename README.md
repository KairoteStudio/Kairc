# Kairc

**Kairote + IRC. 一个轻量、开放、可自托管的实时通信基础设施。**

Kairc 想保留早期互联网 IRC 最珍贵的部分：公开协议、用户自选客户端、按频道组织的实时对话，以及任何人都能运行自己的服务器。它同时补上现代服务必须具备的边界控制、TLS、健康检查与可重复部署。

> 当前状态：`v0.1.0-dev`，可运行的单节点 MVP。协议和配置在首个稳定版本前可能变化；尚未接受过独立安全审计。

## 它现在能做什么

- 兼容标准 IRC 客户端的 TCP 文本协议，遵守 512 字节消息上限
- 昵称注册、频道加入/离开、频道消息和私信
- `NAMES`、`WHO`、`WHOIS`、`LIST`、`TOPIC`、`MODE`、`KICK` 等基础命令
- 第一个加入频道的成员自动成为 operator；operator 离开后自动继任
- RFC 1459 大小写映射、昵称唯一性和频道成员权限检查
- 每连接限流、全局连接上限、有界发送队列和注册超时
- TLS 1.3 直连、容器部署、非 root 运行及 HTTP 健康检查
- 默认不保存消息、不要求账户、不依赖数据库

暂未实现服务器互联、SASL 账户、离线消息、频道封禁列表和 WebSocket 网关。它们会按 [RFC-0001](docs/RFC-0001.md) 的边界逐步加入，而不是塞进第一版核心。

## 快速开始

需要 Go 1.24 或更新版本。

```bash
go run ./cmd/kaircd \
  --listen :6667 \
  --server-name irc.localhost \
  --network KairoteNet
```

随后使用任意 IRC 客户端连接 `localhost:6667`。也可以直接用 `nc` 验证：

```text
$ nc localhost 6667
NICK alice
USER alice 0 * :Alice
JOIN #lobby
PRIVMSG #lobby :hello, early internet
```

使用容器：

```bash
docker compose up --build
```

运行验证：

```bash
go test -race ./...
go vet ./...
go build ./cmd/kaircd
```

## 配置

每个选项都同时支持命令行参数与环境变量。命令行参数优先。

| 参数 | 环境变量 | 默认值 | 说明 |
|---|---|---:|---|
| `--listen` | `KAIRC_LISTEN` | `:6667` | IRC 监听地址 |
| `--health-listen` | `KAIRC_HEALTH_LISTEN` | `:8080` | 健康检查地址；空值关闭 |
| `--server-name` | `KAIRC_SERVER_NAME` | `irc.kairote.local` | 对客户端公开的节点名 |
| `--network` | `KAIRC_NETWORK` | `KairoteNet` | 网络名 |
| `--motd` | `KAIRC_MOTD` | 内置欢迎语 | MOTD；可用字面量 `\n` 换行 |
| `--max-clients` | `KAIRC_MAX_CLIENTS` | `1024` | 最大并发连接数 |
| `--rate` | `KAIRC_RATE` | `8` | 每连接持续消息速率 |
| `--burst` | `KAIRC_BURST` | `24` | 每连接瞬时消息额度 |
| `--registration-timeout` | `KAIRC_REGISTRATION_TIMEOUT` | `30s` | 完成注册的最长时间 |
| `--tls-cert` | `KAIRC_TLS_CERT` | 空 | PEM 证书路径 |
| `--tls-key` | `KAIRC_TLS_KEY` | 空 | PEM 私钥路径 |

生产环境应使用 TLS：

```bash
./kaircd \
  --listen :6697 \
  --server-name irc.example.org \
  --tls-cert /run/secrets/fullchain.pem \
  --tls-key /run/secrets/privkey.pem
```

也可以只在可信内网监听明文端口，由 HAProxy、nginx stream 或其他 TCP 代理终止 TLS。不要把默认的明文 `6667` 直接暴露到公网。

## 架构

```text
IRC client ── TCP/TLS ──> parser ──> single-owner hub ──> bounded client queues
                                      │
                                      ├── nick index
                                      └── ephemeral channels
```

所有昵称和频道状态只由一个 hub goroutine 修改；连接读写并发进行，但不共享可变房间状态。这个模型刻意保持简单，便于审计，也很适合作为未来分片或联邦节点的可靠单节点内核。

更完整的产品原则、信任边界和演进路线见 [docs/RFC-0001.md](docs/RFC-0001.md)，当前兼容范围见 [docs/PROTOCOL.md](docs/PROTOCOL.md)。

## 项目原则

1. 协议先于官方客户端，任何客户端都应是一等公民。
2. 消息默认短暂存在，持久化必须由频道明确选择。
3. 单节点先可靠，再设计节点互联；不伪装成已经去中心化。
4. 运营者拥有本地治理权，但跨节点身份和事件必须可验证。
5. 资源上限是协议实现的一部分，不是部署后的补丁。

## 路线图

- **v0.1 — 单节点内核：** 完成真实客户端互操作测试、频道 operator 模式和部署基线。
- **v0.2 — 公共服务能力：** SASL、账户/昵称绑定、封禁与邀请、可选历史、WebSocket 网关和指标。
- **v0.3 — 节点互联实验：** 节点密钥、签名事件、环路抑制、房间归属及断网重连。
- **v1.0 — 稳定网络：** 版本化协议、迁移承诺、安全审计和至少三个独立运营节点。

## 参与贡献

请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题不要提交公开 Issue，报告方式见 [SECURITY.md](SECURITY.md)。

Kairc 采用 [Mozilla Public License 2.0](LICENSE) 发布。
