# Kairc

**自由、匿名、无中心账户的 P2P IRC 基础设施。**

Kairc 不是一台替用户保管身份和聊天记录的 IRC 服务器。每个参与者在自己的设备上运行 `kaircd`，普通 IRC 客户端只连接本机；`kaircd` 再通过加密的 P2P 链路交换签名事件。没有中心登录服务，没有全网唯一昵称，也没有“官方客户端”。

```text
IRC client ── localhost ── kaircd ── Tor / SOCKS5 ── P2P event graph
                              │                           │
                              ├─ ephemeral signing keys  ├─ parent closure
                              ├─ channel encryption      ├─ deduplication
                              └─ rotating local history  └─ bounded gossip
```

> 当前状态：`0.2.0-dev`，C++23 技术原型。事件图、加密频道、Tor SOCKS5 出站和本地 IRC 网关已经实现；节点发现、前向保密、匿名抗滥用证明和正式安全审计尚未完成。不要把它当作已成熟的匿名通信工具。

## 两个核心原则

### 自由

- 用户自由选择任何兼容的 IRC 客户端。
- 任何人都能运行节点、建立独立网络或选择自己的对等节点。
- 不需要手机号、邮箱、中心账户或全局昵称许可。
- 频道可以公开，也可以由参与者自行持有共享密钥。
- 协议、实现和数据格式都是可审计的；没有推荐流、广告画像或平台锁定。

### 匿名

- IRC 入口强制绑定 loopback，P2P peer 不能直接连接 IRC 客户端，也收不到其 `USER`/realname。
- 每条本地事件使用新的 Ed25519 密钥签名，不产生持久账户标识。
- `USER`、realname 和本机用户名不会进入 P2P 事件。
- `tor://` 对等节点通过 SOCKS5 连接，目标域名不会在本地解析。
- 不记录聊天内容、昵称、对等节点地址或来源 IP 到应用日志。
- 无账户的 Hashcash 风格工作量证明为每条事件提供最低抗垃圾成本。

匿名不等于不可观察。节点仍能看到自己的 TCP 对端；公开频道内容是明文；昵称、频道标签、消息大小与时序都可能造成关联。完整边界见 [PRIVACY.md](docs/PRIVACY.md) 和 [威胁模型](docs/THREAT_MODEL.md)。

## 来自 DarkFi 的启发

Kairc 参考了 DarkFi 的 [DarkIRC 架构文档](https://dark.fi/book/misc/darkirc/darkirc.html)与[官方实现](https://github.com/darkrenaissance/darkfi/tree/master/bin/darkirc)：本地 IRC gateway、P2P 消息同步、轮换 Event Graph、Tor transport，以及“网络匿名”和“消息保密”必须分别处理的原则。

本项目没有复制 DarkFi 的 Rust 源码，也不声称拥有 DarkFi 的完整能力。当前差异尤其重要：

- DarkIRC 有成熟得多的 P2P 栈、节点生命周期和 Event Graph 同步；Kairc 目前只有静态 peer 与有界 inventory/get/event gossip。
- DarkFi 可选用 RLN 零知识限流；Kairc 当前只是公开可验证的逐事件 PoW，不能抵抗拥有大量算力的 Sybil 攻击。
- Kairc 私密频道使用共享密钥 XChaCha20-Poly1305，没有成员级密钥轮换或前向保密。
- Kairc 的 direct TCP 握手使用临时 X25519 会话加密，但不认证对端；公开网络应使用 Tor onion service，并依靠事件签名防止内容篡改。

## 已实现

- C++23，无语言运行时
- 本地 IRC 子集：`CAP`、`NICK`、`USER`、`JOIN`、`PART`、`PRIVMSG`、`NAMES`、`WHOIS`、`PING`
- 每条事件独立的 Ed25519 签名身份
- BLAKE2b 内容寻址与网络域隔离
- 每小时轮换的 DAG、父事件闭包和缺失父事件递归请求
- X25519 会话密钥与 XChaCha20-Poly1305 P2P 帧
- 私密频道 XChaCha20-Poly1305 端到端载荷加密，并绑定签名事件上下文以阻止换壳重放
- Tor/SOCKS5 出站，SOCKS5 负责解析 `.onion` 目标
- SQLite WAL 事件存储与按小时保留窗口
- 有界事件、frame、inventory、pending queue、频道/连接槽位、本地发布速率、写入/握手时间和 PoW 难度

## 构建

需要 CMake 3.20+、支持 C++23 的编译器、libsodium 和 SQLite3。

Arch Linux：

```bash
sudo pacman -S cmake ninja gcc libsodium sqlite
```

Debian/Ubuntu：

```bash
sudo apt install cmake ninja-build g++ libsodium-dev libsqlite3-dev
```

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## 第一次运行

```bash
cp config/kairc.conf.example kairc.conf
./build/kaircd --config kairc.conf --check-config
./build/kaircd --config kairc.conf
```

IRC 客户端连接本机：

```text
/server add kairc localhost/6667 -notls -autoconnect
/connect kairc
/join #lobby
```

本机 IRC 链路不使用 TLS，因为它不离开 loopback。P2P 链路有独立的会话加密；匿名公网部署还必须配置 Tor。

## 两节点开发网络

节点 A：

```ini
irc_listen = 127.0.0.1:6667
p2p_listen = 127.0.0.1:7777
database = ./data/a.db
network_id = local-demo
work_bits = 4
channel.#lobby = public
```

节点 B：

```ini
irc_listen = 127.0.0.1:6668
peer = tcp://127.0.0.1:7777
database = ./data/b.db
network_id = local-demo
work_bits = 4
channel.#lobby = public
```

分别启动后，让两个 IRC 客户端加入 `#lobby`。`tcp://` 只适合本机开发；它会向直接对等节点暴露网络地址。

## Tor 节点

运行本地 Tor SOCKS5 代理后：

```ini
tor_proxy = 127.0.0.1:9050
peer = tor://exampleexampleexampleexampleexampleexampleexampleexample.onion:7777
```

要接受匿名入站连接，应由 Tor onion service 把 `HiddenServicePort` 转发到一个 loopback `p2p_listen`。Kairc 本身不会自动创建 onion service，也不会把 direct TCP 描述成匿名传输。
为避免意外本地 DNS 查询，`.onion` 目标使用 `tcp://` 会在配置校验时直接被拒绝。

## 私密频道

生成共享密钥：

```bash
./build/kaircd --gen-channel-secret
```

每位参与者在自己的配置中加入相同密钥：

```ini
channel.#private = 64_HEX_CHARACTERS
```

包含频道密钥的配置文件必须设为仅 owner 可访问，例如 `chmod 600 kairc.conf`，否则节点会拒绝启动。密钥必须通过已认证的安全渠道交换。任何获得密钥的人都能读取其拿到的该频道事件；更换成员后不会自动轮换密钥，也没有前向保密。
一个共享密钥就是一个私密频道的密码学标识，节点会拒绝把同一密钥配置给两个本地频道名。

## 文档

- [RFC-0001：自由匿名 P2P 架构](docs/RFC-0001.md)
- [P2P 与事件协议](docs/PROTOCOL.md)
- [隐私边界](docs/PRIVACY.md)
- [威胁模型](docs/THREAT_MODEL.md)
- [安全报告](SECURITY.md)

Kairc 由 KairoteStudio 维护，使用 [Mozilla Public License 2.0](LICENSE)。
