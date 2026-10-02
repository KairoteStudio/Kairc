# Kairc

**自由、匿名、无中心账户的 P2P IRC 基础设施。**

Kairc 不是一台替用户保管身份和聊天记录的 IRC 服务器。每个参与者在自己的设备上运行 `kaircd`，普通 IRC 客户端只连接本机；`kaircd` 再通过加密的 P2P 链路交换签名事件。没有中心登录服务，没有全网唯一昵称，也没有“官方客户端”。

```text
IRC client ── localhost ── kaircd ── Tor / SOCKS5 ── P2P event graph
                              │                           │
                              ├─ one-time event keys     ├─ authenticated peers
                              ├─ channel encryption      ├─ canonical DAG order
                              └─ bounded local history   ├─ metered gossip
                                                          └─ signed onion discovery
```

> 当前状态：`0.4.0-dev`，C++23 技术原型。事件图、加密频道、认证 P2P、Tor SOCKS5、本地 IRC 网关、资源配额、确定性历史顺序和轻量 onion-only Kademlia 节点发现已经实现；自动成员密钥协议、RLN、抗 Sybil discovery 和第三方安全审计仍未完成。不要把它当作已成熟的匿名通信工具。

> 协议升级：0.4 使用 Event v2、network hash v2 与 P2P v3，故意不与 0.3 网络或数据库互通。升级实验节点时请使用新的数据库路径并让所有节点同时切换；P2P identity seed 和频道 secret 可以保留，但它们在新 network domain 下产生新的协议标识。

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
- 无账户的 Hashcash 风格工作量证明只提供最低发送成本；真正的资源边界由可信 peer、每 peer/全局令牌桶、验证并发和持久化配额承担。

匿名不等于不可观察。节点仍能看到自己的 TCP 对端；公开频道内容是明文；昵称、频道标签、消息大小与时序都可能造成关联。完整边界见 [PRIVACY.md](docs/PRIVACY.md) 和 [威胁模型](docs/THREAT_MODEL.md)。

## 来自 DarkFi 的启发

Kairc 参考了 DarkFi 的 [DarkIRC 架构文档](https://dark.fi/book/misc/darkirc/darkirc.html)与[官方实现](https://github.com/darkrenaissance/darkfi/tree/master/bin/darkirc)：本地 IRC gateway、P2P 消息同步、轮换 Event Graph、Tor transport，以及“网络匿名”和“消息保密”必须分别处理的原则。

本项目没有复制 DarkFi 的 Rust 源码，也不声称拥有 DarkFi 的完整能力。当前差异尤其重要：

- DarkIRC 有成熟得多的 P2P 栈、节点生命周期和 Event Graph 同步；Kairc 的发现层只是需要静态 bootstrap 才能自举的轻量、onion-only、最终一致 Kademlia 子集，不提供 DarkFi 等价的 Sybil/eclipsing 防护。
- DarkFi 可选用 RLN 零知识限流；Kairc 尚未实现 RLN。逐事件 PoW 只作为发送成本，不能抵抗拥有大量算力的 Sybil。
- Kairc 私密频道仍是共享密钥 XChaCha20-Poly1305。替换密钥会得到新的密码学频道代际，可用于手动移除成员，但没有自动分发、每消息 ratchet 或完整前向保密。
- Kairc P2P v3 用持久 Ed25519 节点身份认证临时 X25519 会话，并默认拒绝未列入 `trusted_peer` 的对端。该身份会让同一节点的多次连接可关联；Tor 仍是隐藏网络地址所必需的独立层。

## 已实现

- C++23，无语言运行时
- 本地 IRC 子集：`CAP`、`NICK`、`USER`、`JOIN`、`PART`、`PRIVMSG`、`NAMES`、`WHOIS`、`PING`
- 每条事件独立的 Ed25519 签名身份
- BLAKE2b 内容寻址与网络域隔离；Event ID 只覆盖规范 unsigned event，阻止一次 PoW 通过多份合法签名生成多个 ID
- 每小时轮换的 DAG、父事件闭包、按依赖索引的 pending queue 和缺失父事件递归请求
- 基于 `(epoch, causal layer, event ID)` 的确定性历史顺序；分区恢复消息通过 IRCv3 时间戳、batch 和 replay 标签显式呈现
- Ed25519 节点身份、临时 X25519 会话密钥、握手 transcript confirmation 与 XChaCha20-Poly1305 P2P 帧
- 私密频道 XChaCha20-Poly1305 端到端载荷加密，并绑定签名事件上下文以阻止换壳重放
- Tor/SOCKS5 出站，SOCKS5 负责解析 `.onion` 目标
- node-key 签名的单 onion endpoint 记录、持久序列高水位、短 TTL/墓碑撤销、256 个 XOR bucket、`FIND_NODES`/`NODES` 和 exact-identity 可达性验证
- SQLite WAL 事件存储、按小时保留、增量回收、数据库/WAL 总量上限和每 epoch 事件上限
- 内容 ID 早期去重、受限的签名验证并发、重复 ID 拒绝，以及双向每认证 identity/全局 bytes、frame、event 令牌桶
- 有界事件、frame、inventory、pending queue、每 peer pending、频道/连接槽位、本地发布速率、空闲连接、写入/握手时间和 PoW 难度

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
p2p_identity_seed = 0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a
trusted_peer = 66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a
database = ./data/a.db
network_id = local-demo
work_bits = 4
channel.#lobby = public
```

节点 B：

```ini
irc_listen = 127.0.0.1:6668
peer = tcp://127.0.0.1:7777
p2p_identity_seed = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
trusted_peer = 43a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c
database = ./data/b.db
network_id = local-demo
work_bits = 4
channel.#lobby = public
```

以上种子只用于可复现的本机示例，绝不能复制到真实网络。生产节点先运行 `./build/kaircd --gen-peer-identity`，只交换输出中的公钥。包含私钥种子的配置必须为 `0600`。分别启动后，让两个 IRC 客户端加入 `#lobby`。`tcp://` 只适合本机开发；它会向直接对等节点暴露网络地址。

## Tor 节点

运行本地 Tor SOCKS5 代理后：

```ini
tor_proxy = 127.0.0.1:9050
peer = tor://exampleexampleexampleexampleexampleexampleexampleexample.onion:7777
```

要接受匿名入站连接，应由 Tor onion service 把 `HiddenServicePort` 转发到一个 loopback `p2p_listen`。Kairc 本身不会自动创建 onion service，也不会把 direct TCP 描述成匿名传输。
为避免意外本地 DNS 查询，`.onion` 目标使用 `tcp://` 会在配置校验时直接被拒绝。

### 轻量节点发现

发现默认关闭。推荐先使用 `trusted`：bootstrap endpoint 与预期节点 identity 绑定，发现 frame 只在可信 link 上交换，且只接受 `trusted_peer` 身份的记录。

```ini
tor_proxy = 127.0.0.1:9050
peer_discovery = trusted
bootstrap_peer = 64_HEX_PUBLIC_KEY@tor://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:7777
trusted_peer = 64_HEX_PUBLIC_KEY

# 只有运行了指向本机 p2p_listen 的 Tor onion service 时才配置：
advertise_peer = tor://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:7777
```

每个 v1 peer record 只允许一个 onion v3 endpoint；成功连接时，握手 identity 必须与记录签名 identity 完全一致，之后记录才可向其他节点传播。地址撤销使用更高 sequence 的签名 tombstone；可拨号记录过期后，SQLite 仍在最长旧记录有效窗口内保留序列高水位，阻止重启回滚。普通身份最多占 4096 个持久水位，另有 576 个受保护水位，覆盖当前可信集合、本机 identity 历史及一个退役可信代际；退役 key 不能在 open 模式无限续占该区。失败拨号退避绑定签名 identity，更新 sequence、TTL 或 endpoint 不能强制立即重拨。

`peer_discovery = open` 是显式风险模式：它接收未知身份的自签记录，并允许按记录中 pin 的 identity 发起连接。实现有有界 bucket、可信记录优先、全局/identity 限流、最多 16 条发现会话（其中未知身份最多 12 条）、5 分钟轮换和退避，但没有 RLN、身份成本或全局 peer diversity 证明；有资源的 Sybil 仍可 eclipse 节点。初始 bootstrap、Tor onion service 生命周期和 bootstrap 多样性仍由运营者负责。

## 私密频道

生成共享密钥：

```bash
./build/kaircd --gen-channel-secret
```

每位参与者在自己的配置中加入相同密钥：

```ini
channel.#private = 64_HEX_CHARACTERS
```

包含频道密钥的配置文件必须设为仅 owner 可访问，例如 `chmod 600 kairc.conf`，否则节点会拒绝启动。密钥必须通过已认证的安全渠道交换。任何获得密钥的人都能读取其拿到的该频道事件。

当前的成员移除流程是手动代际轮换：生成新 secret，只发给保留成员，所有保留成员协调替换配置并重启。新 secret 会产生新的 channel tag，旧成员不能读取新代际；新成员也不会凭新 secret 解密旧代际。确认迁移后应从配置、备份和密码管理器中删除旧 secret。这个流程没有在线协商或防回滚，也不是每消息 ratchet；任一代际密钥泄漏仍会暴露该代际全部已保存历史。
一个共享密钥就是一个私密频道的密码学标识，节点会拒绝把同一密钥配置给两个本地频道名。

## 0.4 加固边界

0.4 在 0.3 的认证 peer、令牌桶、验证工作池、确定性回放和磁盘配额之上，加入了有界、签名、onion-only 的轻量 Kademlia discovery。它解决的是普通节点的自举门槛，不解决开放网络身份成本；RLN、自动成员密钥协议、bootstrap diversity/eclipsing 仿真仍需要独立 RFC、互操作测试和密码学评审。代码和文档不会把 PoW、DHT 或共享密钥宣传成这些机制的等价替代品。

## 文档

- [RFC-0001：自由匿名 P2P 架构](docs/RFC-0001.md)
- [P2P 与事件协议](docs/PROTOCOL.md)
- [隐私边界](docs/PRIVACY.md)
- [威胁模型](docs/THREAT_MODEL.md)
- [0.4 加固状态与后续门槛](docs/HARDENING.md)
- [安全报告](SECURITY.md)

Kairc 由 KairoteStudio 维护，使用 [Mozilla Public License 2.0](LICENSE)。
