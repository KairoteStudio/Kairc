# 隐私边界

Kairc 的目标是减少被迫披露和中心化关联，而不是承诺“绝对匿名”。部署者和使用者必须区分以下层次。

## 本地 IRC 隐私

IRC gateway 强制绑定字面量 `127.0.0.1` 或 `::1`；为避免 hosts/DNS 歧义，配置中的 `localhost` 也会被拒绝。客户端发送的 USER、realname 和本机用户名不会写入事件或日志。nickname 会进入消息，因此使用真实姓名或复用其他平台昵称会主动降低匿名性。

## 网络地址隐私

`tor://` peer 会交给 SOCKS5 proxy 解析和连接，避免本地 DNS 泄漏目标 `.onion`。Tor 隐藏的是网络路径，不会自动隐藏消息内容、消息大小、时间或行为模式。

`tcp://` peer 可以直接看到连接来源地址。它只适合开发或已有安全边界的网络。

P2P v3 的持久 Ed25519 public key 用于 pin peer，并会向连接对端公开，因此同一个节点的多次会话可被关联。这个 key 不是聊天账户，但 trusted-peer 配置本身可能形成社交关系元数据。Tor 隐藏网络路径，不消除这种协议层可关联性。

启用 discovery 并配置 `advertise_peer` 后，节点会公开传播“持久 identity → onion endpoint、端口、时间、capability”的签名记录；这比只使用私下交换的静态 peer 增加可枚举性和跨会话关联。记录不会包含 observed source IP 或 SOCKS proxy 地址，发现拨号也只把 onion hostname 交给 SOCKS5。`open` 模式还会让任意已接纳 peer 查询和提供这些记录；需要最小暴露时应保持 discovery 关闭，或使用 `trusted` 模式与小型 allowlist。

## 消息隐私

公开频道的 nickname 与 message 是明文，所有中继节点都能读取并保存。私密频道加密 payload，但 channel tag、时间、大小、DAG parents 和传播行为可见。

共享密钥在一个密钥代际内没有前向保密。该代际密钥日后泄漏时，过去保存的 ciphertext 也能被解密。替换 secret 会改变 channel tag，可手动移除成员并隔离新旧代际；只有旧 secret 已从配置、备份和密码管理器安全删除时，新 secret 的泄漏才不会连带解密旧代际。这不是自动 ratchet。任何频道成员都能复制消息或泄漏自己持有的密钥。

## 本地存储

默认 SQLite store 保留最近 24 个小时 epoch，并以 512 MiB 主文件/WAL/SHM 总预算和每 epoch 100,000 events 作为硬上限。公开消息以明文保存，私密频道 payload 以 ciphertext 保存；配置文件中的频道密钥与 P2P identity seed 都是敏感材料，含密钥文件若具有 group/other 权限会被拒绝。磁盘加密、备份和安全删除由操作系统与运营者负责。

## 日志

默认应用日志不包含 peer address、来源 IP、nickname、频道名或消息正文。操作系统、Tor、容器平台、防火墙和 IRC 客户端可能产生自己的日志，Kairc 无法替它们作保证。

## 无法防御

- 被攻陷的终端或 IRC 客户端；
- 能同时观察大量网络入口与出口的全局对手；
- 通过语言习惯、时区、消息时序或复用 nickname 进行的关联；
- 已加入私密频道的恶意成员；
- 拒绝服务、选择性转发和 eclipse；
- 目前 PoW 难度下拥有大量计算资源的垃圾发送者。
- trusted peer 自身发送预算内的恶意内容，或运营者显式允许未知 peer 后扩大的 Sybil 面。
