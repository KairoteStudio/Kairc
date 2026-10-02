# Kairc 0.4 wire protocol

本文描述当前原型，不构成 1.0 稳定性承诺。所有多字节整数使用 network byte order。

0.4 的 Event v2、network hash v2 与 P2P v3 是一次有意的断代升级；0.3 数据库与网络不能原地混用。

## 网络与 epoch

```text
network = BLAKE2b-256("kairc/network/v2\0" || u16(len(network_id)) || network_id || u8(work_bits))
epoch   = floor(timestamp_ms / 3_600_000)
root    = BLAKE2b-256("kairc/epoch-root/v1\0" || network || u64(epoch))
```

不同 `network_id` 或 PoW 难度的节点在握手和事件验证阶段互相拒绝。

## Event 编码

```text
u8       version (=2)
u8       kind (=1, channel_message)
bytes32  network
u64      timestamp_ms
bytes32  one-time Ed25519 author key
u64      work_nonce
u8       parent_count (1..4)
bytes32  parents[parent_count]
bytes32  channel_tag
bytes24  content_nonce
u32      content_length (<=8192)
bytes    content
bytes64  Ed25519 signature
```

PoW digest、signature digest 和 event ID 使用不同的 BLAKE2b domain。Signature 覆盖 signature 字段之前的完整编码；event ID 为 `BLAKE2b-256("kairc/event-id/v2\0" || unsigned_event)`，不包含 signature。这样恶意 author 不能为同一份已完成 PoW 的 unsigned event 生成多份合法 Ed25519 signature，再用不同 ID 绕过去重；signature 仍必须在首次接收该 ID 时验证。

节点检查版本、network、未来时间窗口、parent 唯一性、PoW、signature、ID 和 parent closure。Event body 最大 8 KiB。

接收端先从规范编码重新计算 content ID，并在验证 Ed25519 前查询 store 与 pending queue。这个快速路径只接受重新计算出的 ID，不能由 peer 自报 ID 绕过验证。新的远端验证还受固定大小的 verification worker pool 控制。

## Channel payload

聊天明文为两个 `u16 length + bytes` 字段。nickname 使用 IRC ASCII 语法且最多 24 字节；message 最多 350 字节，通常使用 UTF-8，并拒绝 C0 control 与 DEL，避免把 CTCP/DCC 等客户端控制序列带入匿名边界。

公开频道：

```text
tag = BLAKE2b-256("kairc/public-channel/v1\0" || network || canonical_name)
content_nonce = 24 zero bytes
content = plaintext
```

私密频道：

```text
key = BLAKE2b-256("kairc/channel-key/v1\0" || 32-byte shared secret)
tag = BLAKE2b-256("kairc/private-channel/v1\0" || network || key)
content_nonce = random 24 bytes
context = version || kind || network || timestamp_ms || author || parent_count || parents || tag
aad = BLAKE2b-256("kairc/channel-aad/v1\0" || tag || context)
content = XChaCha20-Poly1305(key, nonce, plaintext, associated_data=aad)
```

`context` 不含 PoW nonce、content nonce、content 或 signature。一次性 author key 已在 AEAD 中绑定，而 signature 又覆盖完整 Event；因此不知道频道密钥的 relay 不能把旧 ciphertext 放进自己新签名的外层事件并再次显示为原消息。同一 unsigned Event 的逐字节重放或替代合法 signature 共享同一 content ID。

## DAG 顺序与延迟恢复

Event Graph 不提供共识或全球实时强时序。节点在 parent closure 成立后，为每个 event 持久化确定性 causal layer：

```text
layer(event) = 1                                      if all parents are virtual epoch roots
layer(event) = 1 + max(layer(non-root parents))       otherwise
canonical_order = (epoch ASC, layer ASC, event_id ASC)
```

同一组 event 无论以何种到达顺序写入，最终历史顺序都相同。实时远端消息默认等待 `presentation_delay_ms=750` 的短窗口再按 canonical order 投递；这个窗口不是共识保证。分区恢复或超出窗口的旧消息不会插回客户端已经显示的行，而是以原始时间戳和 replay 标记显式发送。

缺 parent 的 event 按 missing parent 建反向索引，只在对应 parent 到达时重新检查。Parent 到达后才发现跨 epoch 边时，只删除该无效 child，并继续闭合同一 parent 的其他合法 child。默认 global pending 上限为 2048、每个已认证 peer 为 256、receipt TTL 为 300 秒。

## Peer handshake v3

Inbound server 接受 TCP 后先发送一次性 responder-cookie prelude：

```text
bytes8   "KAIRCCK3"
u16      protocol_version (=3)
bytes32  network
bytes32  random responder cookie
```

Outbound client 校验 prelude，并把该 cookie 放进自己的固定长度签名 hello 的 `challenge` 字段。Server 必须验证 cookie、network、role、声明 identity、allowlist 与签名，之后才生成自己的临时 X25519 key 和签名 hello 作为响应：

```text
bytes8   "KAIRCP3P"
u16      protocol_version (=3)
bytes32  network
u8       role (=1 outbound client, =2 inbound server)
bytes32  persistent Ed25519 node identity
bytes32  ephemeral X25519 public key
bytes32  random challenge
bytes64  Ed25519 signature
```

签名对象为上述 signature 之前的完整 hello 的 domain-separated BLAKE2b digest。role 防止反射和 client/server key-direction 混淆；network、临时 key 与 challenge 都被签名。Client 对 fresh responder cookie 的签名让录制的旧 client hello 不能在新连接重放；cookie 本身不是身份凭证。默认情况下，对端 Ed25519 key 必须出现在 `trusted_peer` 中；`allow_unknown_inbound` 与 `allow_unknown_outbound` 是显式降低准入要求的 opt-in。

Outbound side 使用 `crypto_kx_client_session_keys`，inbound side 使用对应 server 函数。双方随后按 `client_hello || server_hello` 计算 domain-separated transcript hash，以每方向 nonce 0 的 AEAD frame 互相确认；只有确认相同 transcript 后 link 才进入 ready 状态。数据 frame 从 nonce counter 1 开始。临时 X25519 secret 在握手后擦除，方向密钥在连接结束时擦除。

未认证连接先进入最多 256 项的非阻塞 cookie-write/hello-read 队列，整个 pre-auth 阶段的绝对期限为 3 秒。队列满时，新连接替换最老的未完成项，而不是被一个固定的静默集合永久挡在外面。直接 TCP 来源的同一 IPv4 或 IPv6 `/64` 最多占 2 项，而且这个 reservation 保持到验签阶段结束；loopback 来源不套用此合并规则，避免 Tor HiddenServicePort 转发把所有 onion 客户端错误视为同一个 `127.0.0.1`。完整 hello 通过廉价预检后，全局最多 16 个验签/握手工作槽，同一声明 identity 最多 2 个；这些槽同时预留后续全局/inbound session 容量。

Server 在 Ed25519 身份签名通过后、生成本地 X25519 key 与 Ed25519 签名前原子扣除两级 authenticated-handshake token：默认每 identity 每分钟 12 次、全局每分钟 120 次；任一预算不足都不会扣另一个。Fresh cookie 阻止录制 hello 重复扣款；达到 4 条 session 上限的 identity 会在生成本地 key 前被拒绝，也不能消耗全局 token。默认策略下，未认证的 connect/close、未知 key 或坏签名不会烧掉该预算。成功认证后，同一 node identity 最多同时占用 4 条会话。

这提供被 pin 的节点身份认证和会话密钥前向保密，但持久 public key 会让对端关联同一节点的不同会话。它不是用户身份，也不认证 event nickname。

## Encrypted frame

```text
u32      ciphertext_length (17..1_048_576)
bytes    XChaCha20-Poly1305 ciphertext
```

明文第一个字节是 frame type，其后是 payload。四字节 length header 是 AEAD associated data。每个方向使用独立 session key；24 字节 nonce 的高 16 字节为零，低 8 字节为递增 counter。counter 0 只用于握手 transcript confirmation，首个普通 frame 使用 1。连接绝不能重用 session key。

| Type | 值 | Payload |
|---|---:|---|
| `INVENTORY` | 1 | `u16 count` + 最多 256 个 event ID |
| `GET_EVENTS` | 2 | `u16 count` + 最多 256 个 event ID |
| `EVENT` | 3 | 一个完整 Event |
| `PING` | 4 | 空 |
| `PONG` | 5 | 空 |
| `PEER_RECORD` | 6 | 当前 link identity 自己的一个签名 peer record |
| `FIND_NODES` | 7 | `u64 request_id` + `bytes32 target` |
| `NODES` | 8 | `u64 request_id` + `u8 count` + 最多 8 个 `u32 length + peer_record` |

收到缺少 parent 的 EVENT 时，节点将它放入有界 pending queue，并向来源 peer 请求缺失 ID。Parent 提交后重新检查 pending event。

ID list 不允许重复项。加密收发两侧按已认证 node identity 共享 token bucket，进程还共享 global token bucket；bytes、frame 和 EVENT 分别计量，重连或并行开 session 不能刷新预算。可信 identity 的预算在进程生命周期内保留；显式允许的未知 identity 在最后一条 session 关闭后至少保留一个预算窗口。超额 link 被关闭。已建立连接有可配置的 read idle timeout。PoW 不承担这些硬资源边界。

默认持久化上限为数据库、WAL 和 SHM 合计 512 MiB，每 epoch 最多 100,000 events。SQLite 同时设置 `max_page_count`、WAL autocheckpoint 与 journal size limit；跨 epoch 清理后执行 incremental vacuum 和 truncating checkpoint。

## Onion peer discovery

Discovery 是 P2P v3 的可选、轻量 Kademlia 子协议，不是共识层。节点 ID 为：

```text
node_id = BLAKE2b-256("kairc/kad-node-id/v1\0" || network || persistent_node_identity)
```

路由表按 XOR distance 使用 256 个 bucket；每个 bucket 最多 8 个 primary 和 8 个 replacement。未完成 endpoint 验证的 live record 只能待在 replacement 且不能被 `NODES` 转发；可信 subject 和已锚定 withdrawal 在容量竞争中优先于普通未验证 replacement。响应仍最多 8 项，这些限制只约束资源，不构成 Sybil 或 diversity 保证。

Peer record v1 的签名之前编码为：

```text
bytes8   "KAIRCDR1"
u16      record_version (=1)
u8       kind (=1 live, =2 tombstone)
bytes32  network
bytes32  persistent Ed25519 identity
u64      monotonically increasing sequence
u64      issued_at_seconds
u64      expires_at_seconds
u16      p2p_protocol_version (=3)
u64      capabilities (bit 0 = event gossip)
u8       endpoint_count (live=1, tombstone=0)
u16+str  canonical lowercase 56-character onion-v3 hostname, when live
u16      TCP port, when live
bytes64  Ed25519 signature
```

签名 digest 使用 `kairc/peer-record/v1`，record ID 使用 `kairc/peer-record-id/v1`。Live record 正常 TTL 为 1 小时；任何 record 最长 2 小时，未来时钟容差 5 分钟。v1 强制一个 identity record 只含一个 endpoint，避免验证一个地址后顺带传播未验证地址。Kairc 只做 56 字符 lowercase base32 与 `.onion` 的规范形状检查；实际 onion-v3 checksum/public-key 有效性由 Tor 在 SOCKS remote-resolution/connect 时确认。

连接发现地址时，P2P hello identity 必须精确等于 record identity。成功后才把 live record 标记为 endpoint-verified 并允许转发。Tombstone 必须拥有更高 sequence，而且只有该 identity 曾完成过 exact-identity endpoint 握手时才允许传播；这个 `ever_verified` anchor 与最高 sequence 持久化。可拨号 raw record 到期后，sequence/digest watermark 仍保留至少一个最大 record 有效窗口，防止重启、缓存淘汰或“长 TTL tombstone → 短 TTL live”使旧记录复活。持久层最多保留 4096 个普通身份水位，另预留 576 个受保护水位：最多 256 个当前配置可信身份、64 个本机 identity 历史，以及一个最多 256 身份的退役可信代际。普通 Sybil 不能耗尽该保留区；被移出 allowlist 的 key 不能以普通记录延长旧受保护水位，它会在最长水位窗口后释放，所有分区合计仍有硬上限。

每条 link 最多同时有 4 个 discovery request，30 秒后失效；非请求、重复或过期 `NODES` 会关闭 link。第三方 record 的有效同序冲突只归因于签名 subject，不会错杀 relay；无效签名仍视为 relay 提供的坏数据。拨号候选在过滤 active/backoff 后选择，可信 identity 优先并有一个专用 worker。失败退避按签名 identity 绑定（60、120、240、480、960 秒），sequence、TTL、capability、endpoint 更新或短期 record 到期都不能提前清零；failure level 与持久水位保留同样长的有界窗口，表饱和时改用共享指数退避。成功完成 exact-identity 会话后进入 10 分钟轮换窗口。发现来源会话最多 16 条，其中未知 identity 最多 12 条；每条最长 5 分钟，hard deadline 同时约束 handshake、frame read 和 write。初始 rendezvous 仍需要静态 `bootstrap_peer`。

`trusted` 模式只允许 trusted link 使用 discovery frame，并只接收 allowlist subject。`open` 模式接受任意自签 subject；签名只能证明 key 持有，不产生身份成本，因此有资源的攻击者仍可填充 bucket、选择性返回记录或 eclipse 节点。PoW 不用于 peer record，RLN 也尚未实现。

## IRC boundary

IRC 只监听字面量 `127.0.0.1` 或 `::1`，最大 line 为 512 字节（含 CRLF）。`USER` 与 realname 不进入事件。`NAMES` 只反映连接同一本地 gateway 的客户端，不是全网 presence。

支持：`CAP`、`NICK`、`USER`、`PING/PONG`、`QUIT`、`JOIN/PART`、频道 `PRIVMSG`、`NAMES`、基础 `MODE` 与 `WHOIS`。IRCv3 capabilities 为 `message-tags`、`server-time` 和 `batch`。

加入频道时，协商了相关 capability 的客户端最多收到 100 条 canonical local history。批次类型为 `kairc/replay`，消息带原事件 `time`；支持 `message-tags` 时还带 `kairc.io/replay=1`。没有时间或 tag capability 的客户端不自动接收历史，避免把旧消息伪装成实时消息。0.4 不支持 direct message、账户、文件、全网 operator 或传播式 ban。
