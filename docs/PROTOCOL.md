# Kairc 0.2 wire protocol

本文描述当前原型，不构成 1.0 稳定性承诺。所有多字节整数使用 network byte order。

## 网络与 epoch

```text
network = BLAKE2b-256("kairc/network/v1\0" || u16(len(network_id)) || network_id || u8(work_bits))
epoch   = floor(timestamp_ms / 3_600_000)
root    = BLAKE2b-256("kairc/epoch-root/v1\0" || network || u64(epoch))
```

不同 `network_id` 或 PoW 难度的节点在握手和事件验证阶段互相拒绝。

## Event 编码

```text
u8       version (=1)
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

PoW digest、signature digest 和 event ID 使用不同的 BLAKE2b domain。Signature 覆盖 signature 字段之前的完整编码；event ID 覆盖包括 signature 在内的完整 event。

节点检查版本、network、未来时间窗口、parent 唯一性、PoW、signature、ID 和 parent closure。Event body 最大 8 KiB。

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

`context` 不含 PoW nonce、content nonce、content 或 signature。一次性 author key 已在 AEAD 中绑定，而 signature 又覆盖完整 Event；因此不知道频道密钥的 relay 不能把旧 ciphertext 放进自己新签名的外层事件并再次显示为原消息。原 Event 的逐字节重放仍由 content ID 去重。

## Peer handshake

双方先发送固定长度 hello，再读取对方 hello：

```text
bytes8   "KAIRCP2P"
u16      protocol_version (=1)
bytes32  network
bytes32  ephemeral X25519 public key
```

Outbound side 使用 `crypto_kx_client_session_keys`，inbound side 使用对应 server 函数。密钥不作为 node identity，连接结束后即失效。

## Encrypted frame

```text
u32      ciphertext_length (17..1_048_576)
bytes    XChaCha20-Poly1305 ciphertext
```

明文第一个字节是 frame type，其后是 payload。四字节 length header 是 AEAD associated data。每个方向使用独立 session key；24 字节 nonce 的高 16 字节为零，低 8 字节为从零递增的 counter。连接绝不能重用 session key。

| Type | 值 | Payload |
|---|---:|---|
| `INVENTORY` | 1 | `u16 count` + 最多 256 个 event ID |
| `GET_EVENTS` | 2 | `u16 count` + 最多 256 个 event ID |
| `EVENT` | 3 | 一个完整 Event |
| `PING` | 4 | 空 |
| `PONG` | 5 | 空 |

收到缺少 parent 的 EVENT 时，节点将它放入有界 pending queue，并向来源 peer 请求缺失 ID。Parent 提交后重新检查 pending event。

## IRC boundary

IRC 只监听字面量 `127.0.0.1` 或 `::1`，最大 line 为 512 字节（含 CRLF）。`USER` 与 realname 不进入事件。`NAMES` 只反映连接同一本地 gateway 的客户端，不是全网 presence。

支持：`CAP`、`NICK`、`USER`、`PING/PONG`、`QUIT`、`JOIN/PART`、频道 `PRIVMSG`、`NAMES`、基础 `MODE` 与 `WHOIS`。0.2 不支持 direct message、账户、文件、全网 operator 或传播式 ban。
