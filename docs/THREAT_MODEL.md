# Threat model

## 保护对象

- 消息内容与 nickname（仅私密频道）；
- 事件完整性和 network 隔离；
- IRC 客户端提交的本机资料；
- 用户网络地址（仅正确配置 Tor 时）；
- 节点可用性与有限的 CPU、内存、磁盘资源。

## 对手

1. 发送畸形 frame/event 的普通 peer。
2. 尝试伪造、篡改或重放消息的主动 peer。
3. 观察 direct TCP 或 Tor 局部路径的网络观察者。
4. 加入公开频道或已获得私密频道密钥的恶意成员。
5. 以大量连接、缺失 parent、inventory 或 PoW 事件消耗资源的 Sybil。
6. 已获得一个可信节点 key、频道共享密钥或运营者错误配置许可的内部/配置型对手。

## 已有控制

- libsodium Ed25519、X25519 与 XChaCha20-Poly1305；
- domain-separated BLAKE2b 内容寻址；
- network hash、时间窗口、PoW、signature 与 parent closure；Event ID 不含 signature，避免 author 用多份合法签名复用一次 PoW；
- 持久 Ed25519 peer identity 对临时 X25519 hello 签名、角色绑定、transcript confirmation，以及默认拒绝未知 peer；
- P2P 双向每认证 identity/全局 bytes、frame、EVENT token bucket、单 identity 会话上限、空闲超时和受限的远端验证并发；
- Server 先发 fresh responder cookie；未认证 cookie/hello I/O 有非阻塞有界队列、3 秒绝对期限、直接来源 reservation、声明 identity 与全局并发限制和廉价 allowlist 预检；只有通过身份签名的握手才消耗每 identity/全局 authenticated-handshake 预算并触发本地临时 key/签名生成；
- ID 重新计算后的 early dedup、重复 GET/INVENTORY ID 拒绝；
- event/frame/inventory/pending/每 peer pending/IRC line 上限；
- missing-parent 反向索引、receipt TTL、跨 epoch child 隔离和按相关依赖处理的 closure；
- 每小时 DAG 轮换、因果 layer + event ID 的最终确定顺序、短呈现窗口与显式 replay 标记；
- loopback-only IRC；
- SOCKS5 remote DNS；
- 私密 payload 的独立端到端 AEAD，并绑定外层签名事件上下文以拒绝密文换壳重放；
- SQLite 主文件/WAL/SHM 总预算、每 epoch 事件上限、WAL checkpoint、incremental vacuum 与按 epoch 保留；
- 本地 IRC client 与 P2P session 数量、本地发布速率均有硬上限；慢速写入和握手有超时。
- 可选 onion-only Kademlia 子集：签名 peer record、单 endpoint、短 TTL、持久 sequence watermark、普通/可信持久配额隔离、已验证 withdrawal anchor、exact-identity 拨号、身份级失败退避、固定 bucket/request/worker/session 上限、可信记录优先和发现会话轮换；

## 尚未闭合的高风险项

- DHT 仍需人工配置至少一个 bootstrap；没有自动 bootstrap 选择、多路径/运营者 diversity 证明或完整 eclipse 防护。尤其在 `open` 模式，攻击者可低成本生成大量签名 identity，竞争 replacement bucket、提供偏置的 `NODES` 响应并选择性转发；有界容量和可信优先只限制资源，不能消除 Sybil；
- 没有 RLN/匿名凭证，PoW 对资源强的攻击者效果有限；
- 分布式来源或高连接率的 onion 客户端仍可持续 churn hello 预读队列或争抢入站工作槽；满队列会替换最老未完成项以避免静默集合永久占位，但这些边界不是 DDoS 防护；
- 共享频道密钥只有需要重启并通过带外渠道协调的手动代际轮换；没有自动成员分发、在线撤销、sender ratchet 或完整前向保密；
- `allow_unknown_* = true` 会主动放弃 allowlist 准入，且持久 peer public key 会带来跨会话可关联性；
- 没有 cover traffic，时序与大小分析仍然有效；
- 没有正式 fuzzing campaign 或第三方密码学评审；本仓库的内部静态审计不能替代独立审计；
- 批量 Ed25519 验签、RLN 电路、Kademlia diversity/抗 eclipse 和群组密钥协议仍需单独协议与互操作性评审。

在这些项目完成前，Kairc 不应宣传为高风险人士可依赖的成熟匿名通信产品。
