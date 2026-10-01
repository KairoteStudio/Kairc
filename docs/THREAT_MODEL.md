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

## 已有控制

- libsodium Ed25519、X25519 与 XChaCha20-Poly1305；
- domain-separated BLAKE2b 内容寻址；
- network hash、时间窗口、PoW、signature 与 parent closure；
- event/frame/inventory/pending/IRC line 上限；
- 每小时 DAG 轮换和保留窗口；
- loopback-only IRC；
- SOCKS5 remote DNS；
- 私密 payload 的独立端到端 AEAD，并绑定外层签名事件上下文以拒绝密文换壳重放；
- 本地 IRC client 与 P2P session 数量、本地发布速率均有硬上限；慢速写入和握手有超时，长期运行时按 epoch 持续清理 store 和 pending event。

## 尚未闭合的高风险项

- 没有 peer discovery 信誉或 eclipse 防护；
- 没有 RLN/匿名凭证，PoW 对资源强的攻击者效果有限；
- direct TCP 临时握手没有持久身份认证，主动 MITM 可观察公开流量并阻断事件；
- 共享频道密钥没有轮换、撤销与前向保密；
- 没有 cover traffic，时序与大小分析仍然有效；
- 没有正式 fuzzing campaign、第三方密码学评审或安全审计；
- inbound peer 与长期运行资源治理仍属于原型级别。

在这些项目完成前，Kairc 不应宣传为高风险人士可依赖的成熟匿名通信产品。
