# 0.4 hardening status

这份表把 2026-10-01 的协议评审意见拆成“已经进入代码的边界”和“不能用临时方案冒充完成的协议工作”。它是实现状态，不是安全承诺。

| 评审项 | 0.4 状态 | 当前控制 | 下一阶段验收条件 |
|---|---|---|---|
| 频道密钥泄漏 | 部分完成 | 替换 secret 会产生隔离的新 channel tag，可带外进行成员移除和密钥代际轮换 | 定义成员 credential、签名 key package、自动 epoch commit、撤销、防回滚、乱序恢复和 sender ratchet；通过独立密码学评审 |
| PoW / Sybil | 边界已加固，RLN 未实现 | 默认 peer allowlist；身份级/全局 bytes、frame、event token bucket；fresh responder cookie、非阻塞 pre-auth I/O、身份级/全局握手预算；验证工作池；pending 和磁盘配额 | 独立 RLN RFC；可复现 circuit/parameters；membership root 与 nullifier 生命周期；double-signal、撤销和恢复测试 |
| DAG 聊天顺序 | 已实现最终确定呈现 | 持久 causal layer；`(epoch, layer, event ID)` canonical history；750 ms 呈现窗口；IRCv3 `server-time`、`batch`、replay tag | 分区、重连、跨 epoch 和随机到达顺序的模型测试；客户端互操作矩阵 |
| Ed25519 验签负载 | 已做有界替代 | Event v2 ID 只覆盖 unsigned event，不能以多份 signature 复用一次 PoW；ID 重算后 early dedup；固定验证并发；peer/global event rate | 在不破坏一次性 author key 与失败隔离的前提下评估 batch verify；只有 benchmark 和安全分析支持时才改 wire format |
| Peer discovery | 轻量实现，抗 Sybil 未完成 | onion-only 签名 record；单 endpoint exact-identity 验证；TTL/tombstone/持久高水位；普通身份配额与本机/可信保留区；256 个有界 XOR bucket；`FIND_NODES`/`NODES`；pinned bootstrap；trusted/open 模式；可信准入优先、不可由 record churn 清零的身份级拨号退避和 5 分钟 session 轮换 | 独立 bootstrap、多路径与 bucket diversity；eclipse/grinding 仿真；抗 Sybil 身份成本或匿名 credential；长期 churn/时钟/重启互操作测试 |
| SQLite/WAL | 已实现硬上限 | DB/WAL/SHM 总预算；每 epoch event 上限；`max_page_count`、WAL checkpoint、journal limit、incremental vacuum | 长期 soak、断电恢复、磁盘满故障注入与冷热分层归档 |

## 为什么没有直接写一个“简易 ratchet”

多成员聊天中的前向保密不是把静态 key 再 hash 一次。协议必须解决并发发送者、乱序/丢包、设备新增、成员移除、旧状态恢复、恶意 commit、身份匿名性和状态持久化。没有这些状态机，所谓按消息换 key 很容易造成永久失步，或者保留一个能重新导出全部历史的 master secret，从而只得到“看起来轮换”的结果。

0.4 因此只把手动 secret replacement 明确定义为密钥代际边界：新成员只拿新代际，被移除成员拿不到新代际；旧 secret 删除后，新 secret 泄漏不会自动推导旧 secret。但一个代际内部仍没有前向保密。自动群组密钥协议会单独版本化，不能静默塞进 Event v2。

## 为什么没有把普通限流叫作 RLN

当前 token bucket 和 peer pinning 是可审计的工程防线，但它们不提供匿名 membership proof，也不能生成或检查 RLN nullifier。未来实现只有在包含 proof verification、root 更新、double-signal 处理和公共参数供应链后，才能在配置或文档中使用 RLN 名称。

## 发布门槛

`0.4.0-dev` 可以作为实验网络发布，但必须保留原型警告。达到公开匿名网络候选前，至少还需要：

1. DHT eclipse/grinding 与 bootstrap/路径多样性测试；
2. 自动成员密钥协议的独立密码学评审；
3. parser/wire format fuzzing 和长期资源 soak；
4. RLN 或另一种有明确匿名与撤销语义的 proof 系统；
5. 第三方复核当前 peer handshake、持久化和隐私文档。
