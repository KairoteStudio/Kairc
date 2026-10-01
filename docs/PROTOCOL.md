# Kairc v0.1 协议兼容范围

Kairc 接受以 CRLF 结尾的 IRC 文本消息。为了方便简单客户端，也接受仅 LF 结尾。包含 CR/LF/NUL 注入或超过 512 字节（含 CRLF）的消息会被拒绝。

## 注册前命令

| 命令 | 状态 | 备注 |
|---|---|---|
| `CAP LS/LIST/REQ/END` | 支持 | v0.1 不公布 capability，所有 `REQ` 返回 `NAK` |
| `PASS` | 接受 | 当前忽略；不代表完成认证 |
| `NICK` | 支持 | ASCII 昵称，最多 24 字节，RFC 1459 casemap |
| `USER` | 支持 | 完成昵称与 USER 后注册 |
| `PING` / `PONG` | 支持 | 可在注册前使用 |
| `QUIT` | 支持 | 可在注册前使用 |

## 已注册命令

| 命令 | 状态 | 备注 |
|---|---|---|
| `JOIN` / `PART` / `QUIT` | 支持 | 支持逗号分隔的多个频道；`JOIN 0` 离开全部 |
| `PRIVMSG` / `NOTICE` | 支持 | 频道和昵称目标；频道启用 no-external-message |
| `TOPIC` | 支持 | 查询开放；修改需要 operator |
| `NAMES` / `LIST` / `WHO` / `WHOIS` | 支持 | 返回基础可见信息 |
| `MODE` | 部分支持 | 查询 `+nt`；支持 operator 的 `+o` / `-o` |
| `KICK` | 支持 | 需要频道 operator |
| `MOTD` / `LUSERS` / `VERSION` / `TIME` | 支持 | 基础服务器信息 |
| `AWAY` | 部分支持 | 返回状态 numeric，暂不持久保存 away message |
| `ISON` | 支持 | 查询在线昵称 |

## 尚未支持

- SASL、账户注册、昵称保留
- `OPER` 与全局 IRC operator
- `INVITE`、ban/key/limit 等频道模式
- IRCv3 message tags、server-time、echo-message、batch
- 服务端互联和网络级昵称同步
- 消息历史、离线消息、附件和富文本

客户端必须把未知 numeric 和未知命令错误视为可恢复情况。服务端不承诺消息顺序跨越不同 TCP 连接，但同一连接提交到同一频道的事件按 hub 接收顺序处理。
