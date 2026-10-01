# Security policy

Kairc 处于 `0.x` 原型阶段，尚未经过独立安全审计。请先阅读 [威胁模型](docs/THREAT_MODEL.md)；不要依赖它保护生命安全、记者信源或其他高风险身份。

请通过 GitHub 仓库 **Security → Report a vulnerability** 私密报告漏洞，不要先建立公开 Issue。报告应包含受影响 commit、复现方式、攻击前提、实际影响和建议修复。

特别欢迎报告以下问题：签名或 AEAD 绕过、跨 network replay、parent closure 绕过、SOCKS5 DNS 泄漏、非 loopback IRC 暴露、无界内存/磁盘/线程消耗以及日志中的身份信息泄漏。

项目会确认报告、复现问题、协调修复和披露时间，但目前不承诺付费漏洞奖励或固定 SLA。
