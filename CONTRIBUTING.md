# Contributing to Kairc

感谢你帮助 KairoteStudio 建设一个开放的实时通信网络。

提交代码前请先用 Issue 或 Discussion 说明较大的协议变化。涉及服务器互联、身份、历史存储或权限模型的改动需要先写 RFC；修复 bug、补测试和改善文档可直接提交 Pull Request。

本地检查：

```bash
gofmt -w cmd internal
go test -race ./...
go vet ./...
go build ./cmd/kaircd
```

Pull Request 应保持单一主题，并说明用户可观察到的行为变化、兼容性影响和测试方式。新增协议命令时，请同时更新 `docs/PROTOCOL.md` 并至少加入一个正常路径和一个拒绝路径测试。

安全漏洞请遵循 [SECURITY.md](SECURITY.md)，不要先公开复现细节。
