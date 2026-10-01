# Contributing

Kairc 把匿名性和协议可审计性放在功能数量之前。修改 wire format、密码学、身份、Event Graph admission、Tor routing 或 retention 时，必须同时更新 RFC/协议文档并说明隐私影响。

构建与测试：

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/kaircd --config config/kairc.conf.example --check-config
```

需要 loopback socket 的双节点集成测试默认关闭；在本机或 CI 中可用
`-DKAIRC_ENABLE_INTEGRATION_TESTS=ON` 配置独立 build 目录后通过 `ctest` 运行。

Pull Request 应保持单一主题，包括正常路径、拒绝路径和资源边界测试。不要引入自行设计的密码算法；优先使用 libsodium 已审计原语。安全漏洞请按 [SECURITY.md](SECURITY.md) 私密报告。
