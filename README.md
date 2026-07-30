# 轻量化 Windows 机房运维监控平台

当前版本定位为 **单节点、隔离预发布**。主备、自动故障转移和生产上线评审暂缓；先在一台 Windows 11 控制端和 1 至 2 台非关键 Windows 服务器上静默运行并收集证据。

## 当前能力

- React 19 运维控制台：总览、资产、事件、告警规则、通知策略、本地账号和角色权限。
- .NET 10 中心端：本地 Bearer 登录、`Admin / Operator / Viewer` RBAC、SQLite、审计和 HTTPS 托管。
- ICMP、TCP、HTTP(S) 探测：并发上限、超时、随机抖动、失败退避、连续失败/恢复状态机和事件去重。
- Windows Agent：`.NET Framework 4.8`，兼容 Windows Server 2012/2012 R2；仅出站 HTTPS、只读采集、无监听端口、无远程命令。
- Agent 指标：CPU、内存、磁盘、网络、启动时间、指定 Windows 服务；可识别失联、重启、服务停止和阈值异常。
- 腾讯云短信：完整通知策略契约、服务器组匹配、联系人组、重试退避、重复提醒和每事件/策略去重。预发布默认关闭真实短信。
- 数据维护：原始指标保留、审计/事件保留、SQLite 在线备份、SHA-256 校验和停机恢复脚本。
- Windows 发布：中心端 `win-x64` 自包含包；Agent 为 `net48` 轻量包。

## 验证

```powershell
npm test
npm run build
dotnet test .\backend\tests\MonitoringPlatform.Api.Tests.csproj -c Release
dotnet build .\agent\MonitoringPlatform.Agent.csproj -c Release
dotnet run --project .\agent\tests\MonitoringPlatform.Agent.SelfTests.csproj -c Release
```

当前自动化覆盖 9 项前端测试、10 项后端安全/探测/Agent/通知/备份测试和 Agent 自测。CI 同时执行依赖漏洞扫描。

## 生成预发布包

```powershell
.\deployment\Publish-Release.ps1 -Version 0.2.0-rc.1
```

发布包位于 `artifacts\monitoring-platform-0.2.0-rc.1-win-x64.zip`。解压后运行 `Initialize-IsolatedPrerelease.ps1`，可在当前用户目录初始化 90 天 HTTPS 隔离实例。完整接入、静默测量、备份恢复和停止条件见 [部署手册.md](./部署手册.md)。

## 明确限制

- 当前为单节点。`/api/ha` 明确返回 `single-node`，不存在伪切换接口。
- Agent 目前使用每主机静态高熵 Key，尚未实现一次性注册和 mTLS；只允许在隔离灰度网段使用。
- 自签预发布证书只用于隔离验收；生产必须替换为单位受信任证书。
- 未完成连续数日静默运行、真实 Windows Server 2012 资源测量和恢复演练前，不进入生产上线评审。
