# 轻量化 Windows 机房运维监控平台

默认仍以 **单节点、隔离预发布** 运行。仓库同时提供双机 HA 的 witness fencing、备用节点自动接管监视器、快照回放和受控回切交付；必须在真实三节点环境完成切换演练后才能启用生产 HA。

## 当前能力

- React 19 运维控制台：总览、资产、事件、告警规则、通知策略、本地账号和角色权限。
- .NET 10 中心端：本地 Bearer 登录、`Admin / Operator / Viewer` RBAC、SQLite、审计和 HTTPS 托管。
- ICMP、TCP、HTTP(S) 探测：并发上限、超时、随机抖动、失败退避、连续失败/恢复状态机和事件去重。
- Windows Agent：`.NET Framework 4.8`，兼容 Windows Server 2012/2012 R2；仅出站 HTTPS、只读采集、无监听端口、无远程命令。
- Agent 指标：CPU、内存、磁盘、网络、启动时间、指定 Windows 服务；可识别失联、重启、服务停止和阈值异常。
- 腾讯云短信：完整通知策略契约、服务器组匹配、联系人组、重试退避、重复提醒和每事件/策略去重。具有 `disabled`、`test`、`live` 三态；预发布初始化为 `disabled`。
- 数据维护：原始指标保留、审计/事件保留、SQLite 在线备份、SHA-256 校验和停机恢复脚本。
- Agent 安全交付基础：一次性注册令牌、CSR 签发、mTLS 认证、客户端证书轮换、签名 MSI 与升级回滚脚本。它们尚未完成现场验收。
- HA 生产交付：witness 租约、fencing epoch、`/api/ready` 写入就绪检查、双节点控制端状态与入口切换、快照复制清单链、被动副本暂存、自动接管监视器、回放校验和受控人工回切脚本。真实双节点、witness 和恢复回放仍需现场验收。

## 验证

```powershell
npm test
npm run build
dotnet test .\backend\tests\MonitoringPlatform.Api.Tests.csproj -c Release
dotnet build .\agent\MonitoringPlatform.Agent.csproj -c Release
dotnet run --project .\agent\tests\MonitoringPlatform.Agent.SelfTests.csproj -c Release
```

自动化测试只能证明代码路径，不可替代现场验收。CI 同时执行依赖漏洞扫描。

## 安装包交付

发布管理员使用 [deployment/Publish-InstallerPackages.ps1](./deployment/Publish-InstallerPackages.ps1) 构建并签名三种 MSI：控制端、Witness 和 Agent。现场人员只需双击 MSI，并从开始菜单打开配置向导；不需要在控制端或被监控服务器输入命令。

控制端 A/B 仍必须共享数据保护密钥目录和同一张密钥证书，使用不同的 Witness 密钥；Witness 必须部署在第三台独立主机。Agent 通过控制台资产页生成的一次性安装码完成 mTLS 注册。完整的准备条件、点击顺序、双机填写示例、静默期与回滚条件见 [部署手册.md](./部署手册.md)，HA 演练见 [deployment/HA-双机生产切换与回放.md](./deployment/HA-双机生产切换与回放.md)。

## 明确限制

- 当前对外可运行范围仍是单节点隔离预发布。只有在 `HighAvailability.Enabled=false` 时 `/api/ha` 返回 `single-node`；不得据此把 HA 代码基础当作已验证高可用。
- HA 自动接管只在备用节点确认主节点 `/api/ready` 连续失败且 witness 授予新 epoch 后执行；计划切换与回切仍使用受控人工流程。没有共享受保护数据密钥环、独立 witness、负载均衡 ready 检查和完整演练证据时，不配置自动接管。
- 启用 `AgentEnrollment` 后默认禁止静态 Agent Key；注册成功的资产永久保持证书认证模式，除非重新注册，否则不能通过 Key 降级。一次性注册和 mTLS 仍必须通过 Windows Server 2012/2012 R2、证书信任与轮换回滚现场门禁。
- Agent 支持单位内网固定本地签名：使用不可导出的 Code Signing 叶证书签署 EXE、脚本和 MSI，服务器按带外核对的唯一指纹导入 Root/TrustedPublisher。更换签名证书、升级/卸载回滚和 Server 2012/2012 R2 实机结果仍是扩大范围前的门禁。
- 腾讯云短信必须依次完成 `disabled -> test -> live`：先只允许配置的测试号码验证模板、重试和去重；任何真实联系人启用前需通过对应证据。
- 自签预发布证书只用于隔离验收；生产必须替换为单位受信任证书。
- 未完成连续数日静默运行、真实 Windows Server 2012/2012 R2 资源测量、断网缓存、备份恢复及业务影响演练前，不进入生产上线评审。
