# HA 受控切换与恢复回放演练

## 状态与边界

当前可运行范围是单节点隔离预发布。仓库已包含 witness HTTPS 租约、epoch fencing、SQLite 快照复制清单链、被动副本暂存、`Set-HaNodePassive.ps1` 和 `Invoke-HaPromotion.ps1`，但尚未在真实双节点和真实 witness 环境完成验证。

这不是自动故障转移方案。不得配置自动提升、DNS 自动漂移或依赖“节点失联即切换”。任何切换都必须在批准窗口由两名运维复核，以受控人工流程完成。

## 演练前置条件

1. 两台同版本控制端，各自使用独立服务身份、HTTPS 证书、数据目录和防火墙白名单；被动端不能接受生产 Agent 写入。
2. 独立 witness 提供 HTTPS `PUT /v1/leases/{clusterId}`，为单个 owner 保存租约和递增 epoch；其数据与两个控制端故障域隔离。必须验证鉴权、时钟同步、断连、重启和拒绝旧 epoch。
3. 复制目录必须是两节点都能访问的独立快照传输位置，仅允许两台控制端机器/服务身份读写，且不得与 SQLite 数据库目录混用。模板使用受控 SMB 快照共享；SQLite 运行库和被动副本始终位于各节点本机 NTFS，严禁把活动 SQLite 放到 SMB。每次快照的 SHA-256 和清单链都要保存，并现场验证共享语义、权限和断连行为。
4. 两节点均启用单位受信任 TLS，Agent mTLS 与固定本地签名或单位签名 MSI 已在 Windows Server 2012/2012 R2 非关键机器通过现场验收。
5. 腾讯云短信保持 `disabled` 或仅测试号码的 `test`。切换演练不得向真实联系人发送短信。

Witness 使用发布包 `witness\Install-WitnessService.ps1` 安装，必须传入单位受信任 HTTPS 证书的 SHA-256 指纹。服务脚本会验证配置 subject、`LocalMachine\My`、Server Authentication EKU 和私钥，并向虚拟服务账号授予最小读取权限；缺少任一项即停止安装。

## 受控人工提升

1. 记录故障时间、旧活动节点 `/api/health` 与 `/api/ha`、witness 当前 owner/epoch、被动端最后复制的清单 sequence/epoch/SHA-256。
2. 物理或网络隔离旧活动节点，或等待其 witness 租约明确过期；没有这一步不得继续。仅“看不到心跳”不是 fencing 证据。
3. 在被动端验证副本文件的 SQLite 完整性检查和清单链。确认业务、备份与当前排队通知的可接受恢复点目标。
4. 两名复核人确认后，以提升 PowerShell 运行 `Invoke-HaPromotion.ps1 -ConfirmPromotion`，传入节点、集群、witness、令牌和已验证副本。脚本会重新取得 witness 租约，停止本地服务，保留旧数据库/配置，写入 active 配置并启动服务；健康检查失败会尝试回滚本机改动。
5. 观察新活动节点至少一个租约周期，确认 `/api/health`、`/api/ha`、事件状态和通知投递状态。旧活动节点继续保持隔离。

## 恢复回放与回切

1. 修复旧节点后，不得直接启动为 active。先备份其残留数据和日志，再用 `Set-HaNodePassive.ps1 -ConfirmDemotion` 配置为 passive，等待至少一个租约 TTL。
2. 被动端只暂存通过 SHA-256 和清单链校验的最新快照。比对资产、事件、审计、通知投递状态和 SQLite `integrity_check`；记录缺失窗口与回放结果。
3. 要回切时，把当前活动节点按同一 fencing 流程降为 passive，确认其租约失效、复制完成，再人工提升目标节点。不得同时存在两个 active 节点。
4. 对同一故障验证每个事件/策略只有一条投递状态；确认切换与回放没有造成重复短信、漏发或重复恢复事件。

## 演练失败即停止

以下任一情形停止演练、保留证据并回到单节点：witness 可被双 owner 获取、epoch 倒退、清单链或 SHA-256 校验失败、SQLite 完整性失败、两个节点同时写入、健康检查失败、重复/漏发通知、业务延迟异常，或无法恢复到已知备份。完成至少一次计划内切换、一次故障切换、一次回放回切并形成证据前，不进入生产 HA 评审。
