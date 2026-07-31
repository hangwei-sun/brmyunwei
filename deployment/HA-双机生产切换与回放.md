# 双机 HA 生产切换与回放

## 先选择运行模式

- **两台模式（无 Witness）**：A/B 各自运行本地数据库，使用一个独立共享根目录保存快照和数据保护密钥；故障切换必须人工确认、先停旧节点再启新节点。该模式不能安全地在网络分区时自动判断主节点，也不能宣称“自动高可用”。
- **自动接管模式（推荐生产 HA）**：在第三个故障域部署轻量 Witness，使用租约和 fencing epoch 防止双主。Witness 可以使用单位已有的独立文件服务器/管理主机，不要求专门购买一台高配服务器，但不能与 A/B 共机、共盘。

下文的 Witness、自动接管和 fencing 步骤只适用于自动接管模式；两台模式请直接执行“人工切换”章节。

## 拓扑与硬性条件

- 控制端 A 与控制端 B 使用独立本机 NTFS SQLite、独立服务身份和同版本发布包；活动数据库不得放入 SMB。
- 两个节点必须共享受控的数据保护密钥环，并用同一张同时安装在 `LocalMachine\My` 的密钥环证书加密。将 `Authentication:DataProtectionKeysPath` 配为独立受控共享目录，并将 `DataProtectionCertificateThumbprint` 配为该证书指纹；否则备用节点不能解密数据库中的短信设置，也不应上线 HA。
- Witness（自动接管模式）位于第三个故障域，必须使用 HTTPS、独立本地数据盘和每个节点不同的 Bearer Token。
- 两端共享的仅是一个共享根目录下的 `snapshots` 和 `keys` 子目录。A/B 对该目录读写，普通用户无权限；复制间隔设为 30 秒。
- Agent 上报入口必须经内部负载均衡或 DNS 名称访问两个控制端。负载均衡只将 `/api/ready` 返回 HTTP 200 的节点设为可写后端；该端点同时检查数据库和 witness 写租约。
- 节点时间使用同一 NTP 源，误差不超过 1 秒。自动接管模式下 Witness 不可与任一控制端共机、共盘或共交换机。

## 配置

在 A 上配置 `ConfiguredRole=active`，在 B 上配置 `ConfiguredRole=passive`。两端均配置同一个 `ClusterId`、`WitnessUrl`、`ReplicationDirectory`，但必须配置不同的 `NodeId`、`WitnessBearerToken`、数据库和副本路径。两端还必须互相填写 `PublicUrl`、`PeerNodeId`、`PeerPublicUrl` 和 `PeerReadyUrl`，这样顶部“双节点”入口才能检查对端 ready 状态并跳转到对应控制端。生产推荐：TTL 60 秒、续租 15 秒、复制 30 秒、租约安全余量 5 秒。

每个节点通过受保护的服务环境设置自己的 witness Token，不把 Token 放到计划任务、命令历史或 JSON 配置文件：

```powershell
$token = Read-Host 'Witness token' -AsSecureString
.\Set-HaWitnessToken.ps1 -WitnessBearerToken $token
```

在两个节点分别安装自动接管监视器。每个监视器的 `PrimaryReadyUrl` 指向对端，`PromotedReadyUrl` 指向本机的证书名称；活动节点启动后会立即退出自己的监视器。计划切换期间不要启动刚降为 passive 节点的监视器，必须等对端确认 ready 后再显式启动。

在 B 上：

```powershell
.\Install-HaFailoverWatcher.ps1 `
  -NodeId 'monitor-b' -ClusterId 'monitoring-platform' `
  -WitnessUrl 'https://witness.example.local:9444/' `
  -PrimaryReadyUrl 'https://monitor-a.example.local:8443/api/ready' `
  -PromotedReadyUrl 'https://monitor-b.example.local:8443/api/ready' `
  -StandbyReplicaPath 'C:\ProgramData\MonitoringPlatform\data\standby-replica.db'
```

在 A 上使用相反的两个地址和 `NodeId`，再执行同一安装命令。不得让两个节点使用相同 `NodeId`、Token 或本机 ready 地址。

该计划任务以 `SYSTEM` 运行，只从本机服务注册表环境读取 witness Token，任务参数不包含秘密。它连续 3 次无法读取 A 的健康状态后才尝试提升；被 witness 拒绝时每 10 秒重试，直到旧租约过期。提升脚本必须确认 B 的 `/api/ready` 已在同一 fencing epoch 变为 `ready` 才完成。因此，A/B 网络分区、负载均衡误判、或 B 单独失联都不会使 B 越过 fencing 强行写入。

## 两台模式人工切换

1. 在 A 的控制台确认当前告警、复制序号和备份时间，先停止 A 的控制端服务并确认 A 的 `/api/ready` 不再返回可写。
2. 确认 A 已断电、断网或服务已停止后，再在 B 的控制端配置中将角色设为 active，启动 B 服务并检查 `/api/ready`、数据库和 Agent 心跳。
3. A 恢复后先保持停止状态，完成快照回放、SQLite 校验和业务探针检查；确认 B 正常后，按相反顺序人工回切。
4. 网络分区时不能仅凭页面状态决定切换；必须由值班人员通过现场/带外方式确认一台节点完全停止，再提升另一台。无法确认时保持两台只读/停止写入。

## 自动接管模式演练顺序

每一次演练均记录开始/结束时间、`/api/ha` 响应、witness epoch、快照 sequence、通知投递状态和业务探针结果。

1. 稳态：A 为 active，B 为 passive。确认 B 上 `Test-HaReplicaReplay.ps1` 成功，sequence 在 90 秒内持续增长。
2. 手动计划切换：先将 A 从负载均衡摘除，执行 `Set-HaNodePassive.ps1 -ConfirmDemotion`，等待至少一个 TTL；在 B 执行 `Invoke-HaPromotion.ps1 -ReadyUrl 'https://monitor-b.example.local:8443/api/ready' -ConfirmPromotion`。检查 B 的 `/api/ha` 为 active，且 epoch 大于 A 最后记录的 epoch，再将 B 加入写入池；最后在 A 执行 `Start-ScheduledTask -TaskName 'MonitoringPlatform-HaFailoverWatcher'`，恢复 A 对 B 的自动监视。
3. 死机自动接管：不优雅停止 A 服务或关闭 A。B 监视器只会在健康失败阈值和 A 租约过期后接管。检查旧节点租约失效、B 新 epoch、数据回放边界、单条短信没有重复以及站内信每用户最多一条。
4. 网络分区：阻断 A 到 witness 的 HTTPS，而保持 A 的局域网服务。A 必须在安全余量前拒绝写入/通知；B 在旧租约到期后获得新 epoch。恢复网络后，A 不得自动重新加入写入池。
5. 旧节点回放：恢复 A 前先断开其到业务网和 witness 的连接，运行 `Set-HaNodePassive.ps1 -ConfirmDemotion` 后再恢复网络；A 不加入负载均衡。等待 B 发布的快照被 A 暂存，运行 `Test-HaReplicaReplay.ps1`；完成 SQLite 校验和 sequence/epoch 校验前不得提升 A。
6. 回切：按“手动计划切换”反向操作。先让 B passive，再等待 TTL，随后提升已完成回放的 A；确认 A ready 后再在 B 启动其监视器。不得直接启动旧 A 为 active。

## 停止条件与回滚

立即停止扩大范围并回到单节点，若出现任一情形：两个节点同时报告 active、epoch 倒退、快照链/SQLite 校验失败、复制超过 90 秒未推进、任何重复短信、Agent 上报持续 503、或业务探针失败。

回滚时把负载均衡仅指向最后确认持有 witness 租约且数据库完整的节点，另一节点执行 `Set-HaNodePassive.ps1 -ConfirmDemotion`。不要从共享目录直接运行 SQLite，也不要复制 WAL/SHM 文件作为恢复方式。
