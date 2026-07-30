# Monitoring Platform Witness

Witness 是部署在第三台独立 Windows 主机上的轻量租约仲裁进程。它不保存监控业务数据，只持久化每个集群的 owner、过期时间和单调递增 epoch，用于阻止两个中心节点同时写入或发送通知。

每个中心节点必须通过环境变量配置独立令牌，例如 `Witness__NodeTokens__center-a`。中心节点对应配置 `HighAvailability__WitnessBearerToken`，不得在仓库或日志中保存令牌。

Witness 必须使用受信任 HTTPS 证书。两台中心端只允许出站访问 Witness 端口；其他来源由防火墙拒绝。Witness 数据文件必须落在本机 NTFS，并纳入备份，不能放在两台中心节点任一节点上。

生产配置完成后，以提升的 PowerShell 安装。脚本要求 HTTPS 证书位于 `LocalMachine\My`、具有 Server Authentication EKU、至少剩余 7 天有效期，并同时按配置 subject 与 SHA-256 指纹固定；它只向 Witness 虚拟服务账号授予该私钥的读取权限。

```powershell
.\Install-WitnessService.ps1 -PackageRoot . `
  -WitnessConfigPath .\appsettings.Production.json `
  -HttpsCertificateSha256 '<HTTPS 证书 SHA-256 指纹>'
```

卸载默认保留程序与租约数据。只有在确认不再需要恢复 epoch 后，才可显式执行 `Uninstall-WitnessService.ps1 -RemoveData`。
