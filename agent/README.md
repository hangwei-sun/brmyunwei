# Windows Monitoring Agent

This is a deliberately small, read-only Windows Service for Windows Server 2012 and 2012 R2. It targets **.NET Framework 4.8**, the supported common runtime for both operating systems. It is not a modern `.NET` service, because Windows Server 2012 (non-R2) cannot safely be made a dependency on newer .NET runtime support.

## Boundaries

- No inbound listener, remote command, process control, restart, patching, or script execution.
- Reads CPU, memory, fixed-disk maximum usage, aggregate network throughput, OS boot time, and explicitly configured Windows service states.
- Samples every 15 to 3600 seconds (default 60); an initial 0 to 60 second deterministic jitter avoids simultaneous startup bursts.
- Uses TLS/HTTPS with normal certificate validation. It sends `X-Agent-Name` and `X-Agent-Key` only to configured HTTPS center endpoints.
- First attempts `PrimaryEndpoint`, then `SecondaryEndpoint` only after primary failure. It does not fan out every sample and therefore avoids normal duplicate reports.
- Sequence numbers are committed locally before collection. Pending reports are capped at 256 by default and old unsent telemetry is discarded first. Logs are capped at 1 MiB plus one archive.

The center endpoint accepts one metric sample per request. The Agent drains a bounded group using a reused HTTPS connection rather than opening parallel connections. The center persists network rate, boot time, Agent version and configured service states; it turns reboot, service failure, heartbeat loss and metric thresholds into deduplicated incidents.

## Build and test

```powershell
dotnet build .\agent\MonitoringPlatform.Agent.csproj -c Release
dotnet run --project .\agent\tests\MonitoringPlatform.Agent.SelfTests.csproj -c Release
```

## Installation

1. Install .NET Framework 4.8 on the managed server. In the center console, add the server and rotate its Agent key.
2. Import the approved prerelease/public CA certificate, then use an elevated PowerShell in the published Agent directory:

```powershell
$key = Read-Host 'Agent Key' -AsSecureString
.\Install-Agent.ps1 -AgentName 'UAT-WEB-01' -AgentKey $key `
  -PrimaryEndpoint 'https://CONTROL-HOST:8443/api/v1/agents/ingest' `
  -WatchedServices 'W3SVC'
```

The installer rejects HTTP, uses `LOCAL SERVICE`, restricts the install/data ACLs, and never opens an inbound port. The Agent key remains a secret in the ACL-protected service configuration.

Validate from the center dashboard that the heartbeat changes. For one interactive, non-service collection cycle use `MonitoringPlatform.Agent.exe --sample-once` from an elevated console. Do not use this mode in scheduled tasks.

## Resource acceptance

After at least 3 minutes of normal operation, run:

```powershell
.\Measure-AgentResource.ps1 -DurationSeconds 180
```

The production gate is average CPU at or below 0.2% and working set at or below 25 MiB. The self-test also caps a worst-case 32-service telemetry body at 16 KiB; with the default one-minute upload interval this remains below the 50 KiB/minute network budget after normal HTTPS overhead. Increase the interval or reduce watched services if any gate fails; do not expand the rollout while over budget.
