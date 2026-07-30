# Windows Monitoring Agent

This is a deliberately small, read-only Windows Service for Windows Server 2012 and 2012 R2. It targets **.NET Framework 4.8**, the supported common runtime for both operating systems. It is not a modern `.NET` service, because Windows Server 2012 (non-R2) cannot safely be made a dependency on newer .NET runtime support.

## Boundaries

- No inbound listener, remote command, process control, restart, patching, or script execution.
- Reads CPU, memory, fixed-disk maximum usage, aggregate network throughput, OS boot time, and explicitly configured Windows service states.
- Samples every 15 to 3600 seconds (default 60); an initial 0 to 60 second deterministic jitter avoids simultaneous startup bursts.
- Uses TLS 1.2/HTTPS with normal certificate validation. In mTLS mode it sends `X-Agent-Name` with its registered client certificate and does not send an Agent Key.
- First attempts `PrimaryEndpoint`, then `SecondaryEndpoint` only after primary failure. It does not fan out every sample and therefore avoids normal duplicate reports.
- Sequence numbers are committed locally before collection. Pending reports are capped at 256 by default and old unsent telemetry is discarded first. Logs are capped at 1 MiB plus one archive.

The center endpoint accepts one metric sample per request. The Agent drains a bounded group using a reused HTTPS connection rather than opening parallel connections. The center persists network rate, boot time, Agent version and configured service states; it turns reboot, service failure, heartbeat loss and metric thresholds into deduplicated incidents.

## One-time enrollment and mTLS

The existing key headers are a transitional compatibility mechanism. When center enrollment is enabled with `AllowLegacyAgentKeys=false`, unenrolled Key clients are rejected; after an asset enters certificate mode it cannot fall back to a Key. This path has not completed a Windows Server 2012/2012 R2 and enterprise-CA field trial, so use only non-critical hardware until CA trust, rotation and rollback evidence is complete.

The intended, fail-closed contract is:

1. The center issues a short-lived, single-use enrollment token bound to one asset.
2. `Enroll-Agent.ps1` creates a non-exportable 2048-bit machine RSA key and PKCS#10 CSR using the Windows Server 2012-compatible Microsoft RSA SChannel CSP. The private key never leaves the server.
3. It posts `{ hostName, csrPem }` over verified HTTPS to `/api/v1/agents/enroll` with `X-Enrollment-Token`. The center response contains `certificateDerBase64` and `certificateSha256`; the script verifies the hash before `certreq -accept` imports it.
4. The script grants `LOCAL SERVICE` read access only to the associated CSP private-key file, writes the SHA-256 certificate fingerprint to the ACL-protected Agent configuration, and restarts the service.

Install the issuing CA and center TLS trust chain through the normal Windows certificate policy before enrolling. Optionally set `PinnedServerCertificateThumbprints` to SHA-256 leaf certificate hashes. Pinning never bypasses chain, expiry, or hostname validation.

Client certificate rotation is explicit, not autonomous: issue a fresh one-time token and run `Enroll-Agent.ps1` again. The center accepts the prior fingerprint only during its short rotation grace period, while the script switches configuration and restarts the service. The enrollment script restores its configuration if activation fails. During that grace window, `Rotate-AgentCertificate.ps1` can switch back to the previously registered certificate and validates its subject, EKU, private key and validity before rollback.

## Build and test

```powershell
dotnet build .\agent\MonitoringPlatform.Agent.csproj -c Release
dotnet run --project .\agent\tests\MonitoringPlatform.Agent.SelfTests.csproj -c Release
```

## Installation

1. Install .NET Framework 4.8 on the managed server and add the asset in the center.
2. Import the approved center TLS and Agent issuing CA chains. Use only an enterprise-signed Agent package, then install without starting:

```powershell
.\Install-Agent.ps1 -AgentName 'UAT-WEB-01' -DeferStartUntilEnrollment `
  -PrimaryEndpoint 'https://CONTROL-HOST:8443/api/v1/agents/ingest' `
  -ApprovedSignerThumbprint '<approved SHA-1 signer thumbprint>' `
  -WatchedServices 'W3SVC'
```

3. Have an Admin issue a short-lived token for the same asset, enter it on the managed server, and enroll:

```powershell
$token = Read-Host 'One-time enrollment token' -AsSecureString
.\Enroll-Agent.ps1 -AgentName 'UAT-WEB-01' `
  -EnrollmentEndpoint 'https://CONTROL-HOST:8443/api/v1/agents/enroll' `
  -IngestEndpoint 'https://CONTROL-HOST:8443/api/v1/agents/ingest' `
  -OneTimeEnrollmentToken $token `
  -ApprovedSignerThumbprint '<approved SHA-1 signer thumbprint>'
```

The installer and enrollment script reject HTTP, use `LOCAL SERVICE`, restrict the install/data/private-key ACLs, and never open an inbound port. Enrollment writes the real Agent name and ingest endpoint, clears any transitional Key, and starts the service only after the certificate is active.

Validate from the center dashboard that the heartbeat changes. For one interactive, non-service collection cycle use `MonitoringPlatform.Agent.exe --sample-once` from an elevated console. Do not use this mode in scheduled tasks.

## Signed package, upgrade, and removal

Publishing is intentionally not anonymous or self-signed. The release operator needs a trusted enterprise code-signing certificate with private key in `CurrentUser\My`, the Windows SDK `signtool.exe`, WiX Toolset v4, and an approved RFC 3161 timestamp service:

```powershell
.\Publish-SignedAgent.ps1 -CodeSigningCertificateThumbprint '<approved SHA-1 signer thumbprint>' `
  -TimestampServer 'https://timestamp.example.internal/rfc3161' -ProductVersion '1.0.0'
```

The build script fails if a signing prerequisite is absent and signs the executable, operational PowerShell scripts and MSI. `Verify-AgentPackage.ps1` fails unless Authenticode status is `Valid` and its signer thumbprint exactly matches the supplied approved signer. The installer verifies its own signature, the executable, and its verifier before accepting an Agent key. Run that verifier before any host rollout. The signed MSI, enterprise trust-chain validation and an upgrade/uninstall rollback test on Windows Server 2012/2012 R2 are hard rollout gates. Do not use `-SkipPublisherCheck`, `Unblock-File`, self-signed production certificates, or a bypassed execution policy as a substitute for signing.

Upgrade preserves the installed configuration and local queue, requires the exact approved signer, and retains executable/configuration rollback files:

```powershell
.\Upgrade-Agent.ps1 -PackageRoot 'D:\release\agent-1.0.0' `
  -ApprovedSignerThumbprint '<approved SHA-1 signer thumbprint>'
```

To remove the service while retaining troubleshooting telemetry, run `Uninstall-Agent.ps1 -ApprovedSignerThumbprint '<approved SHA-1 signer thumbprint>'`. Add `-RemoveData` only for the explicit destructive removal path.

Validate script syntax before packaging:

```powershell
.\Test-AgentScripts.ps1
```

## Resource acceptance

After at least 3 minutes of normal operation, run:

```powershell
.\Measure-AgentResource.ps1 -DurationSeconds 180
```

The production gate is average CPU at or below 0.2% and working set at or below 25 MiB. The self-test also caps a worst-case 32-service telemetry body at 16 KiB; with the default one-minute upload interval this remains below the 50 KiB/minute network budget after normal HTTPS overhead. Increase the interval or reduce watched services if any gate fails; do not expand the rollout while over budget.
