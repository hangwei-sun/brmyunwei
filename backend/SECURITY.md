# Backend security baseline

The API uses two independent authentication paths:

- Local console users authenticate at `POST /api/auth/login` and receive an ASP.NET Core bearer token.
- Agents use a registered client certificate when `AgentEnrollment` is enabled. The legacy `X-Agent-Name` / `X-Agent-Key` path is available only when enrollment is disabled or `AllowLegacyAgentKeys=true`, and is always rejected after an asset enters certificate mode. A console bearer token cannot call the ingest endpoint.

Only `/api/health` and `/api/auth/login` are anonymous. Viewer can read operational data, Operator can also acknowledge/silence/maintain incidents and read audit records, and Admin can manage users, assets, rules, notification policies, Agent keys, and SMS tests.

## Development login

`appsettings.Development.json` enables the local-only test account `admin` / `DevOnly-Admin-2026!`. This account is never loaded outside the Development environment.

## First production login

There is no production default password. On the first start, provide a one-time administrator through environment variables:

```powershell
$env:Authentication__BootstrapAdmin__Enabled = 'true'
$env:Authentication__BootstrapAdmin__Username = 'your-admin-name'
$env:Authentication__BootstrapAdmin__Password = 'a-unique-long-password'
```

After the first account is stored, remove these environment variables. Production must expose HTTPS only. Data Protection keys are persisted outside the repository and protected with Windows DPAPI. In an HA pair, DPAPI cannot protect a shared key ring: both nodes must instead share a protected key directory and use the same private-key certificate in `LocalMachine\My`, configured through `Authentication:DataProtectionCertificateThumbprint`.

The production Windows service runs as a virtual service account. `Install-Service.ps1` requires the SHA-256 fingerprints of the center HTTPS certificate and, when enrollment is enabled, the Agent issuing CA certificate; it grants that identity read access only to those RSA private-key files. Do not grant the service account broad access to the machine certificate store or run it as Administrator.

## Agent enrollment and mTLS

An Admin may call `POST /api/hosts/{name}/agent-key` for the compatibility path. The plaintext key is returned once; only its SHA-256 digest is stored. Rotating the key immediately invalidates the previous value. This path is only acceptable for isolated prerelease compatibility.

The preferred path is one-time enrollment. With `AgentEnrollment:Enabled=true`, an Admin calls `POST /api/hosts/{name}/enrollment-token`; the server stores only a SHA-256 token digest, binds it to the asset, limits its lifetime, and atomically marks it used. `POST /api/v1/agents/enroll` is anonymous only for the one-time token and is rate limited. The issuer is selected by both subject and SHA-256 fingerprint. The returned client certificate must have a matching host CN and Client Authentication EKU. At ingestion, the API verifies its validity, local trusted chain, registered SHA-256 fingerprint and expiry.

Certificate rotation uses a fresh one-time token and the same enrollment flow. The previous registered fingerprint remains valid only for the configured short grace period (15 minutes by default), which permits rollback while the Agent switches certificates. Admin `DELETE /api/hosts/{name}/agent-certificate` immediately clears both fingerprints but keeps the asset in certificate-required mode, preventing a downgrade to a shared key.

The implementation exists but has not yet passed a Windows Server 2012/2012 R2, enterprise CA, client-certificate rotation and rollback field trial. Do not claim mTLS readiness until those gates pass. Private keys, enrollment tokens, CA private keys and bearer tokens must never enter logs, source control, URLs or audit detail.

## Notification rollout

Tencent Cloud SMS uses a three-state guard: `disabled` sends nothing; `test` permits only configured E.164 test numbers; `live` permits configured production contact groups. Test the configured template, retry behavior and one-delivery-state-per-incident/policy deduplication with test numbers before setting `live`. A successful SDK call is not sufficient evidence of a safe rollout; retain request IDs, delivery status and deduplication observations.

Before calling Tencent Cloud, the worker persists an in-flight state. If the witness lease is lost during the external call, that state is not automatically retried. An Operator must reconcile it against Tencent Cloud and explicitly choose `retry`, `mark-sent`, or `stop`; this favors preventing a duplicate SMS storm over silently assuming delivery.

## HA boundary

The default configuration is single node (`HighAvailability:Enabled=false`). HA includes witness leases, fencing epochs, snapshot replication, a standby watcher and `/api/ready`, which reports HTTP 200 only for a database-connected writer holding a valid witness lease. The watcher can promote only after the primary ready check fails and the independent witness grants a new epoch; the promoted process must prove that same epoch through `/api/ready`. This is a deployment capability, not field evidence. Do not enable HA in production until the two-node/witness deployment, manual switch, service-loss switch, network-partition protection, old-node replay and controlled reverse-switch drills have passed.
