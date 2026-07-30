# Backend security baseline

The API uses two independent authentication paths:

- Local console users authenticate at `POST /api/auth/login` and receive an ASP.NET Core bearer token.
- Agents authenticate only with `X-Agent-Name` and `X-Agent-Key`. A console bearer token cannot call the ingest endpoint.

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

After the first account is stored, remove these environment variables. Production must expose HTTPS only. Data Protection keys are persisted outside the repository and protected with Windows DPAPI.

## Agent enrollment

An Admin calls `POST /api/hosts/{name}/agent-key`. The plaintext key is returned once; only its SHA-256 digest is stored. Configure the agent to send the host name and key over HTTPS. Rotating the key immediately invalidates the previous value.

The current HA API reports `single-node` and `failoverSupported: false`. No failover mutation endpoint exists because real coordination and fencing are not implemented.
