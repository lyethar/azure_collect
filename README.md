# azure_collect

> **Azure / Entra ID collection and tool orchestration for authorized security assessments.**

`azure_collect.py` is a single-file Python orchestration script that handles authentication, token retrieval, and execution of the four primary Azure and Entra ID collection tools used during cloud penetration tests — in a single command.

```
   ___   ____  __  ____  ____  ____  ____  __    __    ____  ___  ____
  / _ | |_  / / / / __ \/ __/ / __/ / __/ / /   / /   / __/ / _/ /_  /
 / __ |_/_ < / /_/ /_/ / /__ / _/  / _/  / /__ / /__ / _/  / /_  / /_
/_/ |_/____//____|____/\___/ \___/ /_/   /____//____//___/ /___/ /___/
```

---

## What it does

| Stage | Tool | Description |
|-------|------|-------------|
| 1 | `az cli` | Authenticates to the tenant |
| 2 | `az cli` | Retrieves Graph tokens from both the **v1** (legacy) and **v2** (modern) endpoints |
| 3 | [roadrecon](https://github.com/dirkjanm/ROADtools) | Feeds the legacy token to `roadrecon gather` for full Entra ID enumeration |
| 4 | [azurehound](https://github.com/BloodHoundAD/AzureHound) | Feeds the modern token to `azurehound list` for BloodHound CE ingestion |
| 5 | [EntraFalcon](https://github.com/CompassSecurity/EntraFalcon) | Runs a comprehensive Entra ID security posture assessment |

**Tools are downloaded automatically** at runtime if not present on disk, and deleted immediately after execution.

---

## Requirements

### Python

- Python 3.10+
- No external Python dependencies — stdlib only

### System tools

| Tool | Install |
|------|---------|
| [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) | `winget install Microsoft.AzureCLI` |
| [roadrecon](https://github.com/dirkjanm/ROADtools) | `pip install roadrecon` |
| [PowerShell 7+](https://github.com/PowerShell/PowerShell) | `winget install Microsoft.PowerShell` |

`azurehound` and `EntraFalcon` are downloaded automatically if not found.

---

## Installation

```bash
git clone https://github.com/your-org/azure_collect
cd azure_collect
```

No `pip install` required.

---

## Usage

### Quickstart — full collection, browser auth

```bash
python azure_collect.py --tenant <TENANT_ID>
```

### Device code (useful over SSH or when no browser is available)

```bash
python azure_collect.py --tenant <TENANT_ID> --auth device-code
```

### Reuse an existing `az` session

```bash
python azure_collect.py --tenant <TENANT_ID> --skip-login
```

### Service principal

```bash
python azure_collect.py --tenant <TENANT_ID> --auth sp \
    --client-id <APP_ID> \
    --client-secret <SECRET>
```

### Run only specific stages

```bash
# Tokens + roadrecon only
python azure_collect.py --tenant <TENANT_ID> --stages tokens roadrecon

# azurehound + EntraFalcon only (reuses existing az session)
python azure_collect.py --tenant <TENANT_ID> --skip-login --stages azurehound entrafalcon
```

### Use locally installed tools instead of auto-downloading

```bash
python azure_collect.py --tenant <TENANT_ID> \
    --azurehound "C:/Tools/azurehound.exe" \
    --entrafalcon "C:/Tools/EntraFalcon/run_EntraFalcon.ps1"
```

### Disable auto-download entirely

```bash
python azure_collect.py --tenant <TENANT_ID> --no-auto-download
```

---

## Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--tenant` | *(required)* | Entra ID tenant ID (GUID) |
| `--auth` | `browser` | Auth method: `browser`, `device-code`, `sp` |
| `--skip-login` | — | Skip `az login` and reuse an existing session |
| `--client-id` | — | Service principal client ID (`--auth sp` only) |
| `--client-secret` | — | Service principal client secret (`--auth sp` only) |
| `--output` | `azure_collect_<timestamp>` | Output directory |
| `--stages` | all | Whitelist of stages to run |
| `--azurehound` | `azurehound` (PATH) | Path to azurehound binary |
| `--entrafalcon` | `C:\...\run_EntraFalcon.ps1` | Path to run_EntraFalcon.ps1 |
| `--no-auto-download` | — | Disable automatic tool download from GitHub |

---

## Output layout

```
azure_collect_<timestamp>/
├── tokens/
│   ├── graph_modern.token          # Raw modern Graph JWT
│   ├── graph_legacy.token          # Raw legacy Graph JWT
│   ├── graph_modern_claims.json    # Decoded modern token claims
│   └── graph_legacy_claims.json    # Decoded legacy token claims
├── roadrecon/
│   ├── roadrecon.db                # SQLite database
│   └── roadrecon.html              # Interactive graph report
├── azurehound/
│   └── azurehound.json             # BloodHound CE import file
└── entrafalcon/
    └── ...                         # EntraFalcon HTML report and findings
```

---

## Token strategy

Two tokens are retrieved from the authenticated `az` session, targeting different Graph endpoints:

| Token | Endpoint | Used by |
|-------|----------|---------|
| **Legacy** | `graph.windows.net` (v1 OAuth2) | roadrecon |
| **Modern** | `graph.microsoft.com` (v2 OAuth2) | azurehound |
| **ARM** | `management.azure.com` | azurehound (resource enumeration) |

Tokens are redeemed silently from the MSAL cache via `az account get-access-token` — no second browser prompt.

---

## Auto-download behaviour

When `azurehound` or `EntraFalcon` are not found at the specified path:

1. The latest release is resolved via the GitHub API
2. The asset is downloaded to a temporary directory inside the output folder
3. The tool is executed
4. The temporary directory is deleted immediately after execution

The platform and architecture are detected automatically for `azurehound` (`windows/amd64`, `linux/amd64`, `darwin/arm64`, etc.).

---

## BloodHound CE Queries

The repository includes `entrafalcon_bloodhound_queries.json` — 85 custom Cypher queries for BloodHound CE, built to mirror each of EntraFalcon's nine enumeration areas. Once you have imported the `azurehound.json` collection into BloodHound CE, these queries let you explore the same attack surface EntraFalcon surfaces in its HTML reports, but as interactive graphs with full path visualisation.

### Coverage

| Category | Queries | EntraFalcon Source Module |
|----------|---------|---------------------------|
| Groups | 12 | `check_Groups.psm1` |
| Enterprise Apps | 12 | `check_EnterpriseApps.psm1` |
| Users | 11 | `check_Users.psm1` |
| Attack Paths | 10 | Cross-cutting / risk scoring |
| Roles | 10 | `check_Roles.psm1` |
| App Registrations | 8 | `check_AppRegistrations.psm1` |
| Tenant | 7 | `check_Tenant.psm1` |
| Managed Identities | 6 | `check_ManagedIdentities.psm1` |
| Conditional Access | 5 | `check_CAPs.psm1` |
| PIM | 4 | `check_PIM.psm1` |

### Importing into BloodHound CE

BloodHound CE only supports query import via its API. Use the Compass Security import script from their [`bloodhoundce-resources`](https://github.com/CompassSecurity/bloodhoundce-resources) repository:

```powershell
# Clone the import script
git clone https://github.com/CompassSecurity/bloodhoundce-resources
cd bloodhoundce-resources

# Import the queries (adjust the path to point at this repo's JSON)
./scripts/Import-BloodHoundCECustomQueries.ps1 `
    -BloodHoundUrl "http://localhost:8080" `
    -QueryFile "/path/to/entrafalcon_bloodhound_queries.json"
```

Once imported, all 85 queries appear in BloodHound CE under **Custom Queries**, grouped by category with the `[EntraFalcon]` prefix.

### Query examples

A representative sample from each major category:

**Groups — Users Who Can Inject Into Privileged Groups**
```cypher
MATCH p = (u:AZUser)-[:AZAddMembers]->(g:AZGroup)
    -[:AZGlobalAdmin|AZPrivilegedRoleAdmin|AZUserAccessAdministrator|AZOwner|AZContributor]
    ->(:AZTenant)
WHERE u.enabled = true
RETURN p LIMIT 500
```

**Enterprise Apps — Service Principals with Global Admin**
```cypher
MATCH p = (sp:AZServicePrincipal)-[:AZGlobalAdmin]->(:AZTenant)
RETURN p LIMIT 500
```

**Managed Identities — VMs Whose Managed Identity Has Elevated Roles**
```cypher
MATCH p = (vm:AZVM)-[:AZManagedIdentity]->(sp:AZServicePrincipal)
    -[:AZOwner|AZContributor|AZGlobalAdmin]->()
WHERE sp.serviceprincipaltype = 'ManagedIdentity'
RETURN p LIMIT 500
```

**Roles — Paths to Global Admin via Group Membership**
```cypher
MATCH p = (u:AZUser)-[:AZMemberOf*1..3]->(g:AZGroup)-[:AZGlobalAdmin]->(:AZTenant)
WHERE u.enabled = true
RETURN p LIMIT 500
```

**Conditional Access — Users Who Can Modify CA Exclusion Groups**
```cypher
MATCH p = (u:AZUser)-[:AZAddMembers|AZOwns|AZGenericWrite]->(g:AZGroup)
WHERE g.capexclusiongroup = true AND u.enabled = true
RETURN p LIMIT 500
```

**Attack Path — App Owner → Subscription Owner via Service Principal**
```cypher
MATCH p = (u:AZUser)-[:AZOwns]->(a:AZApp)
    <-[:AZRunAs]-(sp:AZServicePrincipal)-[:AZOwner]->(:AZSubscription)
WHERE u.enabled = true
RETURN p LIMIT 500
```

**Attack Path — On-Premises Synced Account → Cloud Subscription Owner**
```cypher
MATCH p = allShortestPaths((u:AZUser)-[*1..6]->(:AZSubscription))
WHERE u.onpremsyncenabled = true AND u.enabled = true
  AND ANY(r IN relationships(p) WHERE type(r) = 'AZOwner')
RETURN p LIMIT 200
```

### Note on Conditional Access queries

BloodHound CE does not natively collect Conditional Access Policy data. The five CA-category queries rely on a `capexclusiongroup` property on `AZGroup` nodes that is not populated by standard `azurehound` collection. To use them, tag the relevant group nodes after cross-referencing with EntraFalcon's output:

```cypher
// Tag a group as a CA exclusion group by its object ID
MATCH (g:AZGroup {objectid: '<GROUP_OBJECT_ID>'})
SET g.capexclusiongroup = true
```

The remaining 80 queries work against any standard azurehound dataset without modification.

---

- This tool is intended for use during **authorized security assessments only**. Always ensure you have written permission before running any collection against a tenant.
- `az cli` authentication is handled by Microsoft's MSAL library — credentials are never handled or stored by this script.
- Raw token files are written to the output directory. Treat the output folder as sensitive material.

---

## License

MIT
