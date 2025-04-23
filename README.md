# MDE Threat Hunter

Minimal threat hunting with Microsoft Defender for Endpoint.

## Setup

1. Set up 1Password secrets:
   - Create item "MDE API Credentials" in "Security Automation" vault
   - Add fields: `MDE_TENANT_ID`, `MDE_CLIENT_ID`, `MDE_CLIENT_SECRET`
   - Set GitHub secret: `OP_SERVICE_ACCOUNT_TOKEN_READ`

2. Add your KQL queries to `queries/`

3. Hunting runs every 6 hours or on-demand

## Queries

All `.kql` files in `queries/` are automatically executed. Findings appear in GitHub Security tab.

That's it. Simple.