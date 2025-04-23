# MDE Threat Hunter

Minimal threat hunting with Microsoft Defender for Endpoint.

## Setup

1. Set GitHub secrets:
   - `MDE_TENANT_ID`
   - `MDE_CLIENT_ID`
   - `MDE_CLIENT_SECRET`

2. Add your KQL queries to `queries/`

3. Hunting runs every 6 hours or on-demand

## Queries

All `.kql` files in `queries/` are automatically executed. Findings appear in GitHub Security tab.

That's it. Simple.