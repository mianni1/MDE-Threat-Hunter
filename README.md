# MDE-Threat-Hunter

A minimal threat-hunting showcase using Microsoft Defender for Endpoint.

Automated threat hunting using MDE Advanced Hunting and GitHub Actions.

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)

## Features

- **Automated Threat Hunting**: Schedule and run KQL queries against Microsoft Defender for Endpoint
- **Multi-Platform Support**: Hunting capabilities for Windows, Linux, and macOS endpoints
- **Secure Operations**: Self-hosted GitHub runner integration for secure execution with proper permissions
- **Secret Management**: Secure secrets management via 1Password integration
- **Flexible Scheduling**: Configurable execution schedules (critical, daily, weekly)
- **Security Integration**: Findings are sent to GitHub Security tab in SARIF format
- **Detailed Reporting**: HTML and CSV reports with severity classification
- **Alert Notifications**: Optional 1Password secure note creation for critical findings

## Requirements

- Microsoft Defender for Endpoint P2 licence with Advanced Hunting capabilities
- Self-hosted GitHub runners
- 1Password account for secrets management
- GitHub repository with Actions enabled
- PowerShell 7+

## Architecture

The system operates through a few interconnected workflows:

1. **Critical Security Checks** (every 2 hours): Executes high-priority threat detection queries
2. **Daily Security Monitoring** (daily): Runs standard security monitoring across all endpoints
3. **Weekly Comprehensive Threat Hunting** (weekly): Deep analysis with extended lookback periods
4. **Runner Health Checks** (twice daily): Ensures self-hosted runners are operational