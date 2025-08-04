# 🎯 MDE Threat Hunter - Testing Guide

## What We've Built

We've created the most **minimal, streamlined** MDE threat hunting repository with:

### ✨ Features
- **Single workflow** (`hunt.yml`) that runs on GitHub's infrastructure
- **18 KQL queries** covering Windows, Linux, macOS threats
- **Comprehensive SARIF generation** for GitHub Security integration
- **Automatic scheduling** (every 6 hours) + manual triggering
- **Ultra-minimal** - deleted 5,903 lines of bloat!

### 📁 Repository Structure (22 files total)
```
MDE-Threat-Hunter/
├── .github/workflows/hunt.yml    # Single workflow file
├── queries/                      # 18 KQL threat hunting queries
├── README.md                     # Minimal documentation
├── test-suite.ps1               # Comprehensive test validation
└── test-mde.ps1                 # Quick MDE API test
```

## 🧪 Testing Steps

### 1. Local Testing (Already Done ✅)
```bash
pwsh ./test-suite.ps1
```
Results:
- ✅ 18 queries validated
- ✅ Workflow syntax verified
- ✅ SARIF generation tested
- ✅ Repository structure confirmed

### 2. GitHub Actions Testing

The workflow will automatically trigger when you push to `staging` branch (just happened!).

**Check the workflow run:**
1. Go to: https://github.com/mianni1/MDE-Threat-Hunter/actions
2. Look for "MDE Hunt" workflow run
3. Monitor execution logs

### 3. Required GitHub Secrets

For the workflow to actually execute MDE queries, you need to set these repository secrets:

```
MDE_TENANT_ID     = your-azure-tenant-id
MDE_CLIENT_ID     = your-app-registration-client-id  
MDE_CLIENT_SECRET = your-app-registration-secret
```

**To set secrets:**
1. Go to repository Settings → Secrets and variables → Actions
2. Add the three secrets above

### 4. Expected Results

**If secrets are configured:**
- Workflow executes 18 KQL queries against MDE API
- Generates comprehensive SARIF report
- Uploads findings to GitHub Security tab
- Creates workflow summary with results

**If secrets are missing:**
- Workflow will fail at authentication step
- Error logs will show missing credentials

### 5. Viewing Results

**GitHub Security Tab:**
- Navigate to: https://github.com/mianni1/MDE-Threat-Hunter/security/code-scanning
- Filter by tool: "MDE-Threat-Hunter"
- View detailed SARIF findings

**Workflow Summary:**
- Each run creates a summary showing total findings
- Direct links to Security tab for detailed analysis

## 🚀 Manual Testing

**Trigger workflow manually:**
```bash
# If you have GitHub CLI and are authenticated:
gh workflow run hunt.yml --ref staging

# Or use the GitHub web interface:
# Go to Actions → MDE Hunt → Run workflow
```

**Test with different lookback periods:**
- 6h (quick test)
- 24h (standard)
- 7d (comprehensive)
- 30d (deep analysis)

## 📊 Success Metrics

✅ **Streamlined**: 5,903 lines removed, 226 lines added
✅ **Functional**: All 18 queries validated
✅ **Standards Compliant**: SARIF v2.1.0 implementation
✅ **GitHub Native**: Uses ubuntu-latest runners
✅ **Secure**: Proper secret management
✅ **Automated**: Runs every 6 hours automatically

## 🔧 Troubleshooting

**Common Issues:**
1. **Authentication failure** → Check GitHub secrets are set correctly
2. **Query syntax errors** → Run `pwsh ./test-suite.ps1` locally
3. **SARIF upload failure** → Check `security-events: write` permission
4. **No findings** → Normal if environment is clean

**Debug Commands:**
```bash
# Test MDE connection (requires local env vars)
pwsh ./test-mde.ps1

# Validate repository structure
pwsh ./test-suite.ps1

# Check workflow syntax
cat .github/workflows/hunt.yml
```

---

🎉 **Ready to hunt threats with the most minimal, efficient MDE setup possible!**
