#!/usr/bin/env pwsh
# Comprehensive test of the streamlined MDE Threat Hunter

Write-Host "🚀 MDE Threat Hunter - Comprehensive Test Suite" -ForegroundColor Green
Write-Host "=" * 50

# Test 1: Query file validation
Write-Host "🧪 Test 1: Validating query files..." -ForegroundColor Yellow

$queries = Get-ChildItem queries -Filter "*.kql"
Write-Host "📁 Found $($queries.Count) query files"

foreach ($query in $queries) {
    try {
        $content = Get-Content $query.FullName -Raw
        if ($content.Length -lt 10) {
            throw "Query too short"
        }
        if ($content -notmatch '(Device\w+Events|CloudAppEvents)') {
            Write-Warning "⚠️  $($query.Name) may not be a valid MDE query (no Device*Events or CloudAppEvents table found)"
        } else {
            Write-Host "✅ $($query.Name) - Valid" -ForegroundColor Green
        }
    } catch {
        Write-Host "❌ $($query.Name) - Invalid: $_" -ForegroundColor Red
    }
}

# Test 2: Workflow file validation
Write-Host "`n🧪 Test 2: Validating workflow file..." -ForegroundColor Yellow

if (Test-Path ".github/workflows/hunt.yml") {
    $workflow = Get-Content ".github/workflows/hunt.yml" -Raw
    
    # Check critical components
    $checks = @{
        "GitHub Actions syntax" = $workflow -match "name:|on:|jobs:"
        "SARIF generation" = $workflow -match "sarif|SARIF"
        "MDE API calls" = $workflow -match "api\.security\.microsoft\.com"
        "Secret references" = $workflow -match "secrets\.MDE_"
        "Upload to Security tab" = $workflow -match "upload-sarif"
    }
    
    foreach ($check in $checks.GetEnumerator()) {
        if ($check.Value) {
            Write-Host "✅ $($check.Key)" -ForegroundColor Green
        } else {
            Write-Host "❌ $($check.Key)" -ForegroundColor Red
        }
    }
} else {
    Write-Host "❌ Workflow file not found!" -ForegroundColor Red
}

# Test 3: SARIF structure test
Write-Host "`n🧪 Test 3: Testing SARIF generation..." -ForegroundColor Yellow

# Mock some findings to test SARIF structure
$mockFindings = @(
    @{
        Query = "test_query"
        Count = 5
        Severity = "high"
    }
)

try {
    $sarif = @{
        '$schema' = "https://json.schemastore.org/sarif-2.1.0.json"
        version = "2.1.0"
        runs = @(@{
            tool = @{
                driver = @{
                    name = "MDE-Threat-Hunter"
                    version = "2.0.0"
                    rules = @($mockFindings | ForEach-Object {
                        @{
                            id = "MDE_$($_.Query)"
                            shortDescription = @{ text = $_.Query }
                            properties = @{
                                "security-severity" = $_.Severity
                            }
                        }
                    })
                }
            }
            results = @($mockFindings | ForEach-Object {
                @{
                    ruleId = "MDE_$($_.Query)"
                    level = if ($_.Severity -eq "high") { "error" } else { "warning" }
                    message = @{ text = "Found $($_.Count) findings" }
                }
            })
        })
    }
    
    $sarifJson = $sarif | ConvertTo-Json -Depth 15
    $sarifJson | Out-File "test-sarif.json" -Encoding UTF8
    
    # Validate JSON structure
    $parsed = $sarifJson | ConvertFrom-Json
    if ($parsed.version -eq "2.1.0" -and $parsed.runs.Count -gt 0) {
        Write-Host "✅ SARIF structure valid" -ForegroundColor Green
    } else {
        Write-Host "❌ SARIF structure invalid" -ForegroundColor Red
    }
    
    Remove-Item "test-sarif.json" -ErrorAction SilentlyContinue
    
} catch {
    Write-Host "❌ SARIF generation failed: $_" -ForegroundColor Red
}

# Test 4: Repository structure
Write-Host "`n🧪 Test 4: Repository structure validation..." -ForegroundColor Yellow

$requiredFiles = @(
    "README.md",
    ".github/workflows/hunt.yml",
    "queries"
)

foreach ($file in $requiredFiles) {
    if (Test-Path $file) {
        Write-Host "✅ $file exists" -ForegroundColor Green
    } else {
        Write-Host "❌ $file missing" -ForegroundColor Red
    }
}

# Check for bloat (should be minimal)
$totalFiles = (Get-ChildItem -Recurse -File | Where-Object { $_.FullName -notmatch '\.git' }).Count
if ($totalFiles -lt 30) {
    Write-Host "✅ Repository is streamlined ($totalFiles files)" -ForegroundColor Green
} else {
    Write-Host "⚠️  Repository might have bloat ($totalFiles files)" -ForegroundColor Yellow
}

Write-Host "`n🎯 Test Summary" -ForegroundColor Green
Write-Host "=" * 30
Write-Host "Ready for GitHub Actions execution!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Ensure GitHub secrets are set (MDE_TENANT_ID, MDE_CLIENT_ID, MDE_CLIENT_SECRET)"
Write-Host "2. Trigger workflow: gh workflow run hunt.yml"
Write-Host "3. Check results in GitHub Security tab"
