#!/usr/bin/env pwsh
# Quick test script to validate MDE connection and query execution

param(
    [string]$TestQuery = "DeviceProcessEvents | where Timestamp > ago(1h) | take 5"
)

Write-Host "🧪 Testing MDE API connection and query execution..." -ForegroundColor Yellow

# Check if we have the required environment variables
if (-not $env:MDE_TENANT_ID -or -not $env:MDE_CLIENT_ID -or -not $env:MDE_CLIENT_SECRET) {
    Write-Host "❌ Missing MDE environment variables. Please set:" -ForegroundColor Red
    Write-Host "   MDE_TENANT_ID, MDE_CLIENT_ID, MDE_CLIENT_SECRET" -ForegroundColor Red
    exit 1
}

try {
    Write-Host "🔑 Authenticating with MDE API..."
    
    # Get token
    $body = @{ 
        client_id = $env:MDE_CLIENT_ID
        scope = 'https://api.security.microsoft.com/.default'
        client_secret = $env:MDE_CLIENT_SECRET
        grant_type = 'client_credentials'
    }
    
    $tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$env:MDE_TENANT_ID/oauth2/v2.0/token" -Body $body -ContentType 'application/x-www-form-urlencoded'
    $token = $tokenResponse.access_token
    
    Write-Host "✅ Authentication successful!" -ForegroundColor Green
    
    # Test query execution
    Write-Host "🔍 Executing test query..."
    $headers = @{ Authorization = "Bearer $token" }
    $queryBody = @{ Query = $TestQuery } | ConvertTo-Json
    
    $response = Invoke-RestMethod -Method Post -Uri 'https://api.security.microsoft.com/api/advancedhunting/run' -Headers $headers -Body $queryBody -ContentType 'application/json'
    
    Write-Host "✅ Query executed successfully!" -ForegroundColor Green
    Write-Host "📊 Results: $($response.Results.Count) rows returned" -ForegroundColor Cyan
    
    if ($response.Results.Count -gt 0) {
        Write-Host "📋 Sample result columns:" -ForegroundColor Cyan
        $response.Results[0].PSObject.Properties.Name | ForEach-Object { Write-Host "   - $_" }
    }
    
    return $true
    
} catch {
    Write-Host "❌ Test failed: $_" -ForegroundColor Red
    Write-Host "🔍 Error details: $($_.Exception.Message)" -ForegroundColor Red
    return $false
}
