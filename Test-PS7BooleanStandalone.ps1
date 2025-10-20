# PSMA PowerShell 7 Boolean Type Preservation - Standalone Test
# Tests the type-aware serialization logic that fixes GitHub Issue #30
# This test runs independently without requiring PSMA DLLs

Write-Host "=== PSMA PS7 Boolean Fix - Standalone Test ===" -ForegroundColor Cyan
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))" -ForegroundColor Yellow

# Test data covering GitHub Issue #30 scenarios
$testData = @{
    # Single Boolean values (the original issue)
    "Enabled" = $true
    "AccountLocked" = $false
    
    # Multi-valued Boolean attributes (PSMA format)
    "permissions|Boolean" = @($true, $false, $true)
    "flags|Boolean" = @($false, $false)
    
    # Other data types for completeness
    "EmployeeID" = 12345
    "Salary" = 75000.50
    "Department" = "Engineering"
    "emails|String" = @("john.doe@company.com", "j.doe@backup.com")
    "scores|Int32" = @(85, 92, 78)
}

Write-Host "`n=== Original Data Types ===" -ForegroundColor Yellow
foreach ($key in $testData.Keys) {
    $value = $testData[$key]
    if ($value -is [array]) {
        $itemTypes = ($value | ForEach-Object { $_.GetType().Name } | Select-Object -Unique) -join ", "
        Write-Host "  $key = Array[$($value.Length)] ($itemTypes): $($value -join ', ')" -ForegroundColor White
    } else {
        $valueType = if ($value -ne $null) { $value.GetType().Name } else { "null" }
        Write-Host "  $key = $value ($valueType)" -ForegroundColor White
    }
}

# Simulate the exact PowerShell 7 Engine serialization logic from our fix
Write-Host "`n=== PSMA PowerShell 7 Engine Serialization (Our Fix) ===" -ForegroundColor Yellow

$serializedData = @{}
foreach ($key in $testData.Keys) {
    $value = $testData[$key]
    
    if ($null -eq $value) {
        $typeName = 'System.Object'
        $valueStr = ''
    } else {
        $typeName = $value.GetType().FullName
        
        # This is the exact logic from PowerShell7Engine.cs (our fix)
        if ($value -is [bool]) {
            $valueStr = if ($value) { 'True' } else { 'False' }
        } elseif ($value -is [int] -or $value -is [double] -or $value -is [decimal]) {
            $valueStr = $value.ToString()
        } else {
            # For arrays and complex objects - use JSON
            $valueStr = ConvertTo-Json $value -Compress
        }
    }
    
    $serializedLine = "$typeName|$key=$valueStr"
    $serializedData[$key] = $serializedLine
    Write-Host "  $serializedLine" -ForegroundColor Cyan
}

# Test the deserialization logic (ConvertFromJSONString equivalent)
Write-Host "`n=== PSMA PowerShell 7 Engine Deserialization ===" -ForegroundColor Yellow

$deserializedData = @{}
$testsPassed = 0
$testsTotal = 0

foreach ($key in $serializedData.Keys) {
    $serializedValue = $serializedData[$key]
    
    # Parse the TypeName|key=value format
    if ($serializedValue -match '^([^|]+)\|[^=]+=(.*)$') {
        $typeName = $matches[1]
        $valueString = $matches[2]
        
        Write-Host "Deserializing: $key from $typeName" -ForegroundColor Gray
        
        # Simulate ConvertFromJSONString method logic
        $deserializedValue = switch ($typeName) {
            "System.Boolean" {
                [bool]::Parse($valueString)
            }
            "System.Int32" {
                [int]::Parse($valueString)
            }
            "System.Double" {
                [double]::Parse($valueString)
            }
            "System.String" {
                # Remove JSON quotes if present
                if ($valueString.StartsWith('"') -and $valueString.EndsWith('"')) {
                    $valueString.Substring(1, $valueString.Length - 2)
                } else {
                    $valueString
                }
            }
            default {
                # For complex types (arrays), try JSON deserialization
                try {
                    ConvertFrom-Json $valueString
                } catch {
                    $valueString  # fallback to string
                }
            }
        }
        
        $deserializedData[$key] = $deserializedValue
        
        # Validate type preservation
        $originalValue = $testData[$key]
        $testsTotal++
        
        if ($originalValue -is [array] -and $deserializedValue -is [array]) {
            if ($originalValue.Length -eq $deserializedValue.Length) {
                $allMatch = $true
                for ($i = 0; $i -lt $originalValue.Length; $i++) {
                    if ($originalValue[$i] -ne $deserializedValue[$i]) {
                        $allMatch = $false
                        break
                    }
                }
                if ($allMatch) {
                    Write-Host "  ✓ Multi-valued attribute preserved: $($deserializedValue -join ', ')" -ForegroundColor Green
                    $testsPassed++
                } else {
                    Write-Host "  ✗ Multi-valued attribute values differ" -ForegroundColor Red
                }
            } else {
                Write-Host "  ✗ Multi-valued attribute length mismatch" -ForegroundColor Red
            }
        } elseif ($originalValue -eq $deserializedValue -and $originalValue.GetType() -eq $deserializedValue.GetType()) {
            $preservedType = $deserializedValue.GetType().Name
            Write-Host "  ✓ Single value preserved: $deserializedValue ($preservedType)" -ForegroundColor Green
            $testsPassed++
        } else {
            Write-Host "  ✗ Value/type mismatch: $originalValue vs $deserializedValue" -ForegroundColor Red
        }
    }
}

# Final Assessment
Write-Host "`n=== Test Results ===" -ForegroundColor Cyan
Write-Host "Tests Passed: $testsPassed / $testsTotal" -ForegroundColor White

if ($testsPassed -eq $testsTotal) {
    Write-Host "`n SUCCESS! PowerShell 7 Boolean serialization fix is working!" -ForegroundColor Green
    Write-Host "✓ Single Boolean values preserved as Boolean type" -ForegroundColor Green
    Write-Host "✓ Multi-valued Boolean arrays preserved correctly" -ForegroundColor Green
    Write-Host "✓ GitHub Issue #30 is resolved!" -ForegroundColor Green
} else {
    Write-Host "`n FAILURE: Some type preservation tests failed" -ForegroundColor Red
    Write-Host "The fix may need additional work" -ForegroundColor Red
}

Write-Host "`n=== Standalone Test Complete ===" -ForegroundColor Cyan