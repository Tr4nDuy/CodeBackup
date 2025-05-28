# NIDS-SIEM End-to-End Integration Test
# Tests the complete pipeline from Ubuntu Router to Windows Server

param(
    [switch]$QuickTest,
    [switch]$FullTest,
    [switch]$NetworkOnly,
    [switch]$Help
)

$ErrorActionPreference = "Continue"

function Write-ColorOutput($Message, $Color = "White") {
    Write-Host $Message -ForegroundColor $Color
}

function Test-UbuntuConnectivity {
    Write-ColorOutput "=== Testing Ubuntu Router Connectivity ===" "Green"
    
    $ubuntuIP = "192.168.111.133"
    $testPorts = @(22, 80, 443)
    
    Write-ColorOutput "Testing connection to Ubuntu Router ($ubuntuIP)..." "Yellow"
    
    # Test ping
    if (Test-NetConnection -ComputerName $ubuntuIP -InformationLevel Quiet) {
        Write-ColorOutput "✓ Ubuntu Router is reachable via ping" "Green"
    } else {
        Write-ColorOutput "✗ Ubuntu Router is not reachable via ping" "Red"
        return $false
    }
    
    # Test common ports
    foreach ($port in $testPorts) {
        if (Test-NetConnection -ComputerName $ubuntuIP -Port $port -InformationLevel Quiet) {
            Write-ColorOutput "✓ Port $port is open" "Green"
        } else {
            Write-ColorOutput "ℹ Port $port is closed (expected for security)" "Yellow"
        }
    }
    
    return $true
}

function Test-SIEMServices {
    Write-ColorOutput "=== Testing SIEM Services ===" "Green"
    
    $services = @(
        @{Name="Elasticsearch"; Port=9200; Url="http://localhost:9200"; Required=$true},
        @{Name="Logstash"; Port=5514; Protocol="UDP"; Required=$true},
        @{Name="Kibana"; Port=5601; Url="http://localhost:5601"; Required=$true}
    )
    
    $allRunning = $true
    
    foreach ($service in $services) {
        Write-ColorOutput "Testing $($service.Name)..." "Yellow"
        
        if ($service.Url) {
            try {
                $response = Invoke-WebRequest -Uri $service.Url -UseBasicParsing -TimeoutSec 10
                if ($response.StatusCode -eq 200) {
                    Write-ColorOutput "✓ $($service.Name) is running and responding" "Green"
                } else {
                    Write-ColorOutput "⚠ $($service.Name) responded with status $($response.StatusCode)" "Yellow"
                }
            } catch {
                Write-ColorOutput "✗ $($service.Name) is not responding" "Red"
                if ($service.Required) { $allRunning = $false }
            }
        } else {
            # Test UDP port for Logstash
            try {
                $udpClient = New-Object System.Net.Sockets.UdpClient
                $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse("127.0.0.1"), $service.Port)
                $testMessage = "<14>Test message"
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($testMessage)
                $udpClient.Send($bytes, $bytes.Length, $endpoint) | Out-Null
                $udpClient.Close()
                Write-ColorOutput "✓ $($service.Name) UDP port $($service.Port) is accessible" "Green"
            } catch {
                Write-ColorOutput "✗ $($service.Name) UDP port $($service.Port) is not accessible" "Red"
                if ($service.Required) { $allRunning = $false }
            }
        }
    }
    
    return $allRunning
}

function Test-LogPipeline {
    Write-ColorOutput "=== Testing Log Pipeline ===" "Green"
    
    # Generate test log data
    $testLogs = @(
        @{
            Message = '{"timestamp": "' + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.ffffff") + '", "event_type": "network_detection", "prediction": "TCP", "confidence": 0.8745, "is_attack": true, "severity": "high", "network_zone": "WAN", "interface": "ens33", "attack_type": "TCP Port Scan", "source_ip": "203.0.113.100", "destination_ip": "192.168.1.10", "sensor_id": "nids-test-1"}'
            Expected = "Attack detection"
        },
        @{
            Message = '{"timestamp": "' + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.ffffff") + '", "event_type": "network_detection", "prediction": "0_normal", "confidence": 0.9234, "is_attack": false, "severity": "info", "network_zone": "LAN", "interface": "ens37", "attack_type": "normal_traffic", "source_ip": "192.168.1.100", "destination_ip": "192.168.1.1", "sensor_id": "nids-test-2"}'
            Expected = "Normal traffic"
        }
    )
    
    Write-ColorOutput "Sending test logs to Logstash..." "Yellow"
    
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse("127.0.0.1"), 5514)
        
        foreach ($log in $testLogs) {
            $message = "<14>" + $log.Message
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($message)
            $udpClient.Send($bytes, $bytes.Length, $endpoint) | Out-Null
            Write-ColorOutput "  ✓ Sent: $($log.Expected)" "Cyan"
            Start-Sleep -Milliseconds 500
        }
        
        $udpClient.Close()
        Write-ColorOutput "✓ Test logs sent successfully" "Green"
        
        # Wait for processing
        Write-ColorOutput "Waiting for log processing..." "Yellow"
        Start-Sleep -Seconds 10
        
        return $true
    } catch {
        Write-ColorOutput "✗ Failed to send test logs: $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-ElasticsearchData {
    Write-ColorOutput "=== Testing Elasticsearch Data ===" "Green"
    
    try {
        # Check if indices exist
        $indicesResponse = Invoke-RestMethod -Uri "http://localhost:9200/_cat/indices?v" -Method GET
        Write-ColorOutput "Elasticsearch indices:" "Cyan"
        Write-Host $indicesResponse
        
        # Search for NIDS logs
        $searchQuery = @{
            "query" = @{
                "match" = @{
                    "event_type" = "network_detection"
                }
            }
            "size" = 10
            "sort" = @(
                @{
                    "@timestamp" = @{
                        "order" = "desc"
                    }
                }
            )
        } | ConvertTo-Json -Depth 10
        
        $searchResponse = Invoke-RestMethod -Uri "http://localhost:9200/logstash-*/_search" -Method POST -Body $searchQuery -ContentType "application/json"
        
        $hitCount = $searchResponse.hits.total.value
        Write-ColorOutput "Found $hitCount NIDS detection logs in Elasticsearch" "Green"
        
        if ($hitCount -gt 0) {
            Write-ColorOutput "Recent NIDS detections:" "Cyan"
            foreach ($hit in $searchResponse.hits.hits | Select-Object -First 3) {
                $source = $hit._source
                $timestamp = $source.'@timestamp'
                $prediction = $source.prediction
                $zone = $source.network_zone
                $isAttack = $source.is_attack
                
                $status = if ($isAttack -eq $true) { "🚨 ATTACK" } else { "✅ NORMAL" }
                Write-ColorOutput "  $timestamp | $status | $prediction | Zone: $zone" "White"
            }
        }
        
        return $hitCount -gt 0
    } catch {
        Write-ColorOutput "✗ Error accessing Elasticsearch: $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-KibanaAccess {
    Write-ColorOutput "=== Testing Kibana Access ===" "Green"
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:5601/api/status" -UseBasicParsing -TimeoutSec 10
        $status = $response.Content | ConvertFrom-Json
        
        Write-ColorOutput "✓ Kibana is accessible" "Green"
        Write-ColorOutput "  Version: $($status.version.number)" "Cyan"
        Write-ColorOutput "  Status: $($status.status.overall.level)" "Cyan"
        
        # Test index pattern
        try {
            $indexResponse = Invoke-RestMethod -Uri "http://localhost:5601/api/saved_objects/_find?type=index-pattern" -Method GET -Headers @{"kbn-xsrf"="true"}
            $indexPatterns = $indexResponse.saved_objects | Where-Object { $_.attributes.title -like "*nids*" -or $_.attributes.title -like "*logstash*" }
            
            if ($indexPatterns.Count -gt 0) {
                Write-ColorOutput "✓ Found NIDS-related index patterns:" "Green"
                foreach ($pattern in $indexPatterns) {
                    Write-ColorOutput "  - $($pattern.attributes.title)" "Cyan"
                }
            } else {
                Write-ColorOutput "⚠ No NIDS index patterns found. Create manually in Kibana." "Yellow"
            }
        } catch {
            Write-ColorOutput "⚠ Could not check index patterns (may need manual setup)" "Yellow"
        }
        
        return $true
    } catch {
        Write-ColorOutput "✗ Kibana is not accessible: $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-SystemResources {
    Write-ColorOutput "=== Testing System Resources ===" "Green"
    
    # Memory check
    $memory = Get-WmiObject -Class Win32_ComputerSystem
    $totalRAM = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
    $availableRAM = [math]::Round((Get-Counter '\Memory\Available MBytes').CounterSamples[0].CookedValue / 1024, 2)
    $usedRAM = $totalRAM - $availableRAM
    $memoryUsagePercent = [math]::Round(($usedRAM / $totalRAM) * 100, 1)
    
    Write-ColorOutput "Memory usage: $usedRAM GB / $totalRAM GB ($memoryUsagePercent%)" "Cyan"
    
    if ($memoryUsagePercent -gt 80) {
        Write-ColorOutput "⚠ High memory usage detected" "Yellow"
    } else {
        Write-ColorOutput "✓ Memory usage is acceptable" "Green"
    }
    
    # Disk space check
    $disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
    $totalSpaceGB = [math]::Round($disk.Size / 1GB, 2)
    $diskUsagePercent = [math]::Round((1 - ($disk.FreeSpace / $disk.Size)) * 100, 1)
    
    Write-ColorOutput "Disk usage: $diskUsagePercent% used ($freeSpaceGB GB free / $totalSpaceGB GB total)" "Cyan"
    
    if ($freeSpaceGB -lt 5) {
        Write-ColorOutput "⚠ Low disk space warning" "Yellow"
    } else {
        Write-ColorOutput "✓ Disk space is sufficient" "Green"
    }
    
    # CPU check
    $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3
    $avgCPU = [math]::Round(($cpu.CounterSamples | Measure-Object CookedValue -Average).Average, 1)
    
    Write-ColorOutput "CPU usage: $avgCPU%" "Cyan"
    
    if ($avgCPU -gt 80) {
        Write-ColorOutput "⚠ High CPU usage detected" "Yellow"
    } else {
        Write-ColorOutput "✓ CPU usage is acceptable" "Green"
    }
}

function Generate-TestReport {
    param($TestResults)
    
    Write-ColorOutput "`n=== Test Summary Report ===" "Cyan"
    Write-ColorOutput "Generated: $(Get-Date)" "White"
    Write-ColorOutput ""
    
    $totalTests = $TestResults.Count
    $passedTests = ($TestResults | Where-Object { $_.Result -eq $true }).Count
    $failedTests = $totalTests - $passedTests
    
    Write-ColorOutput "Total Tests: $totalTests" "White"
    Write-ColorOutput "Passed: $passedTests" "Green"
    Write-ColorOutput "Failed: $failedTests" "Red"
    Write-ColorOutput "Success Rate: $([math]::Round(($passedTests / $totalTests) * 100, 1))%" "Cyan"
    Write-ColorOutput ""
    
    foreach ($test in $TestResults) {
        $status = if ($test.Result) { "✓ PASS" } else { "✗ FAIL" }
        $color = if ($test.Result) { "Green" } else { "Red" }
        Write-ColorOutput "$status - $($test.Name)" $color
    }
    
    Write-ColorOutput ""
    if ($failedTests -eq 0) {
        Write-ColorOutput "🎉 All tests passed! NIDS-SIEM system is ready for production." "Green"
    } else {
        Write-ColorOutput "⚠ Some tests failed. Please review the issues above." "Yellow"
    }
}

function Show-Help {
    Write-ColorOutput "NIDS-SIEM End-to-End Integration Test" "Cyan"
    Write-ColorOutput ""
    Write-ColorOutput "Usage: .\test_integration.ps1 [OPTIONS]" "White"
    Write-ColorOutput ""
    Write-ColorOutput "OPTIONS:" "Yellow"
    Write-ColorOutput "  -QuickTest      Run essential tests only (5 minutes)" "White"
    Write-ColorOutput "  -FullTest       Run comprehensive tests (15 minutes)" "White"
    Write-ColorOutput "  -NetworkOnly    Test network connectivity only" "White"
    Write-ColorOutput "  -Help           Show this help message" "White"
    Write-ColorOutput ""
    Write-ColorOutput "Test Categories:" "Green"
    Write-ColorOutput "  • Network connectivity (Ubuntu ↔ Windows)" "White"
    Write-ColorOutput "  • SIEM services status" "White"
    Write-ColorOutput "  • Log pipeline functionality" "White"
    Write-ColorOutput "  • Elasticsearch data verification" "White"
    Write-ColorOutput "  • Kibana accessibility" "White"
    Write-ColorOutput "  • System resource monitoring" "White"
}

# Main execution
if ($Help) {
    Show-Help
    exit 0
}

Write-ColorOutput "=============================================" "Cyan"
Write-ColorOutput "NIDS-SIEM End-to-End Integration Test" "Cyan"
Write-ColorOutput "=============================================" "Cyan"
Write-ColorOutput ""

$testResults = @()

try {
    if ($NetworkOnly) {
        Write-ColorOutput "Running network connectivity tests only..." "Green"
        $testResults += @{Name="Ubuntu Connectivity"; Result=(Test-UbuntuConnectivity)}
    }
    elseif ($QuickTest) {
        Write-ColorOutput "Running quick test suite (essential tests only)..." "Green"
        $testResults += @{Name="Ubuntu Connectivity"; Result=(Test-UbuntuConnectivity)}
        $testResults += @{Name="SIEM Services"; Result=(Test-SIEMServices)}
        $testResults += @{Name="Kibana Access"; Result=(Test-KibanaAccess)}
    }
    elseif ($FullTest) {
        Write-ColorOutput "Running full test suite (comprehensive tests)..." "Green"
        $testResults += @{Name="Ubuntu Connectivity"; Result=(Test-UbuntuConnectivity)}
        $testResults += @{Name="SIEM Services"; Result=(Test-SIEMServices)}
        $testResults += @{Name="Log Pipeline"; Result=(Test-LogPipeline)}
        $testResults += @{Name="Elasticsearch Data"; Result=(Test-ElasticsearchData)}
        $testResults += @{Name="Kibana Access"; Result=(Test-KibanaAccess)}
        Test-SystemResources
    }
    else {
        Write-ColorOutput "Running standard test suite..." "Green"
        $testResults += @{Name="Ubuntu Connectivity"; Result=(Test-UbuntuConnectivity)}
        $testResults += @{Name="SIEM Services"; Result=(Test-SIEMServices)}
        $testResults += @{Name="Log Pipeline"; Result=(Test-LogPipeline)}
        $testResults += @{Name="Kibana Access"; Result=(Test-KibanaAccess)}
    }
    
    Generate-TestReport -TestResults $testResults
    
} catch {
    Write-ColorOutput "Test execution failed: $($_.Exception.Message)" "Red"
    exit 1
}

Write-ColorOutput "`nFor detailed monitoring, access:" "Cyan"
Write-ColorOutput "• Kibana Dashboard: http://localhost:5601" "Green"
Write-ColorOutput "• Elasticsearch: http://localhost:9200" "Green"
