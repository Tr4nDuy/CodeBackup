# Script kiểm tra và test toàn bộ hệ thống NIDS-SIEM
# Chạy với quyền Administrator

param(
    [switch]$QuickTest,
    [switch]$FullTest,
    [switch]$StressTest,
    [switch]$GenerateTraffic
)

$ErrorActionPreference = "Continue"

function Write-ColorOutput($Message, $Color = "White") {
    Write-Host $Message -ForegroundColor $Color
}

function Test-ServiceAvailability {
    Write-ColorOutput "=== Testing Service Availability ===" "Cyan"
    
    $tests = @(
        @{ Service = "Elasticsearch"; URL = "http://localhost:9200"; Expected = "elasticsearch" },
        @{ Service = "Kibana"; URL = "http://localhost:5601"; Expected = "kibana" },
        @{ Service = "Logstash"; Port = 5514; Type = "TCP" }
    )
    
    foreach ($test in $tests) {
        if ($test.URL) {
            try {
                $response = Invoke-WebRequest -Uri $test.URL -UseBasicParsing -TimeoutSec 10
                if ($response.Content -like "*$($test.Expected)*") {
                    Write-ColorOutput "✓ $($test.Service): Available" "Green"
                } else {
                    Write-ColorOutput "⚠ $($test.Service): Running but unexpected response" "Yellow"
                }
            } catch {
                Write-ColorOutput "✗ $($test.Service): Not available - $($_.Exception.Message)" "Red"
            }
        } elseif ($test.Port) {
            try {
                $connection = Test-NetConnection -ComputerName "localhost" -Port $test.Port -WarningAction SilentlyContinue
                if ($connection.TcpTestSucceeded) {
                    Write-ColorOutput "✓ $($test.Service): Port $($test.Port) open" "Green"
                } else {
                    Write-ColorOutput "✗ $($test.Service): Port $($test.Port) not accessible" "Red"
                }
            } catch {
                Write-ColorOutput "✗ $($test.Service): Connection test failed" "Red"
            }
        }
    }
}

function Test-NIDSComponents {
    Write-ColorOutput "=== Testing NIDS Components ===" "Cyan"
    
    $nidsPath = "C:\Users\ADMIN\Desktop\CodeBackup\v2_pcap2csv_automation"
    $modelsPath = "C:\Users\ADMIN\Desktop\CodeBackup\Saved model"
    
    # Check NIDS files
    $requiredFiles = @(
        "$nidsPath\program_siem.py",
        "$nidsPath\automation_realtime.sh",
        "$modelsPath\kinn_model.pkl",
        "$modelsPath\scaler.pkl", 
        "$modelsPath\label_encoder.pkl"
    )
    
    foreach ($file in $requiredFiles) {
        if (Test-Path $file) {
            Write-ColorOutput "✓ Found: $(Split-Path $file -Leaf)" "Green"
        } else {
            Write-ColorOutput "✗ Missing: $file" "Red"
        }
    }
    
    # Test Python dependencies
    Write-ColorOutput "Testing Python dependencies..." "Yellow"
    try {
        $pythonTest = python -c "
import pandas as pd
import numpy as np
import sklearn
import joblib
import pickle
import json
print('All Python dependencies available')
"
        Write-ColorOutput "✓ Python dependencies: OK" "Green"
    } catch {
        Write-ColorOutput "✗ Python dependencies: Missing packages" "Red"
    }
}

function Generate-TestTraffic {
    Write-ColorOutput "=== Generating Test Traffic Data ===" "Cyan"
    
    $nidsPath = "C:\Users\ADMIN\Desktop\CodeBackup\v2_pcap2csv_automation"
    $testDataPath = "$nidsPath\test_data.csv"
    
    # Generate synthetic test data
    $testData = @"
Src IP,Dst IP,Src Port,Dst Port,Protocol,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,TotLen Bwd Pkts,Flow Byts/s,Flow Pkts/s
192.168.1.100,192.168.1.1,12345,80,6,0.5,10,8,1500,800,4600,36
10.0.0.50,192.168.1.254,54321,22,6,2.1,100,2,15000,200,7238,48
172.16.0.10,192.168.100.5,33445,443,6,0.1,5,3,500,300,8000,80
192.168.1.200,192.168.1.1,23456,21,6,1.2,50,10,7500,1000,7083,50
10.0.0.100,172.16.0.1,65432,23,6,0.8,25,5,3750,625,5469,37
192.168.1.150,192.168.100.10,34567,25,6,3.0,200,20,30000,4000,11333,73
172.16.0.50,10.0.0.1,45678,53,17,0.2,3,2,300,200,2500,25
192.168.1.75,192.168.1.1,56789,80,6,0.6,12,9,1800,900,4500,35
10.0.0.200,192.168.100.20,67890,135,6,1.5,75,8,11250,1200,8300,55
172.16.0.75,192.168.1.100,78901,139,6,2.8,150,25,22500,3750,9375,62
"@
    
    $testData | Out-File -FilePath $testDataPath -Encoding UTF8
    Write-ColorOutput "✓ Generated test data: $testDataPath" "Green"
    
    return $testDataPath
}

function Test-NIDSPrediction {
    param($TestDataPath)
    
    Write-ColorOutput "=== Testing NIDS Prediction Engine ===" "Cyan"
    
    $nidsPath = "C:\Users\ADMIN\Desktop\CodeBackup\v2_pcap2csv_automation"
    $modelsPath = "C:\Users\ADMIN\Desktop\CodeBackup\Saved model"
    
    try {
        Set-Location $nidsPath
        
        Write-ColorOutput "Running NIDS prediction..." "Yellow"
        $startTime = Get-Date
        
        $result = python program_siem.py --data $TestDataPath --models $modelsPath --output "test_results.csv" 2>&1
        
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "✓ NIDS prediction completed in $([math]::Round($duration, 2)) seconds" "Green"
            
            # Check output files
            if (Test-Path "test_results.csv") {
                $results = Import-Csv "test_results.csv"
                Write-ColorOutput "✓ Results file created with $($results.Count) predictions" "Green"
                
                # Show prediction summary
                $predictions = $results | Group-Object Prediction | Select-Object Name, Count
                Write-ColorOutput "Prediction Summary:" "Yellow"
                foreach ($pred in $predictions) {
                    Write-ColorOutput "  $($pred.Name): $($pred.Count)" "White"
                }
            }
            
            # Check log files
            $logDir = "logs"
            if (Test-Path $logDir) {
                $logFiles = Get-ChildItem $logDir -Filter "*.log"
                Write-ColorOutput "✓ Log files created: $($logFiles.Count)" "Green"
                
                # Check JSON log format
                $jsonLog = "$logDir\nids_detections.log"
                if (Test-Path $jsonLog) {
                    $lastLog = Get-Content $jsonLog | Select-Object -Last 1
                    try {
                        $jsonObj = $lastLog | ConvertFrom-Json
                        Write-ColorOutput "✓ JSON log format valid" "Green"
                    } catch {
                        Write-ColorOutput "⚠ JSON log format issue" "Yellow"
                    }
                }
            }
            
        } else {
            Write-ColorOutput "✗ NIDS prediction failed" "Red"
            Write-ColorOutput "Error: $result" "Red"
        }
        
    } catch {
        Write-ColorOutput "✗ NIDS test error: $($_.Exception.Message)" "Red"
    }
}

function Test-SIEMIntegration {
    Write-ColorOutput "=== Testing SIEM Integration ===" "Cyan"
    
    $nidsLogPath = "C:\Users\ADMIN\Desktop\CodeBackup\v2_pcap2csv_automation\logs\nids_detections.log"
    
    if (Test-Path $nidsLogPath) {
        Write-ColorOutput "Testing log file ingestion..." "Yellow"
        
        # Check if logs are being indexed in Elasticsearch
        try {
            Start-Sleep -Seconds 5  # Wait for Logstash to process
            
            $esQuery = @{
                "query" = @{
                    "match_all" = @{}
                }
                "size" = 1
            } | ConvertTo-Json -Depth 3
            
            $response = Invoke-RestMethod -Uri "http://localhost:9200/nids-logs-*/_search" -Method POST -Body $esQuery -ContentType "application/json"
            
            if ($response.hits.total.value -gt 0) {
                Write-ColorOutput "✓ Data indexed in Elasticsearch: $($response.hits.total.value) documents" "Green"
                
                # Test Kibana access
                try {
                    $kibanaResponse = Invoke-WebRequest -Uri "http://localhost:5601/api/status" -UseBasicParsing -TimeoutSec 10
                    Write-ColorOutput "✓ Kibana API accessible" "Green"
                } catch {
                    Write-ColorOutput "⚠ Kibana API not accessible" "Yellow"
                }
                
            } else {
                Write-ColorOutput "⚠ No data found in Elasticsearch" "Yellow"
            }
            
        } catch {
            Write-ColorOutput "⚠ Could not query Elasticsearch: $($_.Exception.Message)" "Yellow"
        }
    } else {
        Write-ColorOutput "⚠ No NIDS log file found" "Yellow"
    }
}

function Run-StressTest {
    Write-ColorOutput "=== Running Stress Test ===" "Cyan"
    
    Write-ColorOutput "Generating large test dataset..." "Yellow"
    
    # Generate larger dataset for stress testing
    $stressData = @()
    $baseIPs = @("192.168.1.", "10.0.0.", "172.16.0.", "192.168.100.")
    $protocols = @(6, 17, 1)  # TCP, UDP, ICMP
    $ports = @(22, 23, 53, 80, 135, 139, 443, 445, 993, 995)
    
    for ($i = 1; $i -le 1000; $i++) {
        $srcBase = Get-Random -InputObject $baseIPs
        $dstBase = Get-Random -InputObject $baseIPs
        $srcIP = $srcBase + (Get-Random -Minimum 1 -Maximum 254)
        $dstIP = $dstBase + (Get-Random -Minimum 1 -Maximum 254)
        $srcPort = Get-Random -Minimum 1024 -Maximum 65535
        $dstPort = Get-Random -InputObject $ports
        $protocol = Get-Random -InputObject $protocols
        $duration = [math]::Round((Get-Random -Minimum 0.1 -Maximum 10.0), 2)
        $fwdPkts = Get-Random -Minimum 1 -Maximum 200
        $bwdPkts = Get-Random -Minimum 0 -Maximum 50
        $fwdBytes = $fwdPkts * (Get-Random -Minimum 64 -Maximum 1500)
        $bwdBytes = $bwdPkts * (Get-Random -Minimum 64 -Maximum 1500)
        $bytesPerSec = [math]::Round(($fwdBytes + $bwdBytes) / $duration, 2)
        $pktsPerSec = [math]::Round(($fwdPkts + $bwdPkts) / $duration, 2)
        
        $stressData += "$srcIP,$dstIP,$srcPort,$dstPort,$protocol,$duration,$fwdPkts,$bwdPkts,$fwdBytes,$bwdBytes,$bytesPerSec,$pktsPerSec"
    }
    
    $header = "Src IP,Dst IP,Src Port,Dst Port,Protocol,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,TotLen Bwd Pkts,Flow Byts/s,Flow Pkts/s"
    $fullData = $header + "`n" + ($stressData -join "`n")
    
    $stressFile = "C:\Users\ADMIN\Desktop\CodeBackup\v2_pcap2csv_automation\stress_test.csv"
    $fullData | Out-File -FilePath $stressFile -Encoding UTF8
    
    Write-ColorOutput "✓ Generated stress test data: 1000 flows" "Green"
    
    # Run stress test
    Test-NIDSPrediction -TestDataPath $stressFile
    
    # Monitor system resources
    Write-ColorOutput "System resources after stress test:" "Yellow"
    $memory = Get-WmiObject -Class Win32_OperatingSystem
    $memUsage = [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 2)
    Write-ColorOutput "Memory usage: $memUsage%" "White"
    
    $cpu = Get-WmiObject -Class Win32_Processor | Measure-Object -Property LoadPercentage -Average
    Write-ColorOutput "CPU usage: $($cpu.Average)%" "White"
}

function Show-TestSummary {
    Write-ColorOutput "`n=== Test Summary ===" "Cyan"
    Write-ColorOutput "NIDS-SIEM Integration Test Complete" "Green"
    Write-ColorOutput "" "White"
    Write-ColorOutput "Next steps:" "Yellow"
    Write-ColorOutput "1. Access Kibana dashboard: http://localhost:5601" "White"
    Write-ColorOutput "2. Create index pattern: nids-logs-*" "White"
    Write-ColorOutput "3. Import dashboard template from kibana_dashboard.json" "White"
    Write-ColorOutput "4. Start real-time monitoring with automation_realtime.sh" "White"
    Write-ColorOutput "" "White"
    Write-ColorOutput "For production deployment:" "Yellow"
    Write-ColorOutput "- Configure network interfaces in automation script" "White"
    Write-ColorOutput "- Set up log rotation and archival" "White"
    Write-ColorOutput "- Configure alerting and notifications" "White"
    Write-ColorOutput "- Implement SSL/TLS for ELK communication" "White"
}

# Main execution
if ($QuickTest) {
    Test-ServiceAvailability
    Test-NIDSComponents
    $testFile = Generate-TestTraffic
    Test-NIDSPrediction -TestDataPath $testFile
    Show-TestSummary
}
elseif ($FullTest) {
    Test-ServiceAvailability
    Test-NIDSComponents
    $testFile = Generate-TestTraffic
    Test-NIDSPrediction -TestDataPath $testFile
    Test-SIEMIntegration
    Show-TestSummary
}
elseif ($StressTest) {
    Test-ServiceAvailability
    Test-NIDSComponents
    Run-StressTest
    Test-SIEMIntegration
    Show-TestSummary
}
elseif ($GenerateTraffic) {
    Generate-TestTraffic
}
else {
    Write-ColorOutput "NIDS-SIEM Test Suite" "Cyan"
    Write-ColorOutput "Usage:" "White"
    Write-ColorOutput "  .\test_system.ps1 -QuickTest      # Basic functionality test" "Yellow"
    Write-ColorOutput "  .\test_system.ps1 -FullTest       # Complete integration test" "Yellow"
    Write-ColorOutput "  .\test_system.ps1 -StressTest     # Performance and stress test" "Yellow"
    Write-ColorOutput "  .\test_system.ps1 -GenerateTraffic # Generate test data only" "Yellow"
}
