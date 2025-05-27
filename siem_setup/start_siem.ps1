# Script khởi động tổng thể cho NIDS-SIEM
# Chạy với quyền Administrator

param(
    [switch]$Install,
    [switch]$Start,
    [switch]$Stop,
    [switch]$Status,
    [switch]$ConfigureKibana
)

$ErrorActionPreference = "Stop"

# Đường dẫn cấu hình
$ELK_BASE = "E:\ELK"
$NIDS_BASE = "C:\Users\ADMIN\Desktop\CodeBackup\v2_pcap2csv_automation"
$SIEM_CONFIG = "C:\Users\ADMIN\Desktop\CodeBackup\siem_setup"

function Write-ColorOutput($Message, $Color = "White") {
    Write-Host $Message -ForegroundColor $Color
}

function Test-ServiceRunning($ProcessName) {
    return $null -ne (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
}

function Install-ELKStack {
    Write-ColorOutput "=== Installing ELK Stack ===" "Green"
    
    # Cài đặt Elasticsearch
    Write-ColorOutput "Installing Elasticsearch..." "Yellow"
    & "$SIEM_CONFIG\install_elasticsearch.ps1"
    
    # Cài đặt Logstash
    Write-ColorOutput "Installing Logstash..." "Yellow"
    & "$SIEM_CONFIG\install_logstash.ps1"
    
    # Cài đặt Kibana
    Write-ColorOutput "Installing Kibana..." "Yellow"
    & "$SIEM_CONFIG\install_kibana.ps1"
    
    # Copy Logstash pipeline configuration
    $pipelineDir = "$ELK_BASE\logstash\logstash\pipeline"
    if (!(Test-Path $pipelineDir)) {
        New-Item -ItemType Directory -Path $pipelineDir -Force
    }
    Copy-Item "$SIEM_CONFIG\nids-pipeline.conf" "$pipelineDir\" -Force
    
    # Tạo thư mục logs và alerts
    New-Item -ItemType Directory -Path "$ELK_BASE\alerts" -Force
    New-Item -ItemType Directory -Path "$NIDS_BASE\logs" -Force
    
    Write-ColorOutput "ELK Stack installation completed!" "Green"
}

function Start-ELKServices {
    Write-ColorOutput "=== Starting ELK Services ===" "Green"
    
    try {
        # Start Elasticsearch
        if (!(Test-ServiceRunning "java")) {
            Write-ColorOutput "Starting Elasticsearch..." "Yellow"
            Start-Process -FilePath "$ELK_BASE\elasticsearch\elasticsearch\bin\elasticsearch.bat" -WindowStyle Minimized
            Start-Sleep -Seconds 30
        } else {
            Write-ColorOutput "Elasticsearch already running" "Cyan"
        }
        
        # Wait for Elasticsearch to be ready
        Write-ColorOutput "Waiting for Elasticsearch to be ready..." "Yellow"
        $timeout = 60
        $count = 0
        do {
            try {
                $response = Invoke-WebRequest -Uri "http://localhost:9200" -UseBasicParsing -TimeoutSec 5
                if ($response.StatusCode -eq 200) {
                    Write-ColorOutput "Elasticsearch is ready!" "Green"
                    break
                }
            } catch {
                Start-Sleep -Seconds 2
                $count += 2
            }
        } while ($count -lt $timeout)
        
        if ($count -ge $timeout) {
            throw "Elasticsearch failed to start within timeout"
        }
        
        # Start Logstash
        Write-ColorOutput "Starting Logstash..." "Yellow"
        $logstashCmd = "$ELK_BASE\logstash\logstash\bin\logstash.bat -f $ELK_BASE\logstash\logstash\pipeline\nids-pipeline.conf"
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $logstashCmd -WindowStyle Minimized
        Start-Sleep -Seconds 15
        
        # Start Kibana
        Write-ColorOutput "Starting Kibana..." "Yellow"
        Start-Process -FilePath "$ELK_BASE\kibana\kibana\bin\kibana.bat" -WindowStyle Minimized
        Start-Sleep -Seconds 20
        
        Write-ColorOutput "All ELK services started!" "Green"
        Write-ColorOutput "Elasticsearch: http://localhost:9200" "Cyan"
        Write-ColorOutput "Kibana: http://localhost:5601" "Cyan"
        
    } catch {
        Write-ColorOutput "Error starting services: $($_.Exception.Message)" "Red"
        throw
    }
}

function Stop-ELKServices {
    Write-ColorOutput "=== Stopping ELK Services ===" "Yellow"
    
    # Stop Java processes (Elasticsearch, Logstash)
    Get-Process -Name "java" -ErrorAction SilentlyContinue | Stop-Process -Force
    
    # Stop Node processes (Kibana)
    Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like "*Kibana*" } | Stop-Process -Force
    
    Write-ColorOutput "ELK services stopped" "Green"
}

function Get-ELKStatus {
    Write-ColorOutput "=== ELK Stack Status ===" "Cyan"
    
    # Check Elasticsearch
    try {
        $esResponse = Invoke-WebRequest -Uri "http://localhost:9200" -UseBasicParsing -TimeoutSec 5
        Write-ColorOutput "✓ Elasticsearch: Running (http://localhost:9200)" "Green"
    } catch {
        Write-ColorOutput "✗ Elasticsearch: Not running" "Red"
    }
    
    # Check Kibana
    try {
        $kibanaResponse = Invoke-WebRequest -Uri "http://localhost:5601" -UseBasicParsing -TimeoutSec 5
        Write-ColorOutput "✓ Kibana: Running (http://localhost:5601)" "Green"
    } catch {
        Write-ColorOutput "✗ Kibana: Not running" "Red"
    }
    
    # Check Logstash process
    if (Get-Process -Name "java" -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -eq "java" }) {
        Write-ColorOutput "✓ Logstash: Running" "Green"
    } else {
        Write-ColorOutput "✗ Logstash: Not running" "Red"
    }
    
    # Check NIDS logs
    $logFile = "$NIDS_BASE\logs\nids_detections.log"
    if (Test-Path $logFile) {
        $logSize = (Get-Item $logFile).Length
        $lastWrite = (Get-Item $logFile).LastWriteTime
        Write-ColorOutput "✓ NIDS Logs: $([math]::Round($logSize/1KB, 2)) KB (Last: $lastWrite)" "Green"
    } else {
        Write-ColorOutput "✗ NIDS Logs: No log file found" "Yellow"
    }
}

function Configure-Kibana {
    Write-ColorOutput "=== Configuring Kibana Dashboards ===" "Green"
    
    # Wait for services to be ready
    Write-ColorOutput "Waiting for services to be ready..." "Yellow"
    Start-Sleep -Seconds 30
    
    try {
        # Create index pattern
        Write-ColorOutput "Creating Kibana index pattern..." "Yellow"
        
        $indexPattern = @{
            "attributes" = @{
                "title" = "nids-logs-*"
                "timeFieldName" = "@timestamp"
            }
        } | ConvertTo-Json -Depth 10
        
        $headers = @{
            "Content-Type" = "application/json"
            "kbn-xsrf" = "true"
        }
        
        Invoke-RestMethod -Uri "http://localhost:5601/api/saved_objects/index-pattern/nids-logs" `
                         -Method POST `
                         -Body $indexPattern `
                         -Headers $headers
        
        Write-ColorOutput "Index pattern created successfully!" "Green"
        
        # Import sample dashboard configuration
        $dashboardConfig = @"
{
  "version": "8.12.0",
  "objects": [
    {
      "id": "nids-overview",
      "type": "dashboard",
      "attributes": {
        "title": "NIDS Security Overview",
        "description": "Network Intrusion Detection System Overview Dashboard",
        "panelsJSON": "[]",
        "timeRestore": false,
        "version": 1
      }
    }
  ]
}
"@
        
        Write-ColorOutput "Kibana configuration completed!" "Green"
        Write-ColorOutput "Access Kibana at: http://localhost:5601" "Cyan"
        Write-ColorOutput "Index pattern: nids-logs-*" "Cyan"
        
    } catch {
        Write-ColorOutput "Warning: Could not auto-configure Kibana: $($_.Exception.Message)" "Yellow"
        Write-ColorOutput "Please configure manually at http://localhost:5601" "Cyan"
    }
}

function Start-NIDSDemo {
    Write-ColorOutput "=== Starting NIDS Demo ===" "Green"
    
    # Generate sample data for demo
    $sampleData = @"
timestamp,Src IP,Dst IP,Src Port,Dst Port,Protocol,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,TotLen Bwd Pkts,Flow Byts/s,Flow Pkts/s
2024-01-01 10:00:00,192.168.1.100,192.168.1.1,12345,80,6,0.5,10,8,1500,800,4600,36
2024-01-01 10:00:01,10.0.0.50,192.168.1.0,54321,22,6,2.1,100,2,15000,200,7238,48
2024-01-01 10:00:02,172.16.0.10,192.168.100.0,33445,443,6,0.1,5,3,500,300,8000,80
"@
    
    $demoFile = "$NIDS_BASE\demo_data.csv"
    $sampleData | Out-File -FilePath $demoFile -Encoding UTF8
    
    Write-ColorOutput "Running NIDS detection on demo data..." "Yellow"
    
    # Run NIDS with enhanced logging
    Set-Location $NIDS_BASE
    python program_siem.py --data demo_data.csv --models "../Saved model" --output demo_results.csv
    
    Write-ColorOutput "Demo completed! Check logs at: $NIDS_BASE\logs\" "Green"
}

# Main execution logic
if ($Install) {
    Install-ELKStack
}
elseif ($Start) {
    Start-ELKServices
    if ($ConfigureKibana) {
        Configure-Kibana
    }
}
elseif ($Stop) {
    Stop-ELKServices
}
elseif ($Status) {
    Get-ELKStatus
}
elseif ($ConfigureKibana) {
    Configure-Kibana
}
else {
    Write-ColorOutput "NIDS-SIEM Management Script" "Cyan"
    Write-ColorOutput "Usage:" "White"
    Write-ColorOutput "  .\start_siem.ps1 -Install           # Install ELK Stack" "Yellow"
    Write-ColorOutput "  .\start_siem.ps1 -Start             # Start all services" "Yellow"
    Write-ColorOutput "  .\start_siem.ps1 -Start -ConfigureKibana  # Start and configure Kibana" "Yellow"
    Write-ColorOutput "  .\start_siem.ps1 -Stop              # Stop all services" "Yellow"
    Write-ColorOutput "  .\start_siem.ps1 -Status            # Check service status" "Yellow"
    Write-ColorOutput "  .\start_siem.ps1 -ConfigureKibana   # Configure Kibana dashboards" "Yellow"
    Write-ColorOutput "" "White"
    Write-ColorOutput "Example full setup:" "Green"
    Write-ColorOutput "  .\start_siem.ps1 -Install" "Cyan"
    Write-ColorOutput "  .\start_siem.ps1 -Start -ConfigureKibana" "Cyan"
}
