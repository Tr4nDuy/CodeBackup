# NIDS-SIEM Windows Server Quick Deployment Script
# Run as Administrator

param(
    [switch]$FullInstall,
    [switch]$StartOnly,
    [switch]$TestOnly,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

function Write-ColorOutput($Message, $Color = "White") {
    Write-Host $Message -ForegroundColor $Color
}

function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-Prerequisites {
    Write-ColorOutput "=== Installing Prerequisites ===" "Green"
    
    # Check Java installation
    try {
        $javaVersion = java -version 2>&1 | Select-String "version"
        Write-ColorOutput "✓ Java already installed: $javaVersion" "Cyan"
    } catch {
        Write-ColorOutput "Installing Java 11..." "Yellow"
        
        # Download and install Java 11
        $javaUrl = "https://download.java.net/java/GA/jdk11/9/GPL/openjdk-11.0.2_windows-x64_bin.zip"
        $javaZip = "$env:TEMP\openjdk-11.zip"
        $javaDir = "C:\Java"
        
        try {
            Invoke-WebRequest -Uri $javaUrl -OutFile $javaZip
            Expand-Archive -Path $javaZip -DestinationPath $javaDir -Force
            
            # Set JAVA_HOME
            $env:JAVA_HOME = "$javaDir\jdk-11.0.2"
            [Environment]::SetEnvironmentVariable("JAVA_HOME", $env:JAVA_HOME, "Machine")
            [Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";$env:JAVA_HOME\bin", "Machine")
            
            Write-ColorOutput "✓ Java 11 installed successfully" "Green"
        } catch {
            Write-ColorOutput "✗ Failed to install Java. Please install manually." "Red"
            exit 1
        }
    }
    
    # Configure Windows Firewall
    Write-ColorOutput "Configuring Windows Firewall..." "Yellow"
    try {
        New-NetFirewallRule -DisplayName "SIEM-Elasticsearch" -Direction Inbound -Protocol TCP -LocalPort 9200 -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "SIEM-Logstash" -Direction Inbound -Protocol UDP -LocalPort 5514 -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "SIEM-Kibana" -Direction Inbound -Protocol TCP -LocalPort 5601 -Action Allow -ErrorAction SilentlyContinue
        Write-ColorOutput "✓ Firewall rules configured" "Green"
    } catch {
        Write-ColorOutput "⚠ Firewall configuration may need manual setup" "Yellow"
    }
}

function Deploy-ELKStack {
    Write-ColorOutput "=== Deploying ELK Stack ===" "Green"
    
    try {
        # Install ELK Stack
        Write-ColorOutput "Installing Elasticsearch..." "Yellow"
        & ".\install_elasticsearch.ps1"
        
        Write-ColorOutput "Installing Logstash..." "Yellow"
        & ".\install_logstash.ps1"
        
        Write-ColorOutput "Installing Kibana..." "Yellow"
        & ".\install_kibana.ps1"
        
        Write-ColorOutput "✓ ELK Stack installation completed" "Green"
    } catch {
        Write-ColorOutput "✗ ELK Stack installation failed: $($_.Exception.Message)" "Red"
        throw
    }
}

function Test-SIEMConnectivity {
    Write-ColorOutput "=== Testing SIEM Connectivity ===" "Green"
    
    # Test Ubuntu Router connectivity
    $ubuntuRouter = "192.168.111.133"
    
    Write-ColorOutput "Testing connectivity to Ubuntu Router ($ubuntuRouter)..." "Yellow"
    if (Test-NetConnection -ComputerName $ubuntuRouter -Port 22 -InformationLevel Quiet) {
        Write-ColorOutput "✓ Ubuntu Router reachable" "Green"
    } else {
        Write-ColorOutput "✗ Cannot reach Ubuntu Router" "Red"
    }
    
    # Test local services
    $services = @(
        @{Name="Elasticsearch"; Port=9200; Url="http://localhost:9200"},
        @{Name="Kibana"; Port=5601; Url="http://localhost:5601"},
        @{Name="Logstash"; Port=5514; Protocol="UDP"}
    )
    
    foreach ($service in $services) {
        Write-ColorOutput "Testing $($service.Name)..." "Yellow"
        
        if ($service.Url) {
            try {
                $response = Invoke-WebRequest -Uri $service.Url -UseBasicParsing -TimeoutSec 5
                Write-ColorOutput "✓ $($service.Name) responding on port $($service.Port)" "Green"
            } catch {
                Write-ColorOutput "✗ $($service.Name) not responding" "Red"
            }
        } else {
            if (Test-NetConnection -ComputerName "localhost" -Port $service.Port -InformationLevel Quiet) {
                Write-ColorOutput "✓ $($service.Name) listening on port $($service.Port)" "Green"
            } else {
                Write-ColorOutput "✗ $($service.Name) not listening on port $($service.Port)" "Red"
            }
        }
    }
}

function Create-TestData {
    Write-ColorOutput "=== Creating Test Data ===" "Green"
    
    # Generate sample NIDS logs for testing
    $testLogs = @(
        '{"timestamp": "2025-05-28 10:00:00.123456", "event_type": "network_detection", "prediction": "TCP", "confidence": 0.8745, "is_attack": true, "severity": "high", "network_zone": "WAN", "interface": "ens33", "attack_type": "TCP Port Scan", "source_ip": "203.0.113.100", "destination_ip": "192.168.1.10", "sensor_id": "nids-ubuntu-ens33"}',
        '{"timestamp": "2025-05-28 10:01:00.123456", "event_type": "network_detection", "prediction": "0_normal", "confidence": 0.9234, "is_attack": false, "severity": "info", "network_zone": "LAN", "interface": "ens37", "attack_type": "normal_traffic", "source_ip": "192.168.1.100", "destination_ip": "192.168.1.1", "sensor_id": "nids-ubuntu-ens37"}',
        '{"timestamp": "2025-05-28 10:02:00.123456", "event_type": "network_detection", "prediction": "UDP", "confidence": 0.7891, "is_attack": true, "severity": "high", "network_zone": "SERVER", "interface": "ens38", "attack_type": "UDP Port Scan", "source_ip": "10.0.0.50", "destination_ip": "192.168.100.10", "sensor_id": "nids-ubuntu-ens38"}'
    )
    
    $logFile = "C:\ELK\test_nids_logs.json"
    $testLogs | Out-File -FilePath $logFile -Encoding UTF8
    
    Write-ColorOutput "Test data created at: $logFile" "Cyan"
    
    # Send test data to Logstash
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse("127.0.0.1"), 5514)
        
        foreach ($log in $testLogs) {
            $message = "<14>$log"
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($message)
            $udpClient.Send($bytes, $bytes.Length, $endpoint) | Out-Null
            Start-Sleep -Milliseconds 100
        }
        
        $udpClient.Close()
        Write-ColorOutput "✓ Test logs sent to Logstash" "Green"
    } catch {
        Write-ColorOutput "✗ Failed to send test logs: $($_.Exception.Message)" "Red"
    }
}

function Show-SystemStatus {
    Write-ColorOutput "=== SIEM System Status ===" "Cyan"
    
    # Check processes
    $javaProcesses = Get-Process -Name "java" -ErrorAction SilentlyContinue
    $nodeProcesses = Get-Process -Name "node" -ErrorAction SilentlyContinue
    
    Write-ColorOutput "Java processes (Elasticsearch/Logstash): $($javaProcesses.Count)" "White"
    Write-ColorOutput "Node processes (Kibana): $($nodeProcesses.Count)" "White"
    
    # Check disk space
    $disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
    Write-ColorOutput "Free disk space: $freeSpaceGB GB" "White"
    
    # Memory usage
    $memory = Get-WmiObject -Class Win32_ComputerSystem
    $totalRAM = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
    $availableRAM = [math]::Round((Get-Counter '\Memory\Available MBytes').CounterSamples[0].CookedValue / 1024, 2)
    Write-ColorOutput "Memory: $availableRAM GB available / $totalRAM GB total" "White"
    
    Write-ColorOutput "`nAccess URLs:" "Cyan"
    Write-ColorOutput "• Elasticsearch: http://localhost:9200" "Green"
    Write-ColorOutput "• Kibana: http://localhost:5601" "Green"
    Write-ColorOutput "• Logstash: UDP port 5514" "Green"
}

function Show-Help {
    Write-ColorOutput "NIDS-SIEM Windows Server Deployment Script" "Cyan"
    Write-ColorOutput ""
    Write-ColorOutput "Usage: .\deploy_siem.ps1 [OPTIONS]" "White"
    Write-ColorOutput ""
    Write-ColorOutput "OPTIONS:" "Yellow"
    Write-ColorOutput "  -FullInstall     Complete installation (prerequisites + ELK + start)" "White"
    Write-ColorOutput "  -StartOnly       Start existing ELK services only" "White"
    Write-ColorOutput "  -TestOnly        Run connectivity and system tests only" "White"
    Write-ColorOutput "  -Help            Show this help message" "White"
    Write-ColorOutput ""
    Write-ColorOutput "Examples:" "Green"
    Write-ColorOutput "  .\deploy_siem.ps1 -FullInstall    # Complete setup" "Cyan"
    Write-ColorOutput "  .\deploy_siem.ps1 -StartOnly      # Start services" "Cyan"
    Write-ColorOutput "  .\deploy_siem.ps1 -TestOnly       # Test system" "Cyan"
    Write-ColorOutput ""
    Write-ColorOutput "Requirements:" "Yellow"
    Write-ColorOutput "  • Windows Server 2019 or later" "White"
    Write-ColorOutput "  • 4GB+ RAM (8GB recommended)" "White"
    Write-ColorOutput "  • 20GB+ free disk space" "White"
    Write-ColorOutput "  • Administrator privileges" "White"
}

# Main execution logic
if ($Help) {
    Show-Help
    exit 0
}

if (-not (Test-AdminRights)) {
    Write-ColorOutput "This script must be run as Administrator!" "Red"
    Write-ColorOutput "Right-click PowerShell and select 'Run as Administrator'" "Yellow"
    exit 1
}

Write-ColorOutput "=============================================" "Cyan"
Write-ColorOutput "NIDS-SIEM Windows Server Deployment" "Cyan"
Write-ColorOutput "=============================================" "Cyan"
Write-ColorOutput ""

try {
    if ($FullInstall) {
        Write-ColorOutput "Starting full installation..." "Green"
        Install-Prerequisites
        Deploy-ELKStack
        & ".\start_siem.ps1" -Start -ConfigureKibana
        Test-SIEMConnectivity
        Create-TestData
        Show-SystemStatus
        
        Write-ColorOutput "`n✓ Full installation completed successfully!" "Green"
        Write-ColorOutput "SIEM is ready to receive logs from Ubuntu Router (192.168.111.133)" "Cyan"
    }
    elseif ($StartOnly) {
        Write-ColorOutput "Starting ELK services..." "Green"
        & ".\start_siem.ps1" -Start
        Show-SystemStatus
    }
    elseif ($TestOnly) {
        Write-ColorOutput "Running system tests..." "Green"
        Test-SIEMConnectivity
        Create-TestData
        Show-SystemStatus
    }
    else {
        Write-ColorOutput "No action specified. Use -Help for usage information." "Yellow"
        Show-Help
    }
} catch {
    Write-ColorOutput "Deployment failed: $($_.Exception.Message)" "Red"
    exit 1
}

Write-ColorOutput "`nDeployment completed. Check the URLs above to verify services." "Green"
